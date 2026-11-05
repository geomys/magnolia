# Synchronous replication for SQLite

## High-level design

Each write transaction is captured as a SQLite session patchset and appended to a remote log before the local `COMMIT`. A transaction is reported committed only after the append is acknowledged, so the log contains every committed transaction.

### Components

- **Primary.** The only process that writes the database. One writer connection, a pool of read connections. Uses `zombiezen.com/go/sqlite`.
- **Log store.** Remote append-only log in a separate failure domain. Appends a record, fsyncs, acks. No other logic.
- **Recovery.** Rebuilds a database from the latest snapshot plus the log records after it.

### Record

`{seq, type, payload}`. `seq` is a counter held in the database itself and incremented inside the same transaction as the data, so it commits atomically with it. `type` is `patchset` or `ddl`.

### Guarantees

- A transaction reported as committed is never lost while the log store survives.
- Readers on the primary only see transactions that are already in the log.
- At most one transaction is in doubt: the last record in the log may belong to a transaction that never committed locally. Its client received ErrOutcomeUnknown or no answer, so either outcome is valid.

### Non-goals

Availability. If the log store is unreachable, writes fail. Failover is manual.

### Failure cases

| Event | Local seq | Log | Result |
| --- | --- | --- | --- |
| Ack lost, local rolls back | N−1 | Orphan N | Next transaction reuses N. Replay keeps the later record. |
| Crash after ack, before `COMMIT`, disk survives | N−1 | Orphan N | Same as above. |
| Crash after ack, before `COMMIT`, disk lost | — | Orphan N | Restore includes N. Client was never answered. |
| Crash after `COMMIT` | N | N | Nothing to do. |
| Log store unreachable | N−1 | N−1 or orphan N | Write fails with `ErrOutcomeUnknown`. |
| Primary disk lost | — | 1..N | Restore from snapshot plus log. |

## Writer implementation

All writes go through one connection, one transaction at a time. The write lock is held across the network round trip.

### Startup

1. Open the writer connection with `journal_mode = WAL` and `synchronous = FULL`.
2. Run the schema check (see Restrictions). Refuse to start if it fails.
3. On first start only: create the meta table (`CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK (id = 0), seq INTEGER NOT NULL)`, seeded with `(0, 0)`). This is the only schema outside the log, since seq lives in it. Recovery recreates it the same way.
4. Open a separate pool of read connections with `PRAGMA query_only = ON`. Reads never touch the writer connection.

### Per transaction

1. `BEGIN IMMEDIATE`.
2. `conn.CreateSession("")`, then `Attach("")` to track all tables.
3. `UPDATE meta SET seq = seq + 1 WHERE id = 0 RETURNING seq` → N.
4. Run the application's writes.
5. `session.WritePatchset(buf)`, then `session.Delete()`.
6. Send `{N, patchset, buf}` to the log store. Wait for the ack with a timeout.
7. On ack: `COMMIT`, return success.
8. On send error or timeout: `ROLLBACK`, return `ErrOutcomeUnknown`. The next transaction reuses N.
9. If `COMMIT` fails after the ack: return `ErrOutcomeUnknown`. The next transaction reuses N.

The meta update is part of the patchset, so a restored database carries its own seq.

### Schema changes

Same steps, but the session is not used: run the DDL (data definition language: CREATE, ALTER, DROP) after the seq bump and send `{N, ddl, sql}`. The session extension does not record DDL. A DDL transaction contains only DDL; run data backfills afterwards as normal transactions, or they are not replicated. Send a record only when the schema actually changes, for example by checking `PRAGMA user_version`.

### Sends

No retries. A failed send rolls back, and the next transaction gets a new patchset with the same N. The log store never receives the same record twice, so it needs no deduplication. If retries are added later, include a hash of the payload and have recovery drop exact repeats.

### Throughput and size

- Concurrency is the same as plain WAL mode: writers are exclusive, readers run concurrently with the writer. During the round trip, readers see the last committed snapshot.
- Write throughput is about one transaction per round trip to the log store. Batch logical writes into one transaction where possible.
- The session holds old values for every changed row in memory. Split bulk updates and deletes into smaller transactions.

## Log store and recovery

The log store is dumb. All interpretation happens in recovery.

### Log store

- Record framing: `length u32 | crc32c u32 | seq u64 | type u8 | payload`.
- On append: write the record, fsync, ack.
- On restart: scan from the start. If the last record has a bad length or checksum, truncate it; a torn record was never acked. A bad record anywhere else is corruption: stop and alert.

### Snapshots (optional)

1. On the primary, run `VACUUM INTO` from a read connection.
2. Read `meta.seq` from the snapshot file itself. That is the snapshot's seq, S.
3. Store the snapshot next to the log, tagged with S.
4. Truncate log records before the first record with seq greater than S. Keep the previous snapshot until the next one is stored.

### Recovery

1. Start from the latest snapshot if there is one; otherwise from an empty database with the meta table created as in writer startup. S = its `meta.seq`.
2. Read log records in log order. Ignore records with seq ≤ S.
3. Collapse runs: consecutive records with the same seq are retries of one slot; keep the last.
4. Check that seqs run S+1, S+2, … with no gaps. A gap or a lower seq means operator error or a lost record. Stop.
5. Open a recovery connection with `foreign_keys = OFF` and triggers disabled (`SQLITE_DBCONFIG_ENABLE_TRIGGER = 0`, or drop and recreate the triggers around replay if the binding does not expose it).
6. Apply each record in order. For `patchset`, call `conn.ApplyChangeset(r, nil, func(sqlite.ConflictType, *sqlite.ChangesetIterator) sqlite.ConflictAction { return sqlite.ChangesetAbort })`. Any conflict rolls back the record and stops recovery. For `ddl`, execute the SQL and set `meta.seq = N` in the same transaction, since the writer's seq bump is not captured for DDL.
7. Check `meta.seq` equals the last applied seq. Run `PRAGMA integrity_check` and `PRAGMA foreign_key_check`.
8. Rebuild derived data: FTS5 and R\*Tree indexes.
9. Confirm the old primary is down, then start the new primary on the restored file.

### Verification (optional)

Run recovery continuously into a scratch database. On the primary, open a read transaction, read `meta.seq` and compute a content hash per table (rows ordered by primary key, or SQLite's `dbhash` tool). Replay the scratch database to the same seq and compare. A mismatch means a restriction was violated or the replay logic is wrong.

## Restrictions

Violating any of these loses or corrupts data silently. The schema rules are checked at startup.

### Settings

- `journal_mode = WAL`.
- `synchronous = FULL`. With `NORMAL`, a power loss can undo a local commit the log already holds, and the next transaction reuses its seq.

### Schema

- Every table is either `WITHOUT ROWID` or has an `INTEGER PRIMARY KEY`. The session skips tables with no primary key, and other rowids are not preserved across replay.
- Every primary-key column is `NOT NULL`. The session skips rows with a NULL key. Implicit for `WITHOUT ROWID` tables.
- No `AUTOINCREMENT`. Its counter table, `sqlite_sequence`, has no primary key and is not replicated.
- Virtual tables (FTS5, R\*Tree) are derived data and are rebuilt after restore.
- One database file. Writes to `ATTACH`ed databases are not captured.

### Write path

- All writes go through the writer connection with a session attached. No writes from the `sqlite3` CLI or any other process.
- Schema changes go through the `ddl` record type, including any `CREATE TABLE IF NOT EXISTS` at startup.
- A send error is reported to the client as `ErrOutcomeUnknown`. Callers may treat it as a failure if they accept a rare false failure: the write persists only if the database is restored from the log before the next commit reuses its seq.

### Recovery

- Foreign keys off and triggers disabled during replay. The patchset already contains rows changed by cascades and triggers.
- Abort on any conflict.
