package lockstep

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"geomys.org/magnolia/internal/acmeerrors"
	"github.com/prometheus/client_golang/prometheus"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var ErrLogNotFound = errors.New("log not found")

// A LockBackend is a database that supports compare-and-swap operations.
//
// The behavior of calls with the same logID must be serializable and have
// read-after-write consistency, even across processes and restarts, and write
// operations must be durable once they return. Calls with different logID
// values don't need to be consistent.
//
// It is shared across multiple Log instances, and is used only to store the
// latest checkpoint before making it publicly available.
//
// All its methods must be usable concurrently.
type LockBackend interface {
	// Fetch obtains the current checkpoint for a given log, as well as the data
	// necessary to perform a compare-and-swap operation.
	//
	// It must return [ErrLogNotFound] if the log doesn't exist.
	Fetch(ctx context.Context, logID [sha256.Size]byte) (LockedCheckpoint, error)

	// Replace uploads a new checkpoint, atomically checking that the old
	// checkpoint is the provided one, and returning the new one. Replace is
	// expected to retry transient errors, and only return an error for
	// unrecoverable errors (such as a conflict).
	Replace(ctx context.Context, old LockedCheckpoint, new []byte) (LockedCheckpoint, error)

	// Create uploads a new checkpoint, atomically checking that none exist for
	// the log yet.
	Create(ctx context.Context, logID [sha256.Size]byte, new []byte) error

	// Since a LockBackend is intended to be shared across logs, its metrics
	// should be collected by the application, not by the Log.
}

// A LockedCheckpoint is a checkpoint, along with the backend-specific
// information necessary to perform a compare-and-swap operation.
type LockedCheckpoint interface {
	Bytes() []byte
}

type SQLiteBackend struct {
	mu       *sync.Mutex
	conn     *sqlite.Conn
	duration prometheus.Summary
	log      *slog.Logger
}

func NewSQLiteBackend(ctx context.Context, path string, l *slog.Logger) (*SQLiteBackend, error) {
	duration := prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name:       "sqlite_update_duration_seconds",
			Help:       "Duration of SQLite lock backend updates.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
			MaxAge:     1 * time.Minute,
			AgeBuckets: 6,
		},
	)

	conn, err := sqlite.OpenConn(path, sqlite.OpenReadWrite|sqlite.OpenWAL|sqlite.OpenURI)
	if err != nil {
		return nil, fmt.Errorf(`failed to open SQLite lock database (hint: to avoid misconfiguration, the lock database must be created manually with "CREATE TABLE checkpoints (logID BLOB PRIMARY KEY, body BLOB NOT NULL) STRICT"): %w`, err)
	}
	if err := sqlitex.ExecuteTransient(conn, "PRAGMA synchronous = FULL", nil); err != nil {
		conn.Close()
		return nil, err
	}
	if err := sqlitex.ExecuteTransient(conn, "PRAGMA fullfsync = TRUE;", nil); err != nil {
		conn.Close()
		return nil, err
	}

	return &SQLiteBackend{
		conn:     conn,
		duration: duration,
		log:      l,
		mu:       &sync.Mutex{},
	}, nil
}

var _ LockBackend = &SQLiteBackend{}

type sqliteCheckpoint struct {
	body  []byte
	logID [sha256.Size]byte
}

func (c *sqliteCheckpoint) Bytes() []byte { return c.body }

var _ LockedCheckpoint = &sqliteCheckpoint{}

func (b *SQLiteBackend) Fetch(ctx context.Context, logID [sha256.Size]byte) (LockedCheckpoint, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var body []byte
	err := sqlitex.Execute(b.conn, "SELECT body FROM checkpoints WHERE logID = ?", &sqlitex.ExecOptions{
		Args: []any{logID[:]},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			body = make([]byte, stmt.GetLen("body"))
			stmt.GetBytes("body", body)
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	if body == nil {
		return nil, ErrLogNotFound
	}
	return &sqliteCheckpoint{logID: logID, body: body}, nil
}

func (b *SQLiteBackend) Replace(ctx context.Context, old LockedCheckpoint, new []byte) (LockedCheckpoint, error) {
	defer prometheus.NewTimer(b.duration).ObserveDuration()
	b.mu.Lock()
	defer b.mu.Unlock()
	if new == nil {
		// NULL does *not* compare equal to an empty blob!
		new = []byte{}
	}
	o := old.(*sqliteCheckpoint)
	err := sqlitex.Execute(b.conn, "UPDATE checkpoints SET body = ? WHERE logID = ? AND body = ?",
		&sqlitex.ExecOptions{Args: []any{new, o.logID[:], o.body}})
	if err != nil {
		return nil, acmeerrors.Internal("failed to update SQLite checkpoint: %w", err)
	}
	if b.conn.Changes() == 0 {
		// TODO: this also hits if new == old.body, and shouldn't.
		return nil, acmeerrors.Internal("SQLite checkpoint not found or has changed")
	}
	return &sqliteCheckpoint{logID: o.logID, body: new}, nil
}

func (b *SQLiteBackend) Create(ctx context.Context, logID [sha256.Size]byte, new []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if new == nil {
		// NULL does *not* compare equal to an empty blob!
		new = []byte{}
	}
	err := sqlitex.Execute(b.conn, `INSERT INTO checkpoints (logID, body) VALUES (?, ?)
		ON CONFLICT(logID) DO NOTHING`, &sqlitex.ExecOptions{Args: []any{logID[:], new}})
	if err != nil {
		return fmt.Errorf("failed to create checkpoint: %w", err)
	}
	if b.conn.Changes() == 0 {
		return errors.New("checkpoint already exists")
	}
	return nil
}

func (b *SQLiteBackend) Metrics() []prometheus.Collector {
	return []prometheus.Collector{b.duration}
}
