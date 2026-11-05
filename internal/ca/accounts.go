package ca

import (
	"context"
	"crypto/mldsa"
	"errors"
	"fmt"

	"geomys.org/magnolia/internal/acmeerrors"
	"geomys.org/magnolia/internal/jws"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

// accountStore keeps ACME accounts in a SQLite database.
type accountStore struct {
	pool *sqlitex.Pool
}

type account struct {
	kid         string
	key         *mldsa.PublicKey
	deactivated bool
}

func openAccountStore(path string) (*accountStore, error) {
	if path == "" {
		// SQLite would open a separate temporary database per connection.
		return nil, errors.New("accounts database path must be set")
	}
	pool, err := sqlitex.NewPool(path, sqlitex.PoolOptions{
		PrepareConn: func(conn *sqlite.Conn) error {
			// Accounts are authoritative, so make every commit durable.
			return sqlitex.ExecuteTransient(conn, `PRAGMA synchronous = FULL;`, nil)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open accounts database: %w", err)
	}
	conn, err := pool.Take(context.Background())
	if err != nil {
		pool.Close()
		return nil, err
	}
	err = sqlitex.ExecuteTransient(conn, `
		CREATE TABLE IF NOT EXISTS accounts (
			kid TEXT PRIMARY KEY,
			thumbprint TEXT NOT NULL UNIQUE,
			alg TEXT NOT NULL,
			key BLOB NOT NULL,
			deactivated INTEGER NOT NULL DEFAULT 0
		) STRICT;`, nil)
	pool.Put(conn)
	if err != nil {
		pool.Close()
		return nil, err
	}
	return &accountStore{pool: pool}, nil
}

func (s *accountStore) Close() error {
	return s.pool.Close()
}

// scanAccount decodes an account row selected with kid, alg, key, and
// deactivated columns.
func scanAccount(stmt *sqlite.Stmt) (*account, error) {
	params, err := parametersByName(stmt.GetText("alg"))
	if err != nil {
		return nil, err
	}
	encoding := make([]byte, stmt.GetLen("key"))
	stmt.GetBytes("key", encoding)
	key, err := mldsa.NewPublicKey(params, encoding)
	if err != nil {
		return nil, fmt.Errorf("invalid stored key for account %q: %w", stmt.GetText("kid"), err)
	}
	return &account{
		kid:         stmt.GetText("kid"),
		key:         key,
		deactivated: stmt.GetBool("deactivated"),
	}, nil
}

func parametersByName(alg string) (mldsa.Parameters, error) {
	switch alg {
	case "ML-DSA-44":
		return mldsa.MLDSA44(), nil
	case "ML-DSA-65":
		return mldsa.MLDSA65(), nil
	case "ML-DSA-87":
		return mldsa.MLDSA87(), nil
	default:
		return mldsa.Parameters{}, fmt.Errorf("unknown stored algorithm %q", alg)
	}
}

const selectAccount = `SELECT kid, alg, key, deactivated FROM accounts WHERE `

const accountDoesNotExist = "urn:ietf:params:acme:error:accountDoesNotExist"

// take returns a connection from pool, which the caller must return with Put.
func take(ctx context.Context, pool *sqlitex.Pool) (*sqlite.Conn, acmeerrors.Error) {
	conn, err := pool.Take(ctx)
	if err != nil {
		return nil, acmeerrors.Internal("failed to get a database connection: %w", err)
	}
	return conn, nil
}

// transact runs fn in an IMMEDIATE transaction, which serializes writers
// and sees the latest committed state. The transaction is committed if fn
// returns nil, and rolled back otherwise.
func transact(conn *sqlite.Conn, fn func() acmeerrors.Error) acmeerrors.Error {
	err := func() (err error) {
		endFn, err := sqlitex.ImmediateTransaction(conn)
		if err != nil {
			return err
		}
		// endFn recovers panics and reports COMMIT failures through err.
		defer endFn(&err)
		return fn()
	}()
	if err == nil {
		return nil
	}
	if err, ok := err.(acmeerrors.Error); ok {
		return err
	}
	return acmeerrors.Internal("transaction failed: %w", err)
}

// get returns the account at kid, or an accountDoesNotExist or unauthorized
// error if it doesn't exist or is deactivated.
func (s *accountStore) get(ctx context.Context, kid string) (*account, acmeerrors.Error) {
	conn, err := take(ctx, s.pool)
	if err != nil {
		return nil, err
	}
	defer s.pool.Put(conn)
	acct, err := getAccount(conn, kid)
	if err != nil {
		return nil, err
	}
	if acct.deactivated {
		return nil, acmeerrors.New("unauthorized", 401, "account is deactivated")
	}
	return acct, nil
}

// getAccount returns the account at kid, even if deactivated, or an
// accountDoesNotExist error.
func getAccount(conn *sqlite.Conn, kid string) (*account, acmeerrors.Error) {
	return selectOne(conn, selectAccount+`kid = ?`, kid)
}

// lookup returns the account whose key is pub, even if deactivated, or an
// accountDoesNotExist error.
func (s *accountStore) lookup(ctx context.Context, pub *mldsa.PublicKey) (*account, acmeerrors.Error) {
	conn, err := take(ctx, s.pool)
	if err != nil {
		return nil, err
	}
	defer s.pool.Put(conn)
	return lookupAccount(conn, pub)
}

func lookupAccount(conn *sqlite.Conn, pub *mldsa.PublicKey) (*account, acmeerrors.Error) {
	return selectOne(conn, selectAccount+`thumbprint = ?`, jws.JWKThumbprint(pub))
}

func selectOne(conn *sqlite.Conn, query string, arg any) (*account, acmeerrors.Error) {
	var acct *account
	err := sqlitex.Execute(conn, query, &sqlitex.ExecOptions{
		Args: []any{arg},
		ResultFunc: func(stmt *sqlite.Stmt) (err error) {
			acct, err = scanAccount(stmt)
			return err
		},
	})
	if err != nil {
		return nil, acmeerrors.Internal("failed to look up account: %w", err)
	}
	if acct == nil {
		return nil, acmeerrors.New("accountDoesNotExist", 400, "unknown account")
	}
	return acct, nil
}

// create returns the account for pub, creating it at kid if none exists.
// created reports whether the account was created by this call.
func (s *accountStore) create(ctx context.Context, pub *mldsa.PublicKey, kid string) (acct *account, created bool, err acmeerrors.Error) {
	conn, err := take(ctx, s.pool)
	if err != nil {
		return nil, false, err
	}
	defer s.pool.Put(conn)
	err = transact(conn, func() acmeerrors.Error {
		var err acmeerrors.Error
		acct, err = lookupAccount(conn, pub)
		if err == nil {
			return nil
		} else if err.Type() != accountDoesNotExist {
			return err
		}
		if err := sqlitex.Execute(conn, `INSERT INTO accounts (kid, thumbprint, alg, key) VALUES (?, ?, ?, ?)`,
			&sqlitex.ExecOptions{Args: []any{kid, jws.JWKThumbprint(pub), pub.Parameters().String(), pub.Bytes()}}); err != nil {
			return acmeerrors.Internal("failed to create account: %w", err)
		}
		acct, created = &account{kid: kid, key: pub}, true
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return acct, created, nil
}

// deactivate marks the account at kid as deactivated.
func (s *accountStore) deactivate(ctx context.Context, kid string) acmeerrors.Error {
	conn, err := take(ctx, s.pool)
	if err != nil {
		return err
	}
	defer s.pool.Put(conn)
	if err := sqlitex.Execute(conn, `UPDATE accounts SET deactivated = 1 WHERE kid = ?`,
		&sqlitex.ExecOptions{Args: []any{kid}}); err != nil {
		return acmeerrors.Internal("failed to deactivate account: %w", err)
	}
	if conn.Changes() == 0 {
		return acmeerrors.New("accountDoesNotExist", 400, "unknown account")
	}
	return nil
}

// rekey replaces the key of the account at kid, which must be oldKey, with
// newKey. If newKey already belongs to an account, the badPublicKey error
// carries that account's URL in a Location header.
func (s *accountStore) rekey(ctx context.Context, kid string, oldKey, newKey *mldsa.PublicKey) acmeerrors.Error {
	conn, err := take(ctx, s.pool)
	if err != nil {
		return err
	}
	defer s.pool.Put(conn)
	return transact(conn, func() acmeerrors.Error {
		acct, err := getAccount(conn, kid)
		if err != nil {
			return err
		}
		if !oldKey.Equal(acct.key) {
			return acmeerrors.New("unauthorized", 403, "old key does not match current key")
		}
		if newKey.Equal(oldKey) {
			return acmeerrors.New("malformed", 400, "new key is the same as the current key")
		}
		existing, err := lookupAccount(conn, newKey)
		if err == nil {
			return acmeerrors.New("badPublicKey", 409, "key is already in use by another account").
				WithHeader("Location", existing.kid)
		} else if err.Type() != accountDoesNotExist {
			return err
		}
		if err := sqlitex.Execute(conn, `UPDATE accounts SET thumbprint = ?, alg = ?, key = ? WHERE kid = ?`,
			&sqlitex.ExecOptions{Args: []any{jws.JWKThumbprint(newKey), newKey.Parameters().String(), newKey.Bytes(), kid}}); err != nil {
			return acmeerrors.Internal("failed to change account key: %w", err)
		}
		return nil
	})
}
