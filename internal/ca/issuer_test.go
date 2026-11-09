package ca_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/torchwood"
	"geomys.org/magnolia/internal/ca"
	"geomys.org/magnolia/internal/lockstep"
	"geomys.org/magnolia/internal/mtc"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

const (
	testCAID           = "66252.99999.1"
	testIssuanceOrigin = "oid/1.3.6.1.4.1.66252.99999.1.0.1"
	testEvidenceOrigin = "magnolia.test/evidence"
)

// testSequencingPeriod is long, since empty pools are sequenced too, and
// scripts sleep for hours of fake time.
const testSequencingPeriod = time.Hour

// newTestIssuer creates and loads a new issuer, and runs its sequencer until
// the end of the test.
func newTestIssuer(t testing.TB) *ca.Issuer {
	t.Helper()
	config := newTestIssuerConfig(t)
	if err := ca.CreateIssuer(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	iss, err := ca.LoadIssuer(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- iss.RunSequencer(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("sequencer: %v", err)
		}
	})
	return iss
}

// newTestIssuerConfig returns the configuration of an issuer with a new
// backend and signer, cosigned by the CA and by a stand-in for the mirror.
// The logs are not created.
func newTestIssuerConfig(t testing.TB) ca.IssuerConfig {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelWarn}))
	backend, err := lockstep.NewLocalBackend(t.Context(), t.TempDir(), logger)
	if err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(t.TempDir(), "lock.db")
	conn, err := sqlite.OpenConn(dbPath, sqlite.OpenReadWrite|sqlite.OpenCreate)
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlitex.ExecuteTransient(conn,
		"CREATE TABLE locks (origin TEXT PRIMARY KEY, body BLOB NOT NULL) STRICT", nil); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	issuanceSigners := []*torchwood.CosignatureSigner{
		newTestSigner(t, "oid/1.3.6.1.4.1."+testCAID),
		newTestSigner(t, "oid/1.3.6.1.4.1.66252.99999.0"),
	}
	evidenceSigners := []*torchwood.CosignatureSigner{
		newTestSigner(t, testEvidenceOrigin),
	}
	signer, err := lockstep.NewSQLiteSigner(t.Context(), dbPath, logger,
		testIssuanceOrigin, issuanceSigners, testEvidenceOrigin, evidenceSigners)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { signer.Close() })

	logs := lockstep.Config{
		Logger:         logger,
		Backend:        backend,
		Signer:         signer,
		IssuanceOrigin: testIssuanceOrigin,
		EvidenceOrigin: testEvidenceOrigin,
	}
	for _, s := range issuanceSigners {
		logs.IssuanceVerifiers = append(logs.IssuanceVerifiers, s.Verifier())
	}
	for _, s := range evidenceSigners {
		logs.EvidenceVerifiers = append(logs.EvidenceVerifiers, s.Verifier())
	}
	return ca.IssuerConfig{CAID: testCAID, Logs: logs, SequencingPeriod: testSequencingPeriod}
}

func newTestSigner(t testing.TB, name string) *torchwood.CosignatureSigner {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	s, err := torchwood.NewCosignatureSigner(name, key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestIssuerConfig(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*ca.IssuerConfig)
		want   string
	}{
		{"other CA ID", func(c *ca.IssuerConfig) { c.CAID = "66252.99999.2" }, "issuance log origin"},
		{"invalid CA ID", func(c *ca.IssuerConfig) { c.CAID = "66252" }, "trust anchor ID"},
		{"no sequencing period", func(c *ca.IssuerConfig) { c.SequencingPeriod = 0 }, "SequencingPeriod"},
		{"missing CA cosigner", func(c *ca.IssuerConfig) {
			c.Logs.IssuanceVerifiers = c.Logs.IssuanceVerifiers[1:]
		}, "CA cosigner"},
		{"duplicate cosigner", func(c *ca.IssuerConfig) {
			c.Logs.IssuanceVerifiers = append(c.Logs.IssuanceVerifiers, c.Logs.IssuanceVerifiers[0])
		}, "duplicate"},
		{"cosigner not named after a trust anchor ID", func(c *ca.IssuerConfig) {
			c.Logs.IssuanceVerifiers = append(c.Logs.IssuanceVerifiers, newTestSigner(t, "example.com/witness").Verifier())
		}, "not named after a trust anchor ID"},
		{"Ed25519 cosigner", func(c *ca.IssuerConfig) {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			s, err := torchwood.NewCosignatureSigner("oid/1.3.6.1.4.1.66252.99999.3", key)
			if err != nil {
				t.Fatal(err)
			}
			c.Logs.IssuanceVerifiers = append(c.Logs.IssuanceVerifiers, s.Verifier())
		}, "not an ML-DSA cosigner"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config := newTestIssuerConfig(t)
			tt.mutate(&config)
			if err := ca.CreateIssuer(t.Context(), config); err == nil {
				t.Error("CreateIssuer succeeded")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("CreateIssuer: got error %q, want it to mention %q", err, tt.want)
			}

			// LoadIssuer checks the configuration too, even if the logs exist.
			config = newTestIssuerConfig(t)
			if err := ca.CreateIssuer(t.Context(), config); err != nil {
				t.Fatal(err)
			}
			tt.mutate(&config)
			if _, err := ca.LoadIssuer(t.Context(), config); err == nil {
				t.Error("LoadIssuer succeeded")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("LoadIssuer: got error %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

// TestCreateIssuer checks that the logs start with a placeholder entry at
// index 0, so that no certificate has index 0.
func TestCreateIssuer(t *testing.T) {
	config := newTestIssuerConfig(t)
	if err := ca.CreateIssuer(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		log  string
		want []byte
	}{
		{"issuance", mtc.NullLogEntry()},
		{"evidence", []byte("null")},
	} {
		b, err := config.Logs.Backend.Fetch(t.Context(), tt.log+"/tile/entries/000.p/1")
		if err != nil {
			t.Fatal(err)
		}
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		tile, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		entry, rest, err := torchwood.ReadTileEntry(tile)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(entry, tt.want) || len(rest) != 0 {
			t.Errorf("%s log tile is %x, want the single entry %x", tt.log, tile, tt.want)
		}
	}
	if _, err := ca.LoadIssuer(t.Context(), config); err != nil {
		t.Fatal(err)
	}
}

// TestLoadIssuerEmptyLog checks that an issuer whose logs were not created
// with CreateIssuer can't be loaded, as its first certificate would have
// index 0.
func TestLoadIssuerEmptyLog(t *testing.T) {
	config := newTestIssuerConfig(t)
	if err := lockstep.CreateLogs(t.Context(), config.Logs, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.LoadIssuer(t.Context(), config); err == nil {
		t.Error("LoadIssuer succeeded with empty logs")
	} else if !strings.Contains(err.Error(), "CreateIssuer") {
		t.Errorf("got error %q, want it to mention CreateIssuer", err)
	}
}
