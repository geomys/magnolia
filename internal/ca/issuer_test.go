package ca_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/torchwood"
	"geomys.org/magnolia/internal/ca"
	"geomys.org/magnolia/internal/lockstep"
	"geomys.org/magnolia/internal/mtc"
	"golang.org/x/crypto/cryptobyte"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

const (
	testCAID           = "66252.99999.1"
	testIssuanceOrigin = "oid/1.3.6.1.4.1.66252.99999.1.0.1"
	testEvidenceOrigin = "magnolia.test/evidence"
	testReadPrefix     = "https://read.magnolia.test/66252.99999.1"
)

// testSequencingPeriod is long, since empty pools are sequenced too, and
// scripts sleep for hours of fake time.
const testSequencingPeriod = time.Hour

// newTestIssuer creates and loads a new issuer, and runs its sequencer until
// the end of the test. It also returns the issuer's configuration.
func newTestIssuer(t testing.TB) (*ca.Issuer, ca.IssuerConfig) {
	t.Helper()
	config := newTestIssuerConfig(t)
	return startTestIssuer(t, config), config
}

// startTestIssuer creates and loads a new issuer from config, and runs its
// sequencer until the end of the test.
func startTestIssuer(t testing.TB, config ca.IssuerConfig) *ca.Issuer {
	t.Helper()
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
	return newTestIssuerConfigIn(t, t.TempDir())
}

// newTestIssuerConfigIn is like newTestIssuerConfig, but the backend is the
// local directory dir.
func newTestIssuerConfigIn(t testing.TB, dir string) ca.IssuerConfig {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelWarn}))
	backend, err := lockstep.NewLocalBackend(t.Context(), dir, logger)
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
	return ca.IssuerConfig{CAID: testCAID, ReadPrefix: testReadPrefix, Logs: logs, SequencingPeriod: testSequencingPeriod}
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
		{"no ReadPrefix", func(c *ca.IssuerConfig) { c.ReadPrefix = "" }, "ReadPrefix"},
		{"ReadPrefix with trailing slash", func(c *ca.IssuerConfig) { c.ReadPrefix += "/" }, "trailing slash"},
		{"no sequencing period", func(c *ca.IssuerConfig) { c.SequencingPeriod = 0 }, "SequencingPeriod"},
		{"SubtreesSigned set", func(c *ca.IssuerConfig) {
			c.Logs.SubtreesSigned = func(context.Context, []*lockstep.SignedSubtree) error { return nil }
		}, "SubtreesSigned"},
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

func TestIndexPath(t *testing.T) {
	for _, tt := range []struct {
		n    int64
		want string
	}{
		{0, "000"},
		{7, "007"},
		{999, "999"},
		{1000, "x001/000"},
		{1234067, "x001/x234/067"},
		{1_000_000_000, "x001/x000/x000/000"},
	} {
		if got := ca.IndexPath(tt.n); got != tt.want {
			t.Errorf("indexPath(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// FuzzProofFiles checks that a TBSCertificate followed by a standalone file and
// a subtrees file is the certificate built by mtc.Certificate, for any proof it
// accepts.
func FuzzProofFiles(f *testing.F) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		f.Fatal(err)
	}
	caID, err := mtc.ParseTrustAnchorID("66252.99999.1")
	if err != nil {
		f.Fatal(err)
	}
	tbs, err := mtc.TBSCertificate(&mtc.Template{
		CAID:      caID,
		IssuedAt:  time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC),
		PublicKey: key.PublicKey(),
		DNSNames:  []string{"example.com"},
	})
	if err != nil {
		f.Fatal(err)
	}

	// cosignatures is a sequence of uint8 length-prefixed cosigner IDs, each
	// followed by a uint16 length-prefixed signature.
	cosigs := cryptobyte.NewBuilder(nil)
	for _, id := range []string{"66252.99999.0", "66252.99999.1"} {
		id, err := mtc.ParseTrustAnchorID(id)
		if err != nil {
			f.Fatal(err)
		}
		cosigs.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(id.Bytes()) })
		cosigs.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, 2420)) })
	}
	f.Add(int64(2), int64(0), int64(4), make([]byte, 2*32), cosigs.BytesOrPanic())
	f.Add(int64(0), int64(0), int64(1), []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, index, start, end int64, hashes, cosignatures []byte) {
		tbs := bytes.Clone(tbs)
		if err := mtc.SetSerial(tbs, index); err != nil {
			return
		}
		p := &mtc.Proof{Start: start, End: end}
		for h := range slices.Chunk(hashes, 32) {
			if len(h) == 32 {
				p.InclusionProof = append(p.InclusionProof, [32]byte(h))
			}
		}
		s := cryptobyte.String(cosignatures)
		for !s.Empty() {
			var id, sig cryptobyte.String
			if !s.ReadUint8LengthPrefixed(&id) || !s.ReadUint16LengthPrefixed(&sig) {
				return
			}
			cosignerID, err := mtc.NewTrustAnchorID(id)
			if err != nil {
				return
			}
			p.Cosignatures = append(p.Cosignatures, mtc.Cosignature{CosignerID: cosignerID, Signature: sig})
		}
		slices.SortFunc(p.Cosignatures, func(a, b mtc.Cosignature) int {
			return mtc.CompareCosignerIDs(a.CosignerID, b.CosignerID)
		})

		proof, err := p.Bytes()
		if err != nil {
			return
		}
		der, err := mtc.Certificate(tbs, proof)
		if err != nil {
			return
		}
		standalone, err := p.BytesWithoutSignatures()
		if err != nil {
			t.Fatalf("BytesWithoutSignatures: %v", err)
		}
		cosigs, err := mtc.SignaturesBytes(p.Cosignatures)
		if err != nil {
			t.Fatalf("SignaturesBytes: %v", err)
		}

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(cert.RawTBSCertificate, tbs) {
			t.Error("certificate tbsCertificate is not the TBSCertificate")
		}
		if !bytes.Equal(cert.Signature, append(standalone, cosigs...)) {
			t.Error("certificate signatureValue is not the standalone file followed by the subtrees file")
		}
	})
}
