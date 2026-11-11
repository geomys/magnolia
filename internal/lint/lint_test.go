package lint

import (
	"crypto/mldsa"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"filippo.io/torchwood"
	"geomys.org/magnolia/internal/mtc"
	"golang.org/x/mod/sumdb/tlog"
)

func testTemplate(t *testing.T, params mldsa.Parameters) *mtc.Template {
	t.Helper()
	key, err := mldsa.GenerateKey(params)
	if err != nil {
		t.Fatal(err)
	}
	return &mtc.Template{
		CAID:        mtc.MustParseTrustAnchorID("66252.1"),
		IssuedAt:    time.Now(),
		PublicKey:   key.Public().(*mldsa.PublicKey),
		DNSNames:    []string{"example.com", "*.example.com"},
		IPAddresses: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2001:4860:4860::8888")},
	}
}

func testTBS(t *testing.T, tmpl *mtc.Template) []byte {
	t.Helper()
	tbs, err := mtc.TBSCertificate(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	return tbs
}

// hashStorage is an in-memory tlog.HashReader.
type hashStorage []tlog.Hash

func (s hashStorage) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, x := range indexes {
		if x >= int64(len(s)) {
			return nil, fmt.Errorf("hash %d not stored", x)
		}
		out[i] = s[x]
	}
	return out, nil
}

// testProof sets the serial of tbs to index, and returns the subtree hash and
// inclusion proof for [start, end) in a tree of end entries, where entry index
// is the log entry of tbs and the others are arbitrary.
func testProof(t *testing.T, tbs []byte, index, start, end int64) (tlog.Hash, torchwood.RecordInSubtreeProof) {
	t.Helper()
	if err := mtc.SetSerial(tbs, index); err != nil {
		t.Fatal(err)
	}
	entry, err := mtc.LogEntry(tbs)
	if err != nil {
		t.Fatal(err)
	}
	var s hashStorage
	for i := range end {
		data := fmt.Appendf(nil, "entry %d", i)
		if i == index {
			data = entry
		}
		hashes, err := tlog.StoredHashes(i, data, s)
		if err != nil {
			t.Fatal(err)
		}
		s = append(s, hashes...)
	}
	hash, err := torchwood.SubtreeHash(start, end, s)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := torchwood.ProveRecordInSubtree(start, end, index, s)
	if err != nil {
		t.Fatal(err)
	}
	return hash, proof
}

type testCosigner struct {
	Cosigner
	signer *torchwood.CosignatureSigner
}

func newTestCosigner(t *testing.T, id string) testCosigner {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	s, err := torchwood.NewCosignatureSigner("oid/1.3.6.1.4.1."+id, key)
	if err != nil {
		t.Fatal(err)
	}
	return testCosigner{
		Cosigner: Cosigner{ID: mtc.MustParseTrustAnchorID(id), Key: key.Public().(*mldsa.PublicKey)},
		signer:   s,
	}
}

// testCertificate returns the Certificate for a TBSCertificate and a proof.
func testCertificate(t *testing.T, tbs []byte, p *mtc.Proof) []byte {
	t.Helper()
	proof, err := p.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := mtc.Certificate(tbs, proof)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func standaloneCert(t *testing.T, tbs []byte, cosigners ...testCosigner) []byte {
	t.Helper()
	const index, start, end = 9, 8, 13
	hash, proof := testProof(t, tbs, index, start, end)
	var cosignatures []mtc.Cosignature
	for _, c := range cosigners {
		sig, err := c.signer.SignSubtreeRaw("oid/1.3.6.1.4.1.66252.1.0.1", start, end, hash)
		if err != nil {
			t.Fatal(err)
		}
		cosignatures = append(cosignatures, mtc.Cosignature{CosignerID: c.ID, Signature: sig})
	}
	return testCertificate(t, tbs, &mtc.Proof{
		Start: start, End: end, InclusionProof: proof, Cosignatures: cosignatures})
}

// failedLints returns the names of the failed lints in err, or fails the test
// if err is not an *Error.
func failedLints(t *testing.T, err error) []string {
	t.Helper()
	var lintErr *Error
	if !errors.As(err, &lintErr) {
		t.Fatalf("got %v, want *Error", err)
	}
	var names []string
	for _, r := range lintErr.Results {
		names = append(names, r.Name)
	}
	return names
}

func TestPreIssuance(t *testing.T) {
	l, err := PreIssuance()
	if err != nil {
		t.Fatal(err)
	}
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			if err := l.Lint(testTBS(t, testTemplate(t, params))); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestPreIssuanceFailure(t *testing.T) {
	l, err := PreIssuance()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := testTemplate(t, mldsa.MLDSA44())
	tmpl.IPAddresses = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	names := failedLints(t, l.Lint(testTBS(t, tmpl)))
	if !slices.Contains(names, "e_ext_san_contains_reserved_ip") {
		t.Errorf("failed lints %v don't include e_ext_san_contains_reserved_ip", names)
	}
}

func TestPreIssuanceRejectsCertificate(t *testing.T) {
	l, err := PreIssuance()
	if err != nil {
		t.Fatal(err)
	}
	tbs := testTBS(t, testTemplate(t, mldsa.MLDSA44()))
	cert, err := mtc.Certificate(tbs, mtc.PlaceholderProof())
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Lint(cert); err == nil {
		t.Error("linted a Certificate as a TBSCertificate")
	}
}

func TestStandalone(t *testing.T) {
	mirror := newTestCosigner(t, "66252.0")
	ca := newTestCosigner(t, "66252.1")
	other := newTestCosigner(t, "66252.2")
	l, err := Standalone([]Cosigner{mirror.Cosigner, ca.Cosigner})
	if err != nil {
		t.Fatal(err)
	}
	tbs := testTBS(t, testTemplate(t, mldsa.MLDSA65()))

	t.Run("valid", func(t *testing.T) {
		if err := l.Lint(standaloneCert(t, tbs, mirror, ca)); err != nil {
			t.Error(err)
		}
	})
	t.Run("extra cosigner", func(t *testing.T) {
		if err := l.Lint(standaloneCert(t, tbs, mirror, ca, other)); err != nil {
			t.Error(err)
		}
	})
	t.Run("missing cosigner", func(t *testing.T) {
		names := failedLints(t, l.Lint(standaloneCert(t, tbs, ca)))
		if !slices.Equal(names, []string{"e_mtc_proof_verifies"}) {
			t.Errorf("failed lints = %v, want [e_mtc_proof_verifies]", names)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		forged := ca
		forged.signer = other.signer
		names := failedLints(t, l.Lint(standaloneCert(t, tbs, mirror, forged)))
		if !slices.Equal(names, []string{"e_mtc_proof_verifies"}) {
			t.Errorf("failed lints = %v, want [e_mtc_proof_verifies]", names)
		}
	})
	t.Run("TBSCertificate", func(t *testing.T) {
		if err := l.Lint(tbs); err == nil {
			t.Error("linted a TBSCertificate as a Certificate")
		}
	})
}

func TestLandmark(t *testing.T) {
	const index, start, end = 9, 0, 16
	tbs := testTBS(t, testTemplate(t, mldsa.MLDSA87()))
	hash, proof := testProof(t, tbs, index, start, end)
	cert := testCertificate(t, tbs, &mtc.Proof{Start: start, End: end, InclusionProof: proof})

	l, err := Landmark([2]Subtree{{Start: start, End: end, Hash: hash}, {Start: 16, End: 18}})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Lint(cert); err != nil {
		t.Error(err)
	}

	l, err = Landmark([2]Subtree{{Start: start, End: end}, {Start: 16, End: 18}})
	if err != nil {
		t.Fatal(err)
	}
	names := failedLints(t, l.Lint(cert))
	if !slices.Equal(names, []string{"e_mtc_proof_verifies"}) {
		t.Errorf("failed lints = %v, want [e_mtc_proof_verifies]", names)
	}
}

func TestIgnoredLintsExist(t *testing.T) {
	ignored["e_no_such_lint"] = true
	defer delete(ignored, "e_no_such_lint")
	if _, err := PreIssuance(); err == nil {
		t.Error("unknown ignored lint was accepted")
	}
}
