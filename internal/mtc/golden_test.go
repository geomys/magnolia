package mtc

import (
	"bytes"
	"crypto/mldsa"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

var update = flag.Bool("update", false, "update golden files in testdata")

// TestGolden compares the certificates built from a fixed template against
// the DER files in testdata, so that any change to the profile or to the
// encoding shows up in a diff. Run with -update to regenerate them.
//
// The cosignatures are fixed bytes, since ML-DSA signing is randomized.
func TestGolden(t *testing.T) {
	tmpl := testTemplate(t)
	tmpl.DNSNames = []string{"example.com", "*.example.com"}
	tmpl.IPAddresses = []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	}
	tbs, err := TBSCertificate(tmpl)
	if err != nil {
		t.Fatal(err)
	}

	placeholder, err := Certificate(tbs, PlaceholderProof())
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "placeholder", placeholder, tlog.RecordHash(mustLogEntry(t, tbs)))

	const index, start, end, size = 9, 8, 13, 13
	if err := SetSerial(tbs, index); err != nil {
		t.Fatal(err)
	}
	tree := testTree(t, tbs, index, size)
	subtreeHash, err := torchwood.SubtreeHash(start, end, tree)
	if err != nil {
		t.Fatal(err)
	}
	inclusionProof, err := torchwood.ProveRecordInSubtree(start, end, index, tree)
	if err != nil {
		t.Fatal(err)
	}
	sigSize := mldsa.MLDSA44().SignatureSize()
	standalone, err := certificate(tbs, &Proof{
		Start: start, End: end,
		InclusionProof: inclusionProof,
		Cosignatures: []Cosignature{
			{MustParseTrustAnchorID("66252.0"), bytes.Repeat([]byte{0xa0}, sigSize)},
			{MustParseTrustAnchorID("66252.1"), bytes.Repeat([]byte{0xa1}, sigSize)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "standalone", standalone, subtreeHash)

	const landmarkStart, landmarkEnd = 0, 16
	tree = testTree(t, tbs, index, landmarkEnd)
	subtreeHash, err = torchwood.SubtreeHash(landmarkStart, landmarkEnd, tree)
	if err != nil {
		t.Fatal(err)
	}
	inclusionProof, err = torchwood.ProveRecordInSubtree(landmarkStart, landmarkEnd, index, tree)
	if err != nil {
		t.Fatal(err)
	}
	landmark, err := certificate(tbs, &Proof{
		Start: landmarkStart, End: landmarkEnd,
		InclusionProof: inclusionProof,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "landmark", landmark, subtreeHash)
}

func checkGolden(t *testing.T, name string, der []byte, subtreeHash tlog.Hash) {
	t.Helper()
	verifyCertificate(t, der, subtreeHash)
	compareGolden(t, name, der)
}

func compareGolden(t *testing.T, name string, der []byte) {
	t.Helper()
	path := filepath.Join("testdata", name+".der")
	if *update {
		if err := os.WriteFile(path, der, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, want) {
		i := 0
		for i < len(der) && i < len(want) && der[i] == want[i] {
			i++
		}
		t.Errorf("%s: got %d bytes, want %d, first difference at offset %d; "+
			"run with -update and inspect with openssl asn1parse -inform DER -i -in %s",
			name, len(der), len(want), i, path)
	}
}
