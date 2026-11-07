package mtc

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"filippo.io/torchwood"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/mod/sumdb/tlog"
)

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

// testTree builds a tree of n entries, where entry index is the log entry of
// tbs, and the others are arbitrary.
func testTree(t *testing.T, tbs []byte, index, n int64) hashStorage {
	t.Helper()
	entry, err := LogEntry(tbs)
	if err != nil {
		t.Fatal(err)
	}
	var s hashStorage
	for i := range n {
		data := []byte(fmt.Sprintf("entry %d", i))
		if i == index {
			data = entry
		}
		hashes, err := tlog.StoredHashes(i, data, s)
		if err != nil {
			t.Fatal(err)
		}
		s = append(s, hashes...)
	}
	return s
}

func testCosigner(t *testing.T, id string) *torchwood.CosignatureSigner {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	s, err := torchwood.NewCosignatureSigner("oid/1.3.6.1.4.1."+id, key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// mtcProof is a decoded MTCProof.
type mtcProof struct {
	extensions     []byte
	start, end     uint64
	inclusionProof torchwood.RecordInSubtreeProof
	cosignerIDs    [][]byte
	signatures     [][]byte
}

// verifyCertificate follows draft-ietf-plants-merkle-tree-certs-07, Section
// 7.2, as a relying party would, without using the package's own parsing. It
// checks the inclusion proof against subtreeHash, and returns the decoded
// MTCProof for the caller to check the cosignatures.
func verifyCertificate(t *testing.T, der []byte, subtreeHash tlog.Hash) *mtcProof {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
	s := cryptobyte.String(der)
	var certificate, tbs, tbsContents, sigAlg, tbsSigAlg cryptobyte.String
	var sigValue asn1BitString
	if !s.ReadASN1(&certificate, cryptobyte_asn1.SEQUENCE) || !s.Empty() ||
		!certificate.ReadASN1Element(&tbs, cryptobyte_asn1.SEQUENCE) ||
		!certificate.ReadASN1Element(&sigAlg, cryptobyte_asn1.SEQUENCE) ||
		!sigValue.read(&certificate) || !certificate.Empty() {
		t.Fatalf("malformed Certificate")
	}

	// Step 1: id-alg-mtcProof with omitted parameters, inside and out.
	const mtcProofAlgID = "300a06082b06010505070643"
	if hex.EncodeToString(sigAlg) != mtcProofAlgID {
		t.Errorf("signatureAlgorithm = %x", []byte(sigAlg))
	}
	tbsContents = tbs
	var version, serial, issuer, validity, subject, spki cryptobyte.String
	if !tbsContents.ReadASN1(&tbsContents, cryptobyte_asn1.SEQUENCE) ||
		!tbsContents.ReadASN1Element(&version, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) ||
		!tbsContents.ReadASN1Element(&serial, cryptobyte_asn1.INTEGER) ||
		!tbsContents.ReadASN1Element(&tbsSigAlg, cryptobyte_asn1.SEQUENCE) ||
		!tbsContents.ReadASN1Element(&issuer, cryptobyte_asn1.SEQUENCE) ||
		!tbsContents.ReadASN1Element(&validity, cryptobyte_asn1.SEQUENCE) ||
		!tbsContents.ReadASN1Element(&subject, cryptobyte_asn1.SEQUENCE) ||
		!tbsContents.ReadASN1Element(&spki, cryptobyte_asn1.SEQUENCE) {
		t.Fatalf("malformed TBSCertificate")
	}
	if hex.EncodeToString(tbsSigAlg) != mtcProofAlgID {
		t.Errorf("TBSCertificate signature = %x", []byte(tbsSigAlg))
	}

	// Step 2: decode the MTCProof, with no trailing data.
	p := &mtcProof{}
	proof := cryptobyte.String(sigValue)
	var extensions, inclusionProof, signatures cryptobyte.String
	if !proof.ReadUint16LengthPrefixed(&extensions) ||
		!proof.ReadUint48(&p.start) || !proof.ReadUint48(&p.end) ||
		!proof.ReadUint16LengthPrefixed(&inclusionProof) ||
		!proof.ReadUint24LengthPrefixed(&signatures) || !proof.Empty() ||
		len(inclusionProof)%32 != 0 {
		t.Fatalf("malformed MTCProof %x", []byte(sigValue))
	}
	p.extensions = extensions
	for len(inclusionProof) > 0 {
		var h tlog.Hash
		inclusionProof.CopyBytes(h[:])
		p.inclusionProof = append(p.inclusionProof, h)
	}
	for !signatures.Empty() {
		var id, sig cryptobyte.String
		if !signatures.ReadUint8LengthPrefixed(&id) || !signatures.ReadUint16LengthPrefixed(&sig) {
			t.Fatalf("malformed MTCProof signatures")
		}
		if n := len(p.cosignerIDs); n > 0 {
			prev := p.cosignerIDs[n-1]
			if len(id) < len(prev) || len(id) == len(prev) && bytes.Compare(id, prev) <= 0 {
				t.Errorf("cosigner ID %x is not after %x", []byte(id), prev)
			}
		}
		p.cosignerIDs = append(p.cosignerIDs, id)
		p.signatures = append(p.signatures, sig)
	}

	// Steps 3 to 5: index and log number from the serial number.
	if cert.SerialNumber.Sign() < 0 || cert.SerialNumber.BitLen() > 64 {
		t.Fatalf("serialNumber %v out of range", cert.SerialNumber)
	}
	serialNumber := cert.SerialNumber.Uint64()
	index, logNumber := serialNumber&(1<<48-1), serialNumber>>48
	if logNumber != 1 {
		t.Errorf("log number = %d, want 1", logNumber)
	}

	// Steps 7 to 9, with the single-pass method.
	spkiHash := sha256.Sum256(spki)
	spkiContents := spki
	var spkiAlg cryptobyte.String
	if !spkiContents.ReadASN1(&spkiContents, cryptobyte_asn1.SEQUENCE) ||
		!spkiContents.ReadASN1Element(&spkiAlg, cryptobyte_asn1.SEQUENCE) {
		t.Fatalf("malformed SubjectPublicKeyInfo")
	}
	h := sha256.New()
	h.Write([]byte{0x00})                       // leaf domain separator
	h.Write(appendUint16Prefixed(p.extensions)) // MTCProof.extensions
	h.Write([]byte{0x00, 0x01})                 // tbs_cert_entry
	h.Write(version)
	h.Write(issuer)
	h.Write(validity)
	h.Write(subject)
	h.Write(spkiAlg)
	h.Write([]byte{0x04, 0x20})
	h.Write(spkiHash[:])
	h.Write(tbsContents) // the rest, after subjectPublicKeyInfo
	var entryHash tlog.Hash
	h.Sum(entryHash[:0])

	// The single-pass hash matches the hash of the log entry.
	entry, err := LogEntry(tbs)
	if err != nil {
		t.Fatal(err)
	}
	if want := tlog.RecordHash(entry); entryHash != want {
		t.Errorf("single-pass entry hash %v, want RecordHash(LogEntry(tbs)) %v", entryHash, want)
	}

	// Step 10: the inclusion proof leads to the subtree hash.
	if err := torchwood.CheckRecordInSubtree(p.inclusionProof, int64(p.start), int64(p.end),
		subtreeHash, int64(index), entryHash); err != nil {
		t.Errorf("inclusion proof: %v", err)
	}
	return p
}

func appendUint16Prefixed(b []byte) []byte {
	return append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)
}

// asn1BitString is a BIT STRING with no unused bits.
type asn1BitString []byte

func (b *asn1BitString) read(s *cryptobyte.String) bool {
	var bs cryptobyte.String
	if !s.ReadASN1(&bs, cryptobyte_asn1.BIT_STRING) || len(bs) == 0 || bs[0] != 0 {
		return false
	}
	*b = asn1BitString(bs[1:])
	return true
}

func TestCertificateStandalone(t *testing.T) {
	const index, start, end, size = 9, 8, 13, 13
	tbs, err := TBSCertificate(testTemplate(t))
	if err != nil {
		t.Fatal(err)
	}
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

	const logOrigin = "oid/1.3.6.1.4.1.66252.1.0.1"
	mirror := testCosigner(t, "66252.0")
	ca := testCosigner(t, "66252.1")
	var cosignatures []Cosignature
	for _, c := range []struct {
		id     string
		signer *torchwood.CosignatureSigner
	}{{"66252.0", mirror}, {"66252.1", ca}} {
		sig, err := c.signer.SignSubtreeRaw(logOrigin, start, end, subtreeHash)
		if err != nil {
			t.Fatal(err)
		}
		cosignatures = append(cosignatures, Cosignature{MustParseTrustAnchorID(c.id), sig})
	}

	der, err := Certificate(tbs, &Proof{
		Start: start, End: end,
		InclusionProof: inclusionProof,
		Cosignatures:   cosignatures,
	})
	if err != nil {
		t.Fatal(err)
	}
	p := verifyCertificate(t, der, subtreeHash)

	if p.start != start || p.end != end {
		t.Errorf("subtree = [%d, %d), want [%d, %d)", p.start, p.end, start, end)
	}
	if len(p.extensions) != 0 {
		t.Errorf("extensions = %x, want empty", p.extensions)
	}
	if len(p.signatures) != 2 {
		t.Fatalf("got %d cosignatures, want 2", len(p.signatures))
	}
	for i, v := range []*torchwood.CosignatureVerifier{mirror.Verifier(), ca.Verifier()} {
		if !v.VerifySubtreeRaw(logOrigin, start, end, subtreeHash, p.signatures[i]) {
			t.Errorf("cosignature %d by %s doesn't verify", i, v.Name())
		}
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.RawTBSCertificate, tbs) {
		t.Error("RawTBSCertificate != tbs")
	}
	if cert.SerialNumber.Cmp(big.NewInt(1<<48|index)) != 0 {
		t.Errorf("SerialNumber = %v", cert.SerialNumber)
	}
}

func TestCertificateLandmarkRelative(t *testing.T) {
	const index, start, end, size = 9, 0, 16, 20
	tbs, err := TBSCertificate(testTemplate(t))
	if err != nil {
		t.Fatal(err)
	}
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
	der, err := Certificate(tbs, &Proof{Start: start, End: end, InclusionProof: inclusionProof})
	if err != nil {
		t.Fatal(err)
	}
	p := verifyCertificate(t, der, subtreeHash)
	if len(p.signatures) != 0 {
		t.Errorf("got %d cosignatures, want none", len(p.signatures))
	}
	if len(p.inclusionProof) != 4 {
		t.Errorf("inclusion proof has %d hashes, want 4", len(p.inclusionProof))
	}
}

func TestCertificatePlaceholder(t *testing.T) {
	tbs, err := TBSCertificate(testTemplate(t))
	if err != nil {
		t.Fatal(err)
	}
	der, err := Certificate(tbs, PlaceholderProof())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	want := "0000" + "000000000000" + "000000000001" + "0000" + "000000"
	if got := hex.EncodeToString(cert.Signature); got != want {
		t.Errorf("signatureValue = %s, want %s", got, want)
	}

	// A one-entry tree with the placeholder proof verifies, since the
	// subtree hash of [0, 1) is the entry hash.
	entry, err := LogEntry(tbs)
	if err != nil {
		t.Fatal(err)
	}
	verifyCertificate(t, der, tlog.RecordHash(entry))
}

func TestCertificateCosignerOrder(t *testing.T) {
	tbs, err := TBSCertificate(testTemplate(t))
	if err != nil {
		t.Fatal(err)
	}
	cosignatures := func(ids ...string) []Cosignature {
		var cs []Cosignature
		for _, id := range ids {
			cs = append(cs, Cosignature{MustParseTrustAnchorID(id), []byte("sig")})
		}
		return cs
	}
	for _, ids := range [][]string{
		{"66252.0", "66252.1"},
		{"66252.1", "66252.0.1"},   // shorter first, even if lexicographically later
		{"66252.127", "66252.128"}, // 84854c7f, 84854c8100
		{"1.1", "66252.0"},
	} {
		p := PlaceholderProof()
		p.Cosignatures = cosignatures(ids...)
		der, err := Certificate(tbs, p)
		if err != nil {
			t.Errorf("%v: %v", ids, err)
			continue
		}
		got := verifyCertificate(t, der, tlog.RecordHash(mustLogEntry(t, tbs)))
		for i, id := range ids {
			if want := MustParseTrustAnchorID(id).Bytes(); !bytes.Equal(got.cosignerIDs[i], want) {
				t.Errorf("%v: cosigner ID %d = %x, want %x", ids, i, got.cosignerIDs[i], want)
			}
		}
	}
	for _, ids := range [][]string{
		{"66252.1", "66252.0"},
		{"66252.0", "66252.0"},
		{"66252.0.1", "66252.1"},
		{"66252.128", "66252.127"},
	} {
		p := PlaceholderProof()
		p.Cosignatures = cosignatures(ids...)
		if _, err := Certificate(tbs, p); err == nil {
			t.Errorf("%v: Certificate succeeded", ids)
		}
	}
}

func mustLogEntry(t *testing.T, tbs []byte) []byte {
	t.Helper()
	entry, err := LogEntry(tbs)
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestCertificateInvalid(t *testing.T) {
	tbs, err := TBSCertificate(testTemplate(t))
	if err != nil {
		t.Fatal(err)
	}
	indexed := bytes.Clone(tbs)
	if err := SetSerial(indexed, 9); err != nil {
		t.Fatal(err)
	}
	otherLog := testCert(t, big.NewInt(2<<48)).RawTBSCertificate
	for name, tt := range map[string]struct {
		tbs []byte
		p   *Proof
	}{
		"empty subtree":        {tbs, &Proof{Start: 0, End: 0}},
		"reversed subtree":     {tbs, &Proof{Start: 1, End: 0}},
		"negative start":       {tbs, &Proof{Start: -1, End: 1}},
		"unaligned subtree":    {indexed, &Proof{Start: 9, End: 11}},
		"index after subtree":  {indexed, &Proof{Start: 0, End: 8}},
		"index before subtree": {indexed, &Proof{Start: 10, End: 11}},
		"end beyond uint48":    {tbs, &Proof{Start: 0, End: 1<<48 + 1}},
		"missing cosigner ID":  {tbs, &Proof{Start: 0, End: 1, Cosignatures: []Cosignature{{}}}},
		"signature too long":   {tbs, &Proof{Start: 0, End: 1, Cosignatures: []Cosignature{{MustParseTrustAnchorID("66252.0"), make([]byte, 1<<16)}}}},
		"inclusion proof long": {tbs, &Proof{Start: 0, End: 1, InclusionProof: make(torchwood.RecordInSubtreeProof, 1<<11)}},
		"malformed TBS":        {tbs[:len(tbs)-1], PlaceholderProof()},
		"other log":            {otherLog, PlaceholderProof()},
	} {
		if _, err := Certificate(tt.tbs, tt.p); err == nil {
			t.Errorf("%s: Certificate succeeded", name)
		}
	}
}
