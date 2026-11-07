package mtc

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// testCert returns a regular X.509 certificate with an ML-DSA-44 key and the
// given serial number, to exercise the TBSCertificate splitting without
// depending on [TBSCertificate].
func testCert(t *testing.T, serial *big.Int) *x509.Certificate {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Date(2026, 11, 7, 11, 34, 56, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func serialOf(t *testing.T, tbs []byte) *big.Int {
	t.Helper()
	f, err := splitTBS(tbs)
	if err != nil {
		t.Fatal(err)
	}
	s := cryptobyte.String(f.serial)
	serial := new(big.Int)
	if !s.ReadASN1Integer(serial) || !s.Empty() {
		t.Fatalf("malformed serial %x", f.serial)
	}
	return serial
}

func TestSplitTBS(t *testing.T) {
	cert := testCert(t, big.NewInt(1<<48))
	f, err := splitTBS(cert.RawTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := hex.EncodeToString(f.version), "a003020102"; got != want {
		t.Errorf("version = %s, want %s", got, want)
	}
	if got := serialOf(t, cert.RawTBSCertificate); got.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("serial = %v, want %v", got, cert.SerialNumber)
	}
	if !bytes.HasPrefix(f.issuerToSubject, cert.RawIssuer) {
		t.Errorf("issuerToSubject %x doesn't start with issuer %x", f.issuerToSubject, cert.RawIssuer)
	}
	if !bytes.HasSuffix(f.issuerToSubject, cert.RawSubject) {
		t.Errorf("issuerToSubject %x doesn't end with subject %x", f.issuerToSubject, cert.RawSubject)
	}
	if got, want := hex.EncodeToString(f.spkiAlg), "300b0609608648016503040311"; got != want {
		t.Errorf("spkiAlg = %s, want %s", got, want)
	}
	if !bytes.Equal(f.spki, cert.RawSubjectPublicKeyInfo) {
		t.Errorf("spki = %x, want %x", f.spki, cert.RawSubjectPublicKeyInfo)
	}
	if !bytes.HasSuffix(cert.RawTBSCertificate, f.afterSPKI) {
		t.Errorf("afterSPKI %x is not the end of the TBSCertificate", f.afterSPKI)
	}
	extensions := cryptobyte.String(f.afterSPKI)
	if !extensions.SkipASN1(cryptobyte_asn1.Tag(3).Constructed().ContextSpecific()) || !extensions.Empty() {
		t.Errorf("afterSPKI %x is not just the extensions", f.afterSPKI)
	}
}

func TestSplitTBSMalformed(t *testing.T) {
	tbs := testCert(t, big.NewInt(1<<48)).RawTBSCertificate
	for name, input := range map[string][]byte{
		"empty":     nil,
		"trailing":  append(bytes.Clone(tbs), 0),
		"truncated": tbs[:len(tbs)-1],
		"contents":  tbs[4:],
	} {
		if _, err := splitTBS(input); err == nil {
			t.Errorf("%s: splitTBS succeeded", name)
		}
	}
}

func TestSetSerial(t *testing.T) {
	original := testCert(t, big.NewInt(1<<48)).RawTBSCertificate
	tbs := bytes.Clone(original)

	const index = 0xffff_ffff_fffe
	if err := SetSerial(tbs, index); err != nil {
		t.Fatal(err)
	}
	if got, want := serialOf(t, tbs), big.NewInt(1<<48|index); got.Cmp(want) != 0 {
		t.Errorf("serial = %x, want %x", got, want)
	}

	if err := SetSerial(tbs, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tbs, original) {
		t.Error("SetSerial(tbs, index) then SetSerial(tbs, 0) didn't restore tbs")
	}
}

func TestSetSerialErrors(t *testing.T) {
	original := testCert(t, big.NewInt(1<<48)).RawTBSCertificate
	tbs := bytes.Clone(original)
	for _, index := range []int64{-1, 1 << 48} {
		if err := SetSerial(tbs, index); err == nil {
			t.Errorf("SetSerial(tbs, %d) succeeded", index)
		}
	}
	if !bytes.Equal(tbs, original) {
		t.Error("failed SetSerial modified tbs")
	}

	original = testCert(t, big.NewInt(5)).RawTBSCertificate
	tbs = bytes.Clone(original)
	if err := SetSerial(tbs, 0); err == nil {
		t.Error("SetSerial succeeded on a serialNumber of a different length")
	}
	if !bytes.Equal(tbs, original) {
		t.Error("failed SetSerial modified tbs")
	}
}

// tbsCertificateLogEntry is the TBSCertificateLogEntry ASN.1 structure, from
// draft-ietf-plants-merkle-tree-certs-07, Section 5.2.1.
type tbsCertificateLogEntry struct {
	Version  int `asn1:"optional,explicit,default:0,tag:0"`
	Issuer   asn1.RawValue
	Validity struct {
		NotBefore, NotAfter time.Time
	}
	Subject                   asn1.RawValue
	SubjectPublicKeyAlgorithm pkix.AlgorithmIdentifier
	SubjectPublicKeyInfoHash  []byte
	Extensions                []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

func TestLogEntry(t *testing.T) {
	cert := testCert(t, big.NewInt(1<<48))
	entry, err := LogEntry(cert.RawTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}

	s := cryptobyte.String(entry)
	var extensions cryptobyte.String
	var entryType uint16
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.ReadUint16(&entryType) {
		t.Fatalf("malformed MTCLogEntry %x", entry)
	}
	if !extensions.Empty() {
		t.Errorf("extensions = %x, want empty", extensions)
	}
	if entryType != 1 {
		t.Errorf("type = %d, want tbs_cert_entry (1)", entryType)
	}

	// tbs_cert_entry_data is the contents octets of a TBSCertificateLogEntry.
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddBytes(s) })
	der := b.BytesOrPanic()
	var e tbsCertificateLogEntry
	if rest, err := asn1.Unmarshal(der, &e); err != nil {
		t.Fatal(err)
	} else if len(rest) != 0 {
		t.Fatalf("trailing data after TBSCertificateLogEntry: %x", rest)
	}

	if e.Version != 2 {
		t.Errorf("version = %d, want 2 (v3)", e.Version)
	}
	if !bytes.Equal(e.Issuer.FullBytes, cert.RawIssuer) {
		t.Errorf("issuer = %x, want %x", e.Issuer.FullBytes, cert.RawIssuer)
	}
	if !e.Validity.NotBefore.Equal(cert.NotBefore) || !e.Validity.NotAfter.Equal(cert.NotAfter) {
		t.Errorf("validity = %v, want %v to %v", e.Validity, cert.NotBefore, cert.NotAfter)
	}
	if !bytes.Equal(e.Subject.FullBytes, cert.RawSubject) {
		t.Errorf("subject = %x, want %x", e.Subject.FullBytes, cert.RawSubject)
	}
	mldsa44 := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	if !e.SubjectPublicKeyAlgorithm.Algorithm.Equal(mldsa44) ||
		len(e.SubjectPublicKeyAlgorithm.Parameters.FullBytes) != 0 {
		t.Errorf("subjectPublicKeyAlgorithm = %v, want %v without parameters",
			e.SubjectPublicKeyAlgorithm, mldsa44)
	}
	if h := sha256.Sum256(cert.RawSubjectPublicKeyInfo); !bytes.Equal(e.SubjectPublicKeyInfoHash, h[:]) {
		t.Errorf("subjectPublicKeyInfoHash = %x, want %x", e.SubjectPublicKeyInfoHash, h)
	}
	if !reflect.DeepEqual(e.Extensions, cert.Extensions) {
		t.Errorf("extensions = %v, want %v", e.Extensions, cert.Extensions)
	}
}

func TestLogEntryIgnoresSerial(t *testing.T) {
	tbs := testCert(t, big.NewInt(1<<48)).RawTBSCertificate
	want, err := LogEntry(tbs)
	if err != nil {
		t.Fatal(err)
	}
	tbs = bytes.Clone(tbs)
	if err := SetSerial(tbs, 0xffff_ffff_fffe); err != nil {
		t.Fatal(err)
	}
	got, err := LogEntry(tbs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("LogEntry changed with the serial number")
	}
}

func TestLogEntryTooLarge(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1 << 48)}
	// Each name takes 2 + 253 bytes in the subjectAltName extension.
	for range 65535/255 + 1 {
		template.DNSNames = append(template.DNSNames, strings.Repeat("a.", 126)+"a")
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LogEntry(cert.RawTBSCertificate); err == nil {
		t.Error("LogEntry succeeded on an entry over 65535 bytes")
	}
}
