package mtc

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func testCATemplate(t *testing.T) *CATemplate {
	return &CATemplate{
		CAID:       MustParseTrustAnchorID("66252.1"),
		NotBefore:  time.Date(2026, 11, 8, 0, 34, 56, 789_000_000, time.FixedZone("", 3600)),
		PublicKey:  testPublicKey(t, mldsa.MLDSA44()),
		PrefixURLs: []string{"https://read.example.com/66252.1/issuance"},
	}
}

func TestCACertificate(t *testing.T) {
	tmpl := testCATemplate(t)
	der, err := CACertificate(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	compareGolden(t, "ca", der)

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	// 1.3.6.1.5.5.7.25.3=#0d0484854c01, like the issuer of the certificates.
	name, _ := hex.DecodeString("3014311230100608" + "2b06010505071903" + "0d04" + "84854c01")
	if !bytes.Equal(cert.RawSubject, name) || !bytes.Equal(cert.RawIssuer, name) {
		t.Errorf("subject = %x, issuer = %x, want %x", cert.RawSubject, cert.RawIssuer, name)
	}
	if want := big.NewInt(0x84854c01); cert.SerialNumber.Cmp(want) != 0 {
		t.Errorf("serial number = %x, want %x", cert.SerialNumber, want)
	}
	if !bytes.Equal(cert.SubjectKeyId, tmpl.CAID.Bytes()) {
		t.Errorf("subject key identifier = %x", cert.SubjectKeyId)
	}
	if len(cert.AuthorityKeyId) != 0 {
		t.Errorf("authority key identifier = %x, want none", cert.AuthorityKeyId)
	}
	// Both dates are at midnight UTC.
	if want := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC); !cert.NotBefore.Equal(want) {
		t.Errorf("notBefore = %v, want %v", cert.NotBefore, want)
	}
	if want := time.Date(2037, 5, 4, 0, 0, 0, 0, time.UTC); !cert.NotAfter.Equal(want) {
		t.Errorf("notAfter = %v, want %v", cert.NotAfter, want)
	}
	if d := cert.NotAfter.Sub(cert.NotBefore); d != (1461+2280+90)*24*time.Hour {
		t.Errorf("notAfter - notBefore = %v", d)
	}
	if !tmpl.PublicKey.Equal(cert.PublicKey) {
		t.Error("public key doesn't match")
	}
	if !cert.BasicConstraintsValid || !cert.IsCA || cert.MaxPathLen != -1 {
		t.Errorf("basic constraints: valid %v, cA %v, pathLen %d", cert.BasicConstraintsValid, cert.IsCA, cert.MaxPathLen)
	}
	if cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("key usage = %b", cert.KeyUsage)
	}
	if len(cert.Signature) != 0 {
		t.Errorf("signature = %x, want empty", cert.Signature)
	}

	// The signature algorithms are id-alg-unsigned, and the signatureValue is
	// a BIT STRING of length zero.
	outer := cryptobyte.String(der)
	var certificate, tbs, sigAlg cryptobyte.String
	var sig asn1.BitString
	if !outer.ReadASN1(&certificate, cryptobyte_asn1.SEQUENCE) ||
		!certificate.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) ||
		!certificate.ReadASN1Element(&sigAlg, cryptobyte_asn1.SEQUENCE) ||
		!certificate.ReadASN1BitString(&sig) || !certificate.Empty() {
		t.Fatal("malformed certificate")
	}
	unsigned, _ := hex.DecodeString("300a06082b06010505070624")
	if !bytes.Equal(sigAlg, unsigned) || bytes.Count(tbs, unsigned) != 1 {
		t.Errorf("signature algorithms are not id-alg-unsigned")
	}
	if sig.BitLength != 0 {
		t.Errorf("signatureValue has %d bits", sig.BitLength)
	}

	// The extensions that crypto/x509 doesn't know, by OID.
	extensions := make(map[string][]byte)
	critical := make(map[string]bool)
	for _, e := range cert.Extensions {
		extensions[e.Id.String()] = e.Value
		critical[e.Id.String()] = e.Critical
	}
	if len(cert.Extensions) != 5 {
		t.Errorf("got %d extensions, want 5", len(cert.Extensions))
	}
	for oid, want := range map[string]bool{
		"2.5.29.15": true, "2.5.29.19": true, "2.5.29.14": false,
		"1.3.6.1.5.5.7.1.38": true, "1.3.6.1.4.1.64829.2.2": false,
	} {
		if _, ok := extensions[oid]; !ok || critical[oid] != want {
			t.Errorf("extension %s: present %v, critical %v, want critical %v", oid, ok, critical[oid], want)
		}
	}
	// sigAlg ML-DSA-44, minSerial 2^48, maxSerial 2^64 - 1.
	mtcCA, _ := hex.DecodeString("3021" + "300b0609608648016503040311" +
		"0207" + "01000000000000" + "0209" + "00ffffffffffffffff")
	if got := extensions["1.3.6.1.5.5.7.1.38"]; !bytes.Equal(got, mtcCA) {
		t.Errorf("MTCCertificationAuthority = %x, want %x", got, mtcCA)
	}
	var urls []string
	if _, err := asn1.UnmarshalWithParams(extensions["1.3.6.1.4.1.64829.2.2"], &urls, "ia5"); err != nil {
		t.Error(err)
	} else if len(urls) != 1 || urls[0] != tmpl.PrefixURLs[0] {
		t.Errorf("prefix URLs = %q", urls)
	}
}

func TestCACertificateInvalid(t *testing.T) {
	for name, mutate := range map[string]func(*CATemplate){
		"no CA ID": func(c *CATemplate) { c.CAID = TrustAnchorID{} },
		"long CA ID": func(c *CATemplate) {
			c.CAID = MustParseTrustAnchorID("66252.1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17")
		},
		"no notBefore":  func(c *CATemplate) { c.NotBefore = time.Time{} },
		"no key":        func(c *CATemplate) { c.PublicKey = nil },
		"ML-DSA-65 key": func(c *CATemplate) { c.PublicKey = testPublicKey(t, mldsa.MLDSA65()) },
		"no URLs":       func(c *CATemplate) { c.PrefixURLs = nil },
		"empty URL":     func(c *CATemplate) { c.PrefixURLs = []string{""} },
		"non-ASCII URL": func(c *CATemplate) { c.PrefixURLs = []string{"https://exämple.com"} },
	} {
		tmpl := testCATemplate(t)
		mutate(tmpl)
		if _, err := CACertificate(tmpl); err == nil {
			t.Errorf("%s: CACertificate succeeded", name)
		}
	}
}

// TestCACertificateTime checks that validity dates from 2050 are encoded as
// GeneralizedTime.
func TestCACertificateTime(t *testing.T) {
	tmpl := testCATemplate(t)
	tmpl.NotBefore = time.Date(2045, 1, 1, 0, 0, 0, 0, time.UTC)
	der, err := CACertificate(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(der, []byte("\x17\x0d450101000000Z\x18\x0f2055")) {
		t.Error("validity is not a UTCTime followed by a GeneralizedTime")
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		t.Error(err)
	}
}
