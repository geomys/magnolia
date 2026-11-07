package mtc

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func testPublicKey(t *testing.T, params mldsa.Parameters) *mldsa.PublicKey {
	t.Helper()
	key, err := mldsa.NewPrivateKey(params, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key.Public().(*mldsa.PublicKey)
}

func testTemplate(t *testing.T) *Template {
	return &Template{
		CAID:      MustParseTrustAnchorID("66252.1"),
		IssuedAt:  time.Date(2026, 11, 7, 12, 34, 56, 789_000_000, time.UTC),
		PublicKey: testPublicKey(t, mldsa.MLDSA44()),
		DNSNames:  []string{"example.com"},
	}
}

// parseTBS wraps tbs in a Certificate with the placeholder MTCProof, without
// depending on [Certificate], and parses it with crypto/x509.
func parseTBS(t *testing.T, tbs []byte) *x509.Certificate {
	t.Helper()
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		b.AddBytes(mtcProofAlgorithmIdentifier)
		b.AddASN1BitString(make([]byte, 19))
	})
	cert, err := x509.ParseCertificate(b.BytesOrPanic())
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestTBSCertificateBytes checks the encoding against the worked example
// assembled by hand from doc/profile.md and verified with openssl asn1parse.
func TestTBSCertificateBytes(t *testing.T) {
	tmpl := testTemplate(t)
	tbs, err := TBSCertificate(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"308205f2",
		"a003020102",               // version v3
		"020701000000000000",       // serialNumber (1 << 48) | 0
		"300a06082b06010505070643", // signature id-alg-mtcProof
		"30143112301006082b060105050719030d0484854c01", // issuer 66252.1
		"301e170d" + hex.EncodeToString([]byte("261107113456Z")) + // notBefore
			"170d" + hex.EncodeToString([]byte("261114033455Z")), // notAfter
		"3000", // subject
		"30820532300b0609608648016503040311038205210" + "0" +
			hex.EncodeToString(tmpl.PublicKey.Bytes()), // subjectPublicKeyInfo
		"a3683066",
		"300e0603551d0f0101ff0404030207 80",          // keyUsage
		"30130603551d25040c300a06082b06010505070301", // extKeyUsage
		"300f0603551d230408300680 0484854c01",        // authorityKeyIdentifier
		"30190603551d110101ff040f300d820b" + hex.EncodeToString([]byte("example.com")), // subjectAltName
		"30130603551d20040c300a3008060667810c010201",                                   // certificatePolicies
	}, "")
	want = strings.ReplaceAll(want, " ", "")
	if got := hex.EncodeToString(tbs); got != want {
		t.Errorf("TBSCertificate =\n%s\nwant\n%s", got, want)
	}
}

func TestTBSCertificate(t *testing.T) {
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			tmpl := testTemplate(t)
			tmpl.PublicKey = testPublicKey(t, params)
			tmpl.DNSNames = []string{"example.com", "*.example.com"}
			tmpl.IPAddresses = []netip.Addr{
				netip.MustParseAddr("192.0.2.1"),
				netip.MustParseAddr("2001:db8::1"),
			}
			tbs, err := TBSCertificate(tmpl)
			if err != nil {
				t.Fatal(err)
			}
			cert := parseTBS(t, tbs)

			if cert.Version != 3 {
				t.Errorf("Version = %d, want 3", cert.Version)
			}
			if got, want := cert.SerialNumber.Text(16), "1000000000000"; got != want {
				t.Errorf("SerialNumber = %s, want %s", got, want)
			}
			if got, want := hex.EncodeToString(cert.RawIssuer), "30143112301006082b060105050719030d0484854c01"; got != want {
				t.Errorf("RawIssuer = %s, want %s", got, want)
			}
			if got, want := hex.EncodeToString(cert.RawSubject), "3000"; got != want {
				t.Errorf("RawSubject = %s, want %s", got, want)
			}
			wantNotBefore := time.Date(2026, 11, 7, 11, 34, 56, 0, time.UTC)
			if !cert.NotBefore.Equal(wantNotBefore) {
				t.Errorf("NotBefore = %v, want %v", cert.NotBefore, wantNotBefore)
			}
			if got := cert.NotAfter.Sub(cert.NotBefore); got != 160*time.Hour-time.Second {
				t.Errorf("NotAfter - NotBefore = %v, want 160h - 1s", got)
			}

			if !tmpl.PublicKey.Equal(cert.PublicKey) {
				t.Errorf("PublicKey doesn't match")
			}
			spki, err := x509.MarshalPKIXPublicKey(tmpl.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(cert.RawSubjectPublicKeyInfo, spki) {
				t.Errorf("RawSubjectPublicKeyInfo doesn't match x509.MarshalPKIXPublicKey")
			}

			if cert.KeyUsage != x509.KeyUsageDigitalSignature {
				t.Errorf("KeyUsage = %v, want digitalSignature", cert.KeyUsage)
			}
			if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) ||
				len(cert.UnknownExtKeyUsage) != 0 {
				t.Errorf("ExtKeyUsage = %v %v, want serverAuth", cert.ExtKeyUsage, cert.UnknownExtKeyUsage)
			}
			if got, want := hex.EncodeToString(cert.AuthorityKeyId), "84854c01"; got != want {
				t.Errorf("AuthorityKeyId = %s, want %s", got, want)
			}
			if !slices.Equal(cert.DNSNames, tmpl.DNSNames) {
				t.Errorf("DNSNames = %v, want %v", cert.DNSNames, tmpl.DNSNames)
			}
			if len(cert.IPAddresses) != 2 || cert.IPAddresses[0].String() != "192.0.2.1" ||
				cert.IPAddresses[1].String() != "2001:db8::1" {
				t.Errorf("IPAddresses = %v", cert.IPAddresses)
			}
			if len(cert.Policies) != 1 || cert.Policies[0].String() != "2.23.140.1.2.1" {
				t.Errorf("Policies = %v, want [2.23.140.1.2.1]", cert.Policies)
			}

			type ext struct {
				oid      string
				critical bool
			}
			var got []ext
			for _, e := range cert.Extensions {
				got = append(got, ext{e.Id.String(), e.Critical})
			}
			want := []ext{
				{"2.5.29.15", true},  // keyUsage
				{"2.5.29.37", false}, // extKeyUsage
				{"2.5.29.35", false}, // authorityKeyIdentifier
				{"2.5.29.17", true},  // subjectAltName
				{"2.5.29.32", false}, // certificatePolicies
			}
			if !slices.Equal(got, want) {
				t.Errorf("Extensions = %v, want %v", got, want)
			}

			if _, err := LogEntry(tbs); err != nil {
				t.Errorf("LogEntry: %v", err)
			}
		})
	}
}

func TestTBSCertificateIPv4Encoding(t *testing.T) {
	tmpl := testTemplate(t)
	tmpl.DNSNames = nil
	tmpl.IPAddresses = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	tbs, err := TBSCertificate(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	// iPAddress [7] IMPLICIT OCTET STRING, 4 bytes for IPv4.
	if !bytes.Contains(tbs, []byte{0x87, 0x04, 192, 0, 2, 1}) {
		t.Errorf("IPv4 address not encoded as 4 bytes")
	}
}

func TestTBSCertificateTime(t *testing.T) {
	want, err := TBSCertificate(testTemplate(t))
	if err != nil {
		t.Fatal(err)
	}

	// The encoding must not depend on the time.Location or monotonic clock
	// reading of IssuedAt.
	tmpl := testTemplate(t)
	tmpl.IssuedAt = tmpl.IssuedAt.In(time.FixedZone("UTC+5", 5*60*60))
	if got, err := TBSCertificate(tmpl); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(got, want) {
		t.Error("TBSCertificate depends on the time.Location of IssuedAt")
	}

	// Truncation, not rounding, to the second.
	tmpl = testTemplate(t)
	tmpl.IssuedAt = time.Date(2026, 11, 7, 12, 34, 56, 999_999_999, time.UTC)
	if got, err := TBSCertificate(tmpl); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(got, want) {
		t.Error("IssuedAt is not truncated to the second")
	}

	// UTCTime can't represent 2050, and the profile doesn't allow
	// GeneralizedTime.
	tmpl = testTemplate(t)
	tmpl.IssuedAt = time.Date(2049, 12, 30, 0, 0, 0, 0, time.UTC)
	if _, err := TBSCertificate(tmpl); err == nil {
		t.Error("TBSCertificate succeeded with notAfter in 2050")
	}
}

func TestTBSCertificateInvalid(t *testing.T) {
	for name, modify := range map[string]func(*Template){
		"no CA ID":       func(t *Template) { t.CAID = TrustAnchorID{} },
		"no IssuedAt":    func(t *Template) { t.IssuedAt = time.Time{} },
		"no public key":  func(t *Template) { t.PublicKey = nil },
		"no names":       func(t *Template) { t.DNSNames = nil },
		"empty DNS name": func(t *Template) { t.DNSNames = []string{""} },
		"non-ASCII name": func(t *Template) { t.DNSNames = []string{"exämple.com"} },
		"invalid IP":     func(t *Template) { t.IPAddresses = []netip.Addr{{}} },
		"zoned IP":       func(t *Template) { t.IPAddresses = []netip.Addr{netip.MustParseAddr("fe80::1%eth0")} },
		"IPv4-mapped IP": func(t *Template) { t.IPAddresses = []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.1")} },
		"before UTCTime": func(t *Template) { t.IssuedAt = time.Date(1949, 1, 1, 0, 0, 0, 0, time.UTC) },
	} {
		tmpl := testTemplate(t)
		modify(tmpl)
		if _, err := TBSCertificate(tmpl); err == nil {
			t.Errorf("%s: TBSCertificate succeeded", name)
		}
	}
}

func TestTBSCertificateOIDs(t *testing.T) {
	// Cross-check the hardcoded encodings against encoding/asn1.
	for _, tt := range []struct {
		der []byte
		oid asn1.ObjectIdentifier
	}{
		{mtcProofAlgorithmIdentifier, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 67}},
	} {
		var ai struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		if rest, err := asn1.Unmarshal(tt.der, &ai); err != nil || len(rest) != 0 {
			t.Fatalf("%x: %v", tt.der, err)
		}
		if !ai.Algorithm.Equal(tt.oid) || len(ai.Parameters.FullBytes) != 0 {
			t.Errorf("%x = %v, want %v without parameters", tt.der, ai.Algorithm, tt.oid)
		}
	}
}
