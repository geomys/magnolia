package mtc

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// TestPropertyListExample encodes the example CertificatePropertyList of
// draft-ietf-tls-trust-anchor-ids-06, Section 7.4: trust anchor ID 32473.1,
// groups 2187.2.{100-200} and 32473.3.{42-}.{100-200}, and negotiation.
func TestPropertyListExample(t *testing.T) {
	want := "ACoAAAAEgf1ZAQABABoAGAmRC5ELAgJkgUgNgf1Zgf1ZAwMqgGSBSAACAAA="
	got, err := propertyList(MustParseTrustAnchorID("32473.1").Bytes(), [][]byte{
		{0x91, 0x0b, 0x91, 0x0b, 2, 2, 100, 0x81, 0x48},
		{0x81, 0xfd, 0x59, 0x81, 0xfd, 0x59, 3, 3, 42, 0x80, 100, 0x81, 0x48},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(got); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestStandaloneProperties(t *testing.T) {
	caID := MustParseTrustAnchorID("66252.1")

	// trust_anchor_id 66252.1, trust_anchor_groups 66252.1.2.{0-}.{0-}.
	want := "001d" +
		"0000" + "0004" + "84854c01" +
		"0001" + "0011" + "000f" + "0e" + "84854c84854c" + "0101" + "0202" + "0080" + "0080"
	got, err := StandaloneProperties(caID)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(got); got != want {
		t.Errorf("got %s, want %s", got, want)
	}

	if _, err := StandaloneProperties(TrustAnchorID{}); err == nil {
		t.Error("StandaloneProperties accepted a zero CA ID")
	}
}
