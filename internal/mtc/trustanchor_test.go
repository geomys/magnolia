package mtc

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestTrustAnchorID(t *testing.T) {
	for _, tt := range []struct {
		ascii, binary string
	}{
		{"32473.1", "81fd5901"}, // draft-ietf-tls-trust-anchor-ids-06, Section 4
		{"66252.1", "84854c01"}, // doc/profile.md
		{"66252.1.0.1", "84854c010001"},
		{"1.0", "0100"},
		{"1.127", "017f"},
		{"1.128", "018100"},
		{"1.16383", "01ff7f"},
		{"1.16384", "01818000"},
		{"1.2147483647", "0187ffffff7f"},
		{strings.Repeat("1.", 31) + "1", strings.Repeat("01", 32)},
	} {
		id, err := ParseTrustAnchorID(tt.ascii)
		if err != nil {
			t.Errorf("ParseTrustAnchorID(%q): %v", tt.ascii, err)
			continue
		}
		if got := hex.EncodeToString(id.Bytes()); got != tt.binary {
			t.Errorf("ParseTrustAnchorID(%q) = %s, want %s", tt.ascii, got, tt.binary)
		}

		b := mustDecodeHex(t, tt.binary)
		id2, err := NewTrustAnchorID(b)
		if err != nil {
			t.Errorf("NewTrustAnchorID(%s): %v", tt.binary, err)
			continue
		}
		if got := id2.String(); got != tt.ascii {
			t.Errorf("NewTrustAnchorID(%s).String() = %q, want %q", tt.binary, got, tt.ascii)
		}
		if id != id2 {
			t.Errorf("%q: ParseTrustAnchorID != NewTrustAnchorID", tt.ascii)
		}
	}
}

func TestParseTrustAnchorIDInvalid(t *testing.T) {
	for _, s := range []string{
		"",
		".",
		"1",
		"66252",
		"1.",
		".1",
		"1..2",
		"01.1",
		"66252.01",
		"-1.1",
		"+1.1",
		" 1.1",
		"1.1 ",
		"0x10.1",
		"1.2147483648",
		"1.4294967296",
		"1.18446744073709551616",
		strings.Repeat("1.", 32) + "1",
	} {
		if id, err := ParseTrustAnchorID(s); err == nil {
			t.Errorf("ParseTrustAnchorID(%q) = %v, want error", s, id)
		}
	}
}

func TestNewTrustAnchorIDInvalid(t *testing.T) {
	for _, binary := range []string{
		"",
		"01",                     // one component
		"84854c",                 // one component
		"018001",                 // non-minimal
		"84854c8001",             // non-minimal second component
		"0184",                   // truncated
		"84854c8485",             // truncated
		"018880808000",           // 2^31
		"01908080808000",         // 2^32
		"0181808080808000",       // 2^35
		strings.Repeat("01", 33), // too long
	} {
		b := mustDecodeHex(t, binary)
		if id, err := NewTrustAnchorID(b); err == nil {
			t.Errorf("NewTrustAnchorID(%s) = %v, want error", binary, id)
		}
	}
}

func TestTrustAnchorIDBytesCopy(t *testing.T) {
	b := []byte{0x84, 0x85, 0x4c, 0x01}
	id, err := NewTrustAnchorID(b)
	if err != nil {
		t.Fatal(err)
	}
	b[3] = 0x02
	id.Bytes()[3] = 0x03
	if got := id.String(); got != "66252.1" {
		t.Errorf("TrustAnchorID changed to %q through an aliased slice", got)
	}
}

func TestTrustAnchorIDRoundTrip(t *testing.T) {
	for _, s := range []string{"1.2", "1.2.3", "66252.99999.1.0.1", "2147483647.1073741824"} {
		id, err := ParseTrustAnchorID(s)
		if err != nil {
			t.Fatal(err)
		}
		again, err := NewTrustAnchorID(id.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if id != again || again.String() != s {
			t.Errorf("%q: round trip produced %q", s, again)
		}
	}
	if zero := (TrustAnchorID{}); !bytes.Equal(zero.Bytes(), nil) || zero.String() != "" {
		t.Error("zero TrustAnchorID is not empty")
	}
}

func TestMustParseTrustAnchorID(t *testing.T) {
	if got := MustParseTrustAnchorID("66252.1").String(); got != "66252.1" {
		t.Errorf("MustParseTrustAnchorID(\"66252.1\") = %q", got)
	}
	defer func() {
		if recover() == nil {
			t.Error("MustParseTrustAnchorID(\"66252\") didn't panic")
		}
	}()
	MustParseTrustAnchorID("66252")
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
