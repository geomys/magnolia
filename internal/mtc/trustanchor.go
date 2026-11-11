package mtc

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"strings"
)

// maxTrustAnchorIDLen is the maximum length of the binary representation of a
// trust anchor ID, from draft-ietf-tls-trust-anchor-ids-06, Section 4.
const maxTrustAnchorIDLen = 32

// A TrustAnchorID is a trust anchor ID, as defined in
// draft-ietf-tls-trust-anchor-ids-06, Section 4.
//
// Only IDs of at most 32 bytes, with at least two components (a PEN and at
// least one component under its arc), are supported. As allowed by Section 8,
// components are also limited to 31 bits, the positive range of an int32.
//
// TrustAnchorID values can be compared with ==. The zero value is not a valid
// trust anchor ID.
type TrustAnchorID struct {
	b string // binary representation, always valid if not zero
}

// ParseTrustAnchorID parses the ASCII representation of a trust anchor ID,
// such as "66252.1".
func ParseTrustAnchorID(s string) (TrustAnchorID, error) {
	var b []byte
	for c := range strings.SplitSeq(s, ".") {
		if c == "" || len(c) > 1 && c[0] == '0' || strings.ContainsFunc(c, isNotDigit) {
			return TrustAnchorID{}, fmt.Errorf("invalid trust anchor ID %q", s)
		}
		n, err := strconv.ParseUint(c, 10, 64)
		if err != nil || n > math.MaxInt32 {
			return TrustAnchorID{}, fmt.Errorf("trust anchor ID %q has a component that is too large", s)
		}
		b = appendComponent(b, int32(n))
	}
	id, err := NewTrustAnchorID(b)
	if err != nil {
		return TrustAnchorID{}, fmt.Errorf("invalid trust anchor ID %q: %w", s, err)
	}
	return id, nil
}

// MustParseTrustAnchorID is like [ParseTrustAnchorID], but panics if s is not
// a valid trust anchor ID. It is intended for constants and tests.
func MustParseTrustAnchorID(s string) TrustAnchorID {
	id, err := ParseTrustAnchorID(s)
	if err != nil {
		panic("mtc: " + err.Error())
	}
	return id
}

func isNotDigit(r rune) bool { return r < '0' || r > '9' }

// NewTrustAnchorID returns a TrustAnchorID from the binary representation of a
// trust anchor ID, the contents octets of the DER encoding of its RELATIVE-OID.
// It returns an error if b is malformed or not supported.
func NewTrustAnchorID(b []byte) (TrustAnchorID, error) {
	if _, err := components(b); err != nil {
		return TrustAnchorID{}, err
	}
	return TrustAnchorID{string(b)}, nil
}

// appendComponent appends the encoding of a component to the binary
// representation of a trust anchor ID: base 128, most significant group first,
// with the high bit set on all bytes except the last one, per X.690, Section
// 8.20.2.
func appendComponent(b []byte, c int32) []byte {
	for i := (bits.Len32(uint32(c)) - 1) / 7; i > 0; i-- {
		b = append(b, byte(c>>(7*i))|0x80)
	}
	return append(b, byte(c)&0x7f)
}

// components decodes the components of the binary representation of a trust
// anchor ID, enforcing all the restrictions documented on [TrustAnchorID].
func components[B ~[]byte | ~string](b B) ([]int32, error) {
	if len(b) == 0 || len(b) > maxTrustAnchorIDLen {
		return nil, fmt.Errorf("trust anchor ID is %d bytes, expected 1 to %d", len(b), maxTrustAnchorIDLen)
	}
	var components []int32
	var n uint64
	var continued bool // the last byte had the high bit set
	for i := range len(b) {
		if !continued && b[i] == 0x80 {
			return nil, errors.New("non-minimal trust anchor ID component")
		}
		n = n<<7 | uint64(b[i]&0x7f)
		if n > math.MaxInt32 {
			return nil, errors.New("trust anchor ID component is too large")
		}
		continued = b[i]&0x80 != 0
		if !continued {
			components = append(components, int32(n))
			n = 0
		}
	}
	if continued {
		return nil, errors.New("truncated trust anchor ID component")
	}
	if len(components) < 2 {
		return nil, errors.New("trust anchor ID has fewer than two components")
	}
	return components, nil
}

// Bytes returns the binary representation of id, the contents octets of the
// DER encoding of its RELATIVE-OID.
func (id TrustAnchorID) Bytes() []byte {
	return []byte(id.b)
}

// String returns the ASCII representation of id, such as "66252.1".
func (id TrustAnchorID) String() string {
	if id.b == "" {
		return ""
	}
	components, err := components(id.b)
	if err != nil {
		panic("mtc: invalid TrustAnchorID: " + err.Error())
	}
	var b []byte
	for i, c := range components {
		if i > 0 {
			b = append(b, '.')
		}
		b = strconv.AppendInt(b, int64(c), 10)
	}
	return string(b)
}
