package ca

import (
	"cmp"
	"net/netip"

	"geomys.org/magnolia/internal/acmeerrors"
)

// An identifier is an ACME identifier, as it appears in order objects.
type identifier struct {
	Type  string `json:"type"`  // "dns" or "ip"
	Value string `json:"value"` // with "*." prefix for wildcards
}

func (id identifier) compare(other identifier) int {
	return cmp.Or(cmp.Compare(id.Type, other.Type), cmp.Compare(id.Value, other.Value))
}

func rejected(format string, a ...any) acmeerrors.Error {
	return acmeerrors.New("rejectedIdentifier", 400, format, a...)
}

// checkIPIdentifier checks that the value of an "ip" identifier is an address
// in the textual form RFC 8738 requires.
func checkIPIdentifier(value string) acmeerrors.Error {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return rejected("IP address is not valid: %w", err)
	}
	if ip.Zone() != "" {
		return rejected("IP address has a zone")
	}
	if ip.Is4In6() {
		return rejected("IP address is an IPv4-mapped IPv6 address")
	}
	if canonical := ip.String(); canonical != value {
		return rejected("IP address is not in its canonical form %s", canonical)
	}
	return nil
}
