package ca

import (
	"cmp"
	"net/netip"
	"strings"

	"geomys.org/magnolia/internal/acmeerrors"
	"geomys.org/magnolia/internal/namelists"
	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

// An identifier is an ACME identifier, as it appears in order objects.
type identifier struct {
	Type  string `json:"type"`  // "dns" or "ip"
	Value string `json:"value"` // with "*." prefix for wildcards
}

func (id identifier) compare(other identifier) int {
	return cmp.Or(cmp.Compare(id.Type, other.Type), cmp.Compare(id.Value, other.Value))
}

const (
	maxIdentifiers   = 10
	maxDNSNameLength = 253
	maxLabelLength   = 63
	minLabels        = 2
	maxLabels        = 10
)

func rejected(format string, a ...any) acmeerrors.Error {
	return acmeerrors.New("rejectedIdentifier", 400, format, a...)
}

// checkDNSSyntax checks that the value of a "dns" identifier is a domain name
// exactly as it would appear in a certificate, optionally preceded by "*.".
//
// The name must be lowercase and made of at least two P-Labels or Non-Reserved
// LDH Labels, without a trailing dot. A P-Label has to be valid Punycode that
// decodes to a string in Normalization Form C.
func checkDNSSyntax(value string) acmeerrors.Error {
	if value == "" {
		return rejected("DNS name is empty")
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return rejected("DNS name is an IP address")
	}
	if len(value) > maxDNSNameLength {
		return rejected("DNS name is longer than %d bytes", maxDNSNameLength)
	}
	name, _ := strings.CutPrefix(value, "*.")
	for _, c := range name {
		switch {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '.':
		case 'A' <= c && c <= 'Z':
			return rejected("DNS name is not lowercase")
		case c == '*':
			return rejected("DNS name has a wildcard that is not its whole first label")
		default:
			return rejected("DNS name has an invalid character %q", c)
		}
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		switch {
		case label == "":
			return rejected("DNS name has an empty label")
		case len(label) > maxLabelLength:
			return rejected("DNS name has a label longer than %d bytes", maxLabelLength)
		case label[0] == '-' || label[len(label)-1] == '-':
			return rejected("DNS name has a label that starts or ends with a hyphen")
		case strings.HasPrefix(label, "xn--"):
			decoded, err := idna.ToUnicode(label)
			if err != nil {
				return rejected("DNS name has an xn-- label that is not valid Punycode: %w", err)
			}
			if !norm.NFC.IsNormalString(decoded) {
				return rejected("DNS name has a P-Label that does not decode to Unicode Normalization Form C")
			}
		case len(label) >= 4 && label[2:4] == "--":
			return rejected("DNS name has a label with hyphens in the third and fourth position that is not a P-Label")
		}
	}
	if len(labels) < minLabels {
		return rejected("DNS name has fewer than %d labels", minLabels)
	}
	if len(labels) > maxLabels {
		return rejected("DNS name has more than %d labels", maxLabels)
	}
	return nil
}

// checkDNSIdentifier checks that the value of a "dns" identifier is a name the
// CA is willing to certify.
//
// Besides [checkDNSSyntax], the name can't be an Internal Name. It can't be a
// public suffix, or a wildcard for one. Nothing under .arpa is accepted, which
// rules out reverse zones and a few special-use names.
func checkDNSIdentifier(value string, tlds *namelists.TLDs, suffixes *namelists.PublicSuffixes) acmeerrors.Error {
	if err := checkDNSSyntax(value); err != nil {
		return err
	}
	name, wildcard := strings.CutPrefix(value, "*.")
	_, tld, _ := strings.CutLast(name, ".")
	switch {
	case !tlds.Contains(tld):
		return rejected("DNS name does not end in a public top-level domain")
	case tld == "arpa":
		return rejected("DNS name is under .arpa")
	case suffixes.Contains(name):
		if wildcard {
			return rejected("DNS name is a wildcard for a public suffix")
		}
		return rejected("DNS name is a public suffix")
	}
	return nil
}

// checkIPIdentifier checks that the value of an "ip" identifier is an address
// the CA is willing to certify, in the textual form RFC 8738 requires.
//
// The address can't be a Reserved IP Address, in the terms of the Baseline
// Requirements, or a multicast address.
func checkIPIdentifier(value string, reserved *namelists.ReservedIPs) acmeerrors.Error {
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
	if block, ok := reserved.Find(ip); ok {
		return rejected("IP address is in the special-purpose block %v", block)
	}
	if ip.IsMulticast() {
		return rejected("IP address is a multicast address")
	}
	return nil
}

// identifiersError returns the error for a newOrder request with rejected
// identifiers, with a subproblem for each of them, as specified in RFC 8555,
// Section 6.7.1. Every error in rejected is for the identifier at the same
// index in ids.
func identifiersError(ids []identifier, rejected []acmeerrors.Error) acmeerrors.Error {
	subproblems := make([]map[string]any, 0, len(rejected))
	for i, err := range rejected {
		subproblems = append(subproblems, acmeerrors.Render(err.WithField("identifier", ids[i])))
	}
	var err acmeerrors.Error
	if len(rejected) == 1 {
		err = acmeerrors.New("rejectedIdentifier", 400, "rejected identifier %q: %s",
			ids[0].Value, rejected[0].Detail())
	} else {
		err = acmeerrors.New("rejectedIdentifier", 400, "rejected identifier %q and %d more: %s",
			ids[0].Value, len(rejected)-1, rejected[0].Detail())
	}
	return err.WithField("subproblems", subproblems)
}
