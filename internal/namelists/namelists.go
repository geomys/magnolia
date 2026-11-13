// Package namelists implements the externally maintained lists that decide
// which identifiers can be certified: the IANA list of top-level domains, the
// ICANN section of the Public Suffix List, and the IANA special-purpose
// address registries.
package namelists

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// TLDs is the set of top-level domains in the root zone, which the Baseline
// Requirements use to define Internal Names.
type TLDs struct {
	names map[string]bool
}

// ParseTLDs parses https://data.iana.org/TLD/tlds-alpha-by-domain.txt, which
// has a top-level domain per line, with IDNs as A-labels, and comments
// starting with "#".
func ParseTLDs(data []byte) (*TLDs, error) {
	t := &TLDs{names: make(map[string]bool)}
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := strings.ToLower(line)
		if strings.ContainsFunc(name, func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-'
		}) {
			return nil, fmt.Errorf("invalid top-level domain %q", line)
		}
		t.names[name] = true
	}
	if len(t.names) == 0 {
		return nil, errors.New("no top-level domains")
	}
	return t, nil
}

// Contains reports whether label, in lowercase, is a top-level domain.
func (t *TLDs) Contains(label string) bool {
	return t.names[label]
}

// PublicSuffixes is the set of public suffixes in the ICANN section of the
// Public Suffix List, the domains under which registries let unrelated parties
// register names, such as "com" and "co.uk". The Baseline Requirements
// recommends using it for recognizing wildcards that would cover a whole
// registry, such as "*.co.uk".
type PublicSuffixes struct {
	rules      map[string]bool // exact rules, and the parents of wildcard rules
	wildcards  map[string]bool // parents of wildcard rules
	exceptions map[string]bool
}

const (
	beginICANN = "// ===BEGIN ICANN DOMAINS==="
	endICANN   = "// ===END ICANN DOMAINS==="
)

// ParsePublicSuffixes parses the ICANN section of
// https://publicsuffix.org/list/public_suffix_list.dat, in the format
// specified at https://github.com/publicsuffix/list/wiki/Format.
func ParsePublicSuffixes(data []byte) (*PublicSuffixes, error) {
	p := &PublicSuffixes{
		rules:      make(map[string]bool),
		wildcards:  make(map[string]bool),
		exceptions: make(map[string]bool),
	}
	const before, inside, after = 0, 1, 2
	section := before
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		switch {
		case line == beginICANN && section == before:
			section = inside
			continue
		case line == endICANN && section == inside:
			section = after
			continue
		case line == beginICANN || line == endICANN:
			return nil, errors.New("misplaced ICANN section marker")
		case section != inside || line == "" || strings.HasPrefix(line, "//"):
			continue
		}
		// Each line is only read up to the first whitespace.
		rule, _, _ := strings.Cut(line, " ")
		rule, _, _ = strings.Cut(rule, "\t")
		set := p.rules
		name := rule
		if rest, ok := strings.CutPrefix(rule, "!"); ok {
			set, name = p.exceptions, rest
		} else if rest, ok := strings.CutPrefix(rule, "*."); ok {
			set, name = p.wildcards, rest
		}
		// Rules are in Unicode, and are matched against A-labels.
		name, err := idna.Punycode.ToASCII(strings.ToLower(name))
		if err != nil {
			return nil, fmt.Errorf("invalid public suffix rule %q: %w", rule, err)
		}
		if name == "" || strings.Contains(name, "*") || strings.Contains(name, "!") ||
			strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
			return nil, fmt.Errorf("invalid public suffix rule %q", rule)
		}
		set[name] = true
	}
	if section != after {
		return nil, errors.New("missing ICANN section")
	}
	if len(p.rules) == 0 {
		return nil, errors.New("no public suffix rules")
	}
	// A wildcard rule such as "*.ck" makes everything directly under "ck" a
	// public suffix, but not "ck" itself. The parent is as registry-controlled
	// as its children, so we treat it as a public suffix too.
	for name := range p.wildcards {
		p.rules[name] = true
	}
	return p, nil
}

// Contains reports whether name is a public suffix. name must be a lowercase
// domain name without a trailing dot, with IDNs as A-labels.
func (p *PublicSuffixes) Contains(name string) bool {
	if p.exceptions[name] {
		return false
	}
	if p.rules[name] {
		return true
	}
	_, parent, ok := strings.Cut(name, ".")
	return ok && p.wildcards[parent]
}

// ReservedIPs is the set of address blocks in the IANA IPv4 and IPv6
// Special-Purpose Address Space registries, which the Baseline Requirements
// use to define Reserved IP Addresses.
type ReservedIPs struct {
	blocks []netip.Prefix
}

// ParseReservedIPs parses the CSV versions of the two registries,
// https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv and
// https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv.
func ParseReservedIPs(ipv4, ipv6 []byte) (*ReservedIPs, error) {
	r := &ReservedIPs{}
	for _, registry := range []struct {
		data []byte
		is4  bool
	}{{ipv4, true}, {ipv6, false}} {
		blocks, err := parseAddressRegistry(registry.data)
		if err != nil {
			return nil, err
		}
		for _, b := range blocks {
			if b.Addr().Is4() != registry.is4 {
				return nil, fmt.Errorf("address block %v is in the wrong registry", b)
			}
		}
		r.blocks = append(r.blocks, blocks...)
	}
	return r, nil
}

func parseAddressRegistry(data []byte) ([]netip.Prefix, error) {
	rd := csv.NewReader(bytes.NewReader(data))
	rd.FieldsPerRecord = -1
	records, err := rd.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("invalid address registry: %w", err)
	}
	if len(records) < 2 || len(records[0]) == 0 || records[0][0] != "Address Block" {
		return nil, errors.New("invalid address registry: missing Address Block column")
	}
	var blocks []netip.Prefix
	for _, record := range records[1:] {
		if len(record) == 0 {
			continue
		}
		// A cell can list multiple blocks, and have footnotes, such as
		// "192.0.0.170/32, 192.0.0.171/32" and "192.0.0.0/24 [2]".
		for block := range strings.SplitSeq(record[0], ",") {
			block, _, _ = strings.Cut(block, "[")
			prefix, err := netip.ParsePrefix(strings.TrimSpace(block))
			if err != nil {
				return nil, fmt.Errorf("invalid address block %q: %w", record[0], err)
			}
			if prefix != prefix.Masked() {
				return nil, fmt.Errorf("invalid address block %q: not a network address", record[0])
			}
			blocks = append(blocks, prefix)
		}
	}
	return blocks, nil
}

// Find returns the first special-purpose address block that contains ip.
func (r *ReservedIPs) Find(ip netip.Addr) (block netip.Prefix, ok bool) {
	for _, b := range r.blocks {
		if b.Contains(ip) {
			return b, true
		}
	}
	return netip.Prefix{}, false
}
