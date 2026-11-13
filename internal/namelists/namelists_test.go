package namelists_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"geomys.org/magnolia/internal/namelists"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestTLDs(t *testing.T) {
	tlds, err := namelists.ParseTLDs(readTestdata(t, "tlds-alpha-by-domain.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"com":         true,
		"aaa":         true,
		"zw":          true,
		"arpa":        true,
		"xn--p1ai":    true,
		"COM":         false,
		"local":       false,
		"onion":       false,
		"example.com": false,
		"":            false,
		"version":     false,
	} {
		if got := tlds.Contains(name); got != want {
			t.Errorf("Contains(%q) = %v, want %v", name, got, want)
		}
	}

	for _, data := range []string{
		"",
		"# Version 2026111300\n",
		"COM\nexample.com\n",
		"COM\nNET ORG\n",
		"<html>\n",
	} {
		if _, err := namelists.ParseTLDs([]byte(data)); err == nil {
			t.Errorf("ParseTLDs(%q) succeeded", data)
		}
	}
}

func TestPublicSuffixes(t *testing.T) {
	psl, err := namelists.ParsePublicSuffixes(readTestdata(t, "public_suffix_list.dat"))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"com":             true,
		"example.com":     false,
		"www.example.com": false,
		"uk":              true,
		"co.uk":           true,
		"example.co.uk":   false,
		"example.uk":      false,
		"onion":           true,

		// Wildcard rules make every name directly under them a public
		// suffix, except for exceptions, and their parent too.
		"ck":                    true,
		"example.ck":            true,
		"www.ck":                false,
		"www.example.ck":        false,
		"kawasaki.jp":           true,
		"example.kawasaki.jp":   true,
		"city.kawasaki.jp":      false,
		"a.example.kawasaki.jp": false,
		"sch.uk":                true,
		"example.sch.uk":        true,

		// Rules are converted to A-labels.
		"xn--p1ai":         true,
		"example.xn--p1ai": false,
		"xn--55qx5d.cn":    true,
		"рф":               false,

		// A top-level domain without a rule of its own is not a public
		// suffix, even if there are rules under it.
		"za":         false,
		"co.za":      true,
		"example.za": false,
		"local":      false,

		// The private section is ignored.
		"github.io":                          false,
		"example.githubcloudusercontent.com": false,

		"":     false,
		"COM":  false,
		"com.": false,
	} {
		if got := psl.Contains(name); got != want {
			t.Errorf("Contains(%q) = %v, want %v", name, got, want)
		}
	}

	section := func(rules ...string) string {
		return "// ===BEGIN ICANN DOMAINS===\n" + strings.Join(rules, "\n") + "\n// ===END ICANN DOMAINS===\n"
	}
	if _, err := namelists.ParsePublicSuffixes([]byte(section("com // trailing text is ignored", "  net  "))); err != nil {
		t.Error(err)
	}
	for _, data := range []string{
		"",
		"com\nnet\n",
		"// ===BEGIN ICANN DOMAINS===\ncom\n",
		"com\n// ===END ICANN DOMAINS===\n",
		"// ===END ICANN DOMAINS===\ncom\n// ===BEGIN ICANN DOMAINS===\n",
		section("com") + section("net"),
		section(),
		section("// only comments"),
		section("*"),
		section("!"),
		section("*.*.com"),
		section("example.*.com"),
		section("com."),
		section(".com"),
		section("example..com"),
		section("!!www.ck"),
	} {
		if _, err := namelists.ParsePublicSuffixes([]byte(data)); err == nil {
			t.Errorf("ParsePublicSuffixes(%q) succeeded", data)
		}
	}
}

func TestReservedIPs(t *testing.T) {
	ipv4 := readTestdata(t, "iana-ipv4-special-registry-1.csv")
	ipv6 := readTestdata(t, "iana-ipv6-special-registry-1.csv")
	ips, err := namelists.ParseReservedIPs(ipv4, ipv6)
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]string{
		"10.1.2.3":        "10.0.0.0/8",
		"127.0.0.1":       "127.0.0.0/8",
		"192.0.2.1":       "192.0.2.0/24",
		"192.168.1.1":     "192.168.0.0/16",
		"255.255.255.255": "240.0.0.0/4",
		"::1":             "::1/128",
		"::":              "::/128",
		"2001:db8::1":     "2001:db8::/32",
		"fe80::1":         "fe80::/10",
		"fd00::1":         "fc00::/7",

		// Blocks sharing a cell, and blocks with a footnote.
		"192.0.0.170": "192.0.0.0/24",
		"192.0.0.1":   "192.0.0.0/24",
		"2001::1":     "2001::/23",

		// Blocks are reserved even if they are globally reachable.
		"192.175.48.1":         "192.175.48.0/24",
		"64:ff9b::808:808":     "64:ff9b::/96",
		"2620:4f:8000::1":      "2620:4f:8000::/48",
		"::ffff:192.0.2.1":     "::ffff:0.0.0.0/96",
		"::ffff:8.8.8.8":       "::ffff:0.0.0.0/96",
		"8.8.8.8":              "",
		"1.1.1.1":              "",
		"2606:4700:4700::1111": "",

		// Multicast is not in the special-purpose registries.
		"224.0.0.1": "",
		"ff02::1":   "",
	} {
		block, ok := ips.Find(netip.MustParseAddr(addr))
		if got := block.String(); ok != (want != "") || ok && got != want {
			t.Errorf("Find(%v) = %v, %v, want %q", addr, block, ok, want)
		}
	}

	const header = "Address Block,Name,RFC\n"
	for _, tt := range []struct{ ipv4, ipv6 string }{
		{"", string(ipv6)},
		{string(ipv4), ""},
		{header, string(ipv6)},
		{"Name,RFC\nLoopback,[RFC 1122]\n", string(ipv6)},
		{header + "localhost,Loopback,[RFC 1122]\n", string(ipv6)},
		{header + "127.0.0.1,Loopback,[RFC 1122]\n", string(ipv6)},
		{header + "127.0.0.1/8,Loopback,[RFC 1122]\n", string(ipv6)},
		{header + "\"127.0.0.0/8, \",Loopback,[RFC 1122]\n", string(ipv6)},
		{string(ipv6), string(ipv6)},
		{string(ipv4), string(ipv4)},
	} {
		if _, err := namelists.ParseReservedIPs([]byte(tt.ipv4), []byte(tt.ipv6)); err == nil {
			t.Errorf("ParseReservedIPs(%q, %q) succeeded", tt.ipv4, tt.ipv6)
		}
	}
}
