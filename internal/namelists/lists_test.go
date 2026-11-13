package namelists_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"geomys.org/magnolia/internal/namelists"
)

const (
	tldsURL     = "data.iana.org/TLD/tlds-alpha-by-domain.txt"
	suffixesURL = "publicsuffix.org/list/public_suffix_list.dat"
	ipv4URL     = "www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv"
	ipv6URL     = "www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv"
)

// upstream is a fake of the servers the lists are fetched from.
type upstream struct {
	mu       sync.Mutex
	bodies   map[string][]byte // by host and path
	down     map[string]bool
	requests map[string]int
}

// newUpstream returns an upstream serving lists large enough to be plausible.
func newUpstream(t *testing.T) *upstream {
	return &upstream{
		bodies: map[string][]byte{
			tldsURL:     tldList(),
			suffixesURL: suffixList(),
			ipv4URL:     readTestdata(t, "iana-ipv4-special-registry-1.csv"),
			ipv6URL:     readTestdata(t, "iana-ipv6-special-registry-1.csv"),
		},
		down:     make(map[string]bool),
		requests: make(map[string]int),
	}
}

func tldList(extra ...string) []byte {
	var b strings.Builder
	b.WriteString("# Version 2000010100, Last Updated Sat Jan  1 00:00:00 2000 UTC\nCOM\nORG\nUK\n")
	for i := range 1000 {
		fmt.Fprintf(&b, "TLD%d\n", i)
	}
	for _, tld := range extra {
		b.WriteString(tld + "\n")
	}
	return []byte(b.String())
}

func suffixList(extra ...string) []byte {
	var b strings.Builder
	b.WriteString("// ===BEGIN ICANN DOMAINS===\ncom\norg\nuk\nco.uk\n")
	for i := range 5000 {
		fmt.Fprintf(&b, "suffix%d.com\n", i)
	}
	for _, suffix := range extra {
		b.WriteString(suffix + "\n")
	}
	b.WriteString("// ===END ICANN DOMAINS===\n")
	return []byte(b.String())
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	url := r.Host + r.URL.Path
	u.requests[url]++
	body, ok := u.bodies[url]
	switch {
	case !ok:
		http.NotFound(w, r)
	case u.down[url]:
		http.Error(w, "down for maintenance", http.StatusServiceUnavailable)
	default:
		w.Write(body)
	}
}

func (u *upstream) set(url string, body []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.bodies[url] = body
}

func (u *upstream) setDown(down bool, urls ...string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, url := range urls {
		u.down[url] = down
	}
}

func (u *upstream) count(url string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.requests[url]
}

// open returns the Lists cached in dir, refreshed from u until the test or
// the returned function ends them. It must be called inside a synctest bubble.
func open(t *testing.T, dir string, u *upstream) (lists *namelists.Lists, stop func()) {
	t.Helper()
	srv := httptest.NewTestServer(t, u)
	lists, err := namelists.Open(namelists.Config{Dir: dir, Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		lists.Run(ctx)
		close(done)
	}()
	stop = sync.OnceFunc(func() {
		cancel()
		<-done
	})
	t.Cleanup(stop)
	return lists, stop
}

func hasTLD(lists *namelists.Lists, tld string) bool {
	tlds, _, err := lists.DNS()
	return err == nil && tlds.Contains(tld)
}

func hasSuffix(lists *namelists.Lists, name string) bool {
	_, suffixes, err := lists.DNS()
	return err == nil && suffixes.Contains(name)
}

func isReserved(lists *namelists.Lists, addr string) bool {
	reserved, err := lists.IP()
	if err != nil {
		return false
	}
	_, ok := reserved.Find(netip.MustParseAddr(addr))
	return ok
}

func TestFetch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		u := newUpstream(t)
		srv := httptest.NewTestServer(t, u)
		dir := filepath.Join(t.TempDir(), "lists")
		lists, err := namelists.Open(namelists.Config{Dir: dir, Client: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}

		// Nothing is available before the first fetch.
		if _, _, err := lists.DNS(); err == nil || !strings.Contains(err.Error(), "not been fetched") {
			t.Errorf("DNS() before the first fetch: got %v", err)
		}
		if _, err := lists.IP(); err == nil || !strings.Contains(err.Error(), "not been fetched") {
			t.Errorf("IP() before the first fetch: got %v", err)
		}

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go lists.Run(ctx)
		synctest.Wait()

		if !hasTLD(lists, "com") || hasTLD(lists, "example") {
			t.Error("unexpected top-level domains after the first fetch")
		}
		if !hasSuffix(lists, "co.uk") || hasSuffix(lists, "example.com") {
			t.Error("unexpected public suffixes after the first fetch")
		}
		if !isReserved(lists, "10.0.0.1") || !isReserved(lists, "fd00::1") || isReserved(lists, "8.8.8.8") {
			t.Error("unexpected reserved IPs after the first fetch")
		}

		// The lists are cached verbatim.
		for url, file := range map[string]string{
			tldsURL: "tlds-alpha-by-domain.txt", suffixesURL: "public_suffix_list.dat",
			ipv4URL: "iana-ipv4-special-registry-1.csv", ipv6URL: "iana-ipv6-special-registry-1.csv",
		} {
			cached, err := os.ReadFile(filepath.Join(dir, file))
			if err != nil {
				t.Error(err)
			} else if !bytes.Equal(cached, u.bodies[url]) {
				t.Errorf("%s is not a copy of %s", file, url)
			}
		}

		// Each list is fetched again once a day.
		u.set(tldsURL, tldList("EXAMPLE"))
		u.set(suffixesURL, suffixList("example.com"))
		time.Sleep(23 * time.Hour)
		synctest.Wait()
		if hasTLD(lists, "example") || u.count(tldsURL) != 1 || u.count(ipv6URL) != 1 {
			t.Error("lists were fetched again within a day")
		}
		time.Sleep(time.Hour)
		synctest.Wait()
		if !hasTLD(lists, "example") || !hasSuffix(lists, "example.com") {
			t.Error("lists were not updated after a day")
		}
		for _, url := range []string{tldsURL, suffixesURL, ipv4URL, ipv6URL} {
			if n := u.count(url); n != 2 {
				t.Errorf("%s was fetched %d times in a day, want 2", url, n)
			}
		}
	})
}

func TestRedirects(t *testing.T) {
	for _, tt := range []struct {
		name          string
		scheme        string
		loop          bool
		customPolicy  bool
		reject        bool
		wantRequests  int
		wantCallbacks int
		wantAvailable bool
	}{
		{name: "HTTPS", scheme: "https", wantRequests: 1, wantAvailable: true},
		{name: "HTTP", scheme: "http"},
		{name: "redirect loop", scheme: "https", loop: true, wantRequests: 9},
		{name: "custom rejection", scheme: "https", customPolicy: true, reject: true, wantCallbacks: 1},
		{name: "custom acceptance", scheme: "https", customPolicy: true, wantRequests: 1, wantCallbacks: 1, wantAvailable: true},
		{name: "custom policy cannot allow HTTP", scheme: "http", customPolicy: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				u := newUpstream(t)
				requests, callbacks := 0, 0
				target := tt.scheme + "://redirect.example/list"
				srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.Host + r.URL.Path {
					case tldsURL:
						http.Redirect(w, r, target, http.StatusFound)
					case "redirect.example/list":
						requests++
						if tt.loop {
							http.Redirect(w, r, target, http.StatusFound)
						} else {
							w.Write(tldList())
						}
					default:
						u.ServeHTTP(w, r)
					}
				}))
				client := srv.Client()
				if tt.customPolicy {
					client.CheckRedirect = func(*http.Request, []*http.Request) error {
						callbacks++
						if tt.reject {
							return errors.New("redirect rejected by caller")
						}
						return nil
					}
				}
				lists, err := namelists.Open(namelists.Config{Dir: t.TempDir(), Client: client})
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				go lists.Run(ctx)
				synctest.Wait()
				if requests != tt.wantRequests || callbacks != tt.wantCallbacks {
					t.Errorf("got %d redirected requests and %d callbacks, want %d and %d",
						requests, callbacks, tt.wantRequests, tt.wantCallbacks)
				}
				if got := hasTLD(lists, "com"); got != tt.wantAvailable {
					t.Errorf("DNS lists available: got %v, want %v", got, tt.wantAvailable)
				}
				if !isReserved(lists, "10.0.0.1") {
					t.Error("redirect prevented other lists from being fetched")
				}
				// Open must not install its policy on the caller's client.
				if !tt.customPolicy && client.CheckRedirect != nil {
					t.Error("Open modified the caller's client")
				}
			})
		})
	}
}

func TestCache(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		u := newUpstream(t)
		dir := t.TempDir()
		lists, stop := open(t, dir, u)
		synctest.Wait()
		if !hasTLD(lists, "com") {
			t.Fatal("lists were not fetched")
		}
		stop()

		// The cached lists are available right away, without fetching them.
		time.Sleep(time.Hour)
		u.setDown(true, tldsURL, suffixesURL, ipv4URL, ipv6URL)
		lists, stop = open(t, dir, u)
		if !hasTLD(lists, "com") || !hasSuffix(lists, "co.uk") || !isReserved(lists, "10.0.0.1") {
			t.Error("cached lists are not available")
		}
		synctest.Wait()
		if n := u.count(tldsURL); n != 1 {
			t.Errorf("list was fetched %d times, want 1", n)
		}

		// If they can't be fetched, they are used for 30 days.
		time.Sleep(30*24*time.Hour - 2*time.Hour)
		synctest.Wait()
		if !hasTLD(lists, "com") || !isReserved(lists, "10.0.0.1") {
			t.Error("lists expired in less than 30 days")
		}
		time.Sleep(2 * time.Hour)
		synctest.Wait()
		if _, _, err := lists.DNS(); err == nil || !strings.Contains(err.Error(), "2000-01-01") {
			t.Errorf("DNS() after 30 days: got %v", err)
		}
		if _, err := lists.IP(); err == nil || !strings.Contains(err.Error(), "2000-01-01") {
			t.Errorf("IP() after 30 days: got %v", err)
		}
		stop()

		// The expired lists are still unavailable after a restart, until
		// they are fetched.
		lists, _ = open(t, dir, u)
		if _, _, err := lists.DNS(); err == nil {
			t.Error("expired lists are available after a restart")
		}
		u.setDown(false, tldsURL, suffixesURL)
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if !hasTLD(lists, "com") {
			t.Error("lists were not fetched after the servers came back")
		}

		// The name lists and the address registries are independent.
		if _, err := lists.IP(); err == nil {
			t.Error("address registries are available")
		}
		u.setDown(false, ipv4URL)
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if _, err := lists.IP(); err == nil {
			t.Error("address registries are available with only one of them")
		}
		u.setDown(false, ipv6URL)
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if !isReserved(lists, "10.0.0.1") {
			t.Error("address registries were not fetched after the servers came back")
		}
	})
}

func TestBadResponses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		u := newUpstream(t)
		dir := t.TempDir()
		lists, stop := open(t, dir, u)
		synctest.Wait()

		// Responses that don't look like the list they are supposed to be
		// don't replace it, in memory or on disk.
		ipv4, ipv6 := u.bodies[ipv4URL], u.bodies[ipv6URL]
		truncated := func(data []byte, before string) []byte {
			t.Helper()
			i := bytes.Index(data, []byte(before))
			if i < 0 {
				t.Fatalf("missing truncation point %q", before)
			}
			return data[:i]
		}
		const minimalIPv4 = "Address Block\n10.0.0.0/8\n127.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n240.0.0.0/4\n255.255.255.255/32\n"
		for _, tt := range []struct {
			name string
			url  string
			body []byte
		}{
			{"empty", tldsURL, nil},
			{"HTML", tldsURL, []byte("<html><body>Not here anymore.</body></html>\n")},
			{"too few top-level domains", tldsURL, []byte("COM\nORG\nEXAMPLE\n")},
			{"no com", tldsURL, bytes.ReplaceAll(tldList("EXAMPLE"), []byte("COM\n"), nil)},
			{"too large", tldsURL, append(tldList("EXAMPLE"), bytes.Repeat([]byte("#\n"), 4<<20+1)...)},
			{"truncated", suffixesURL, bytes.TrimSuffix(suffixList("example.com"), []byte("// ===END ICANN DOMAINS===\n"))},
			{"too few public suffixes", suffixesURL, []byte("// ===BEGIN ICANN DOMAINS===\ncom\nco.uk\nexample.com\n// ===END ICANN DOMAINS===\n")},
			{"other registry", ipv4URL, ipv6},
			{"other registry", ipv6URL, ipv4},
			{"missing blocks", ipv4URL, []byte("Address Block,Name\n192.0.2.0/24,Documentation\n")},
			{"truncated IPv4", ipv4URL, truncated(ipv4, "169.254.0.0/16")},
			{"missing final IPv4 block", ipv4URL, truncated(ipv4, "255.255.255.255/32")},
			{"missing final IPv6 block", ipv6URL, truncated(ipv6, "fe80::/10")},
			{"too few address blocks", ipv4URL, []byte(minimalIPv4)},
			{"duplicate address blocks", ipv4URL, []byte(minimalIPv4 + strings.Repeat("10.0.0.0/8\n", 20))},
		} {
			good := u.bodies[tt.url]
			u.set(tt.url, tt.body)
			time.Sleep(24 * time.Hour)
			synctest.Wait()
			if hasTLD(lists, "example") || hasSuffix(lists, "example.com") || !hasTLD(lists, "com") ||
				!hasSuffix(lists, "co.uk") || !isReserved(lists, "10.0.0.1") || !isReserved(lists, "fd00::1") ||
				!isReserved(lists, "192.168.1.1") || !isReserved(lists, "255.255.255.255") || !isReserved(lists, "fe80::1") {
				t.Errorf("%s: response replaced the list", tt.name)
			}
			_, file, _ := strings.CutLast(tt.url, "/")
			cached, err := os.ReadFile(filepath.Join(dir, file))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(cached, good) {
				t.Errorf("%s: response replaced the cached list", tt.name)
			}
			// A failed fetch is retried every five minutes.
			before := u.count(tt.url)
			time.Sleep(11 * time.Minute)
			synctest.Wait()
			if n := u.count(tt.url) - before; n < 2 || n > 3 {
				t.Errorf("%s: fetch was retried %d times in 11 minutes, want 2 or 3", tt.name, n)
			}
			u.set(tt.url, good)
			time.Sleep(5 * time.Minute)
			synctest.Wait()
		}
		stop()

		lists, stop = open(t, dir, u)
		if hasTLD(lists, "example") || !hasTLD(lists, "com") || !hasSuffix(lists, "co.uk") || !isReserved(lists, "10.0.0.1") {
			t.Error("bad responses were cached")
		}
		stop()

		// A cached list that is not valid is ignored, and fetched again.
		if err := os.WriteFile(filepath.Join(dir, "tlds-alpha-by-domain.txt"), []byte("COM\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		u.setDown(true, tldsURL)
		lists, _ = open(t, dir, u)
		if _, _, err := lists.DNS(); err == nil {
			t.Error("invalid cached list is available")
		}
		if !isReserved(lists, "10.0.0.1") {
			t.Error("address registries are not available")
		}
		u.setDown(false, tldsURL)
		time.Sleep(5 * time.Minute)
		synctest.Wait()
		if !hasTLD(lists, "com") {
			t.Error("invalid cached list was not fetched again")
		}
	})
}

func TestStatic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tlds, err := namelists.ParseTLDs([]byte("COM\n"))
		if err != nil {
			t.Fatal(err)
		}
		lists := namelists.Static(tlds, nil, nil)
		if _, _, err := lists.DNS(); err == nil {
			t.Error("DNS() succeeded without public suffixes")
		}
		if _, err := lists.IP(); err == nil {
			t.Error("IP() succeeded without address registries")
		}

		suffixes, err := namelists.ParsePublicSuffixes([]byte("// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n"))
		if err != nil {
			t.Fatal(err)
		}
		reserved, err := namelists.ParseReservedIPs(
			readTestdata(t, "iana-ipv4-special-registry-1.csv"), readTestdata(t, "iana-ipv6-special-registry-1.csv"))
		if err != nil {
			t.Fatal(err)
		}
		lists = namelists.Static(tlds, suffixes, reserved)
		time.Sleep(365 * 24 * time.Hour)
		if !hasTLD(lists, "com") || !hasSuffix(lists, "com") || !isReserved(lists, "10.0.0.1") {
			t.Error("static lists are not available")
		}
	})
}
