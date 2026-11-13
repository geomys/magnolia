package ca_test

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"geomys.org/magnolia/internal/acmetest"
	"geomys.org/magnolia/internal/ca"
	"geomys.org/magnolia/internal/namelists"
)

const directoryURL = "https://magnolia.test/acme/directory"

// newTestCA returns a fresh CA for a test, with a new issuer whose sequencer
// is running. It must be called inside a synctest bubble.
func newTestCA(t testing.TB) (http.Handler, string) {
	t.Helper()
	iss, _ := newTestIssuer(t)
	return newTestCAWithIssuer(t, iss), directoryURL
}

// newTestCAWithIssuer is like newTestCA, but with the given issuer.
func newTestCAWithIssuer(t testing.TB, iss *ca.Issuer) http.Handler {
	t.Helper()
	return newCA(t, iss).Handler()
}

// testNames returns lists with a few real top-level domains, public suffixes,
// and special-purpose address blocks, and the reserved .example.
func testNames(t testing.TB) *namelists.Lists {
	t.Helper()
	tlds, err := namelists.ParseTLDs([]byte("ARPA\nCK\nCOM\nEXAMPLE\nNET\nORG\nUK\n"))
	if err != nil {
		t.Fatal(err)
	}
	suffixes, err := namelists.ParsePublicSuffixes([]byte(`// ===BEGIN ICANN DOMAINS===
arpa
in-addr.arpa
*.ck
!www.ck
com
net
org
uk
co.uk
// ===END ICANN DOMAINS===
`))
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := namelists.ParseReservedIPs(
		[]byte("Address Block,Name\n10.0.0.0/8,Private-Use\n192.0.2.0/24,Documentation (TEST-NET-1)\n"),
		[]byte("Address Block,Name\n::1/128,Loopback Address\n::ffff:0:0/96,IPv4-mapped Address\n2001:db8::/32,Documentation\n"))
	if err != nil {
		t.Fatal(err)
	}
	return namelists.Static(tlds, suffixes, reserved)
}

// newCA returns a fresh CA with the given issuer. It must be called inside a
// synctest bubble.
func newCA(t testing.TB, iss *ca.Issuer) *ca.CA {
	t.Helper()
	return newCAWithConfig(t, iss, ca.Config{Names: testNames(t)})
}

// newCAWithConfig is like newCA, but with the Names and NoNameLimit of
// the given configuration.
func newCAWithConfig(t testing.TB, iss *ca.Issuer, config ca.Config) *ca.CA {
	t.Helper()
	accounts := filepath.Join(t.TempDir(), "accounts.db")
	if err := ca.CreateAccounts(accounts); err != nil {
		t.Fatal(err)
	}
	c, err := ca.New(ca.Config{
		WritePrefix: "https://magnolia.test/acme",
		NonceKey:    bytes.Repeat([]byte{42}, 32),
		Accounts:    accounts,
		Issuer:      iss,
		Names:       config.Names,

		NoNameLimit: config.NoNameLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	// Nonces minted in the same millisecond the CA started are rejected as
	// too old, and fake time only advances when everything is idle.
	time.Sleep(time.Millisecond)
	return c
}

// newTestClient returns a client for a fresh CA. It must be called inside a
// synctest bubble.
func newTestClient(t testing.TB) *acmetest.Client {
	t.Helper()
	h, dirURL := newTestCA(t)
	srv := httptest.NewTestServer(t, h)
	return acmetest.NewClient(t, srv.Client(), dirURL)
}

func TestScripts(t *testing.T) {
	acmetest.RunScripts(t, "testdata/scripts", newTestCA)
}

// TestOrderExpiry checks that orders are dropped from memory when they expire,
// which is not observable through ACME.
func TestOrderExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		iss, _ := newTestIssuer(t)
		c := newCA(t, iss)
		srv := httptest.NewTestServer(t, c.Handler())
		client := acmetest.NewClient(t, srv.Client(), directoryURL)

		readyOrder(t, client, "example.org")
		time.Sleep(2 * time.Hour)
		readyOrder(t, client, "example.com")
		if n := c.Orders(); n != 2 {
			t.Errorf("got %d orders before any expired, want 2", n)
		}
		time.Sleep(2 * time.Hour)
		if n := c.Orders(); n != 1 {
			t.Errorf("got %d orders after the first expired, want 1", n)
		}
		time.Sleep(2 * time.Hour)
		if n := c.Orders(); n != 0 {
			t.Errorf("got %d orders after both expired, want 0", n)
		}
	})
}

// TestNamesUnavailable checks that orders are refused when the lists needed to
// check their identifiers are not available, and only then.
func TestNamesUnavailable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		all := testNames(t)
		tlds, suffixes, err := all.DNS()
		if err != nil {
			t.Fatal(err)
		}
		reserved, err := all.IP()
		if err != nil {
			t.Fatal(err)
		}
		const dns, ip = `{"type":"dns","value":"example.org"}`, `{"type":"ip","value":"1.1.1.1"}`
		for _, tt := range []struct {
			name        string
			names       *namelists.Lists
			identifiers string
			want        string // in the detail of a 503, or empty for a 201
		}{
			{"no lists", namelists.Static(nil, nil, nil), dns, "list of top-level domains has not been fetched"},
			{"no lists", namelists.Static(nil, nil, nil), ip, "IPv4 special-purpose address registry has not been fetched"},
			{"no public suffixes", namelists.Static(tlds, nil, reserved), dns, "Public Suffix List has not been fetched"},
			{"no name lists", namelists.Static(nil, nil, reserved), ip, ""},
			{"no name lists", namelists.Static(nil, nil, reserved), ip + "," + dns, "list of top-level domains has not been fetched"},
			{"no address registries", namelists.Static(tlds, suffixes, nil), dns, ""},
			{"no address registries", namelists.Static(tlds, suffixes, nil), dns + "," + ip, "IPv4 special-purpose address registry has not been fetched"},
		} {
			iss, _ := newTestIssuer(t)
			c := newCAWithConfig(t, iss, ca.Config{Names: tt.names})
			srv := httptest.NewTestServer(t, c.Handler())
			client := acmetest.NewClient(t, srv.Client(), directoryURL)
			account := client.Key("account")
			resp := client.Do(&acmetest.Request{Method: "POST", URL: client.URL("newAccount"), Key: account, Payload: []byte(`{}`)})
			if resp.StatusCode != 201 {
				t.Fatalf("newAccount: %d %s", resp.StatusCode, resp.Body)
			}
			resp = client.Do(&acmetest.Request{Method: "POST", URL: client.URL("newOrder"), Key: account,
				Payload: []byte(`{"identifiers":[` + tt.identifiers + `]}`)})
			switch {
			case tt.want == "" && resp.StatusCode != 201:
				t.Errorf("%s: newOrder for %s: got %d %s, want 201", tt.name, tt.identifiers, resp.StatusCode, resp.Body)
			case tt.want != "" && (resp.StatusCode != 503 || resp.Problem == nil ||
				resp.Problem.Type != "urn:ietf:params:acme:error:serverInternal" || !strings.Contains(resp.Problem.Detail, tt.want)):
				t.Errorf("%s: newOrder for %s: got %d %s, want 503 serverInternal", tt.name, tt.identifiers, resp.StatusCode, resp.Body)
			}
		}
	})
}

// TestNoNameLimit checks that the limit on the number of identifiers
// can be disabled, without disabling the checks on each of them.
func TestNoNameLimit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		iss, _ := newTestIssuer(t)
		c := newCAWithConfig(t, iss, ca.Config{Names: testNames(t), NoNameLimit: true})
		srv := httptest.NewTestServer(t, c.Handler())
		client := acmetest.NewClient(t, srv.Client(), directoryURL)

		// Let's Encrypt certificates have up to 100 names.
		var names []string
		for i := range 100 {
			names = append(names, fmt.Sprintf("%d.example.org", i))
		}
		_, finalizeURL := readyOrder(t, client, names...)
		csr := client.CSR(client.Key("cert"), &x509.CertificateRequest{DNSNames: names})
		resp := finalize(client, finalizeURL, csr)
		if status, _ := resp.JSON.(map[string]any)["status"].(string); status != "valid" {
			t.Errorf("finalize with 100 names: got %d %s, want valid", resp.StatusCode, resp.Body)
		}

		names[50] = "example.local"
		var ids []string
		for _, n := range names {
			ids = append(ids, `{"type":"dns","value":"`+n+`"}`)
		}
		resp = client.Do(&acmetest.Request{Method: "POST", URL: client.URL("newOrder"), Key: client.Key("account"),
			Payload: []byte(`{"identifiers":[` + strings.Join(ids, ",") + `]}`)})
		if resp.Problem == nil || resp.Problem.Type != "urn:ietf:params:acme:error:rejectedIdentifier" {
			t.Errorf("newOrder with an invalid name: got %d %s, want rejectedIdentifier", resp.StatusCode, resp.Body)
		}
	})
}

// TestRequestSize checks the body limit without embedding large bodies in scripts.
func TestRequestSize(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newTestClient(t)
		for _, tt := range []struct {
			size, status int
		}{
			{1 << 16, 400}, // Within the limit, but not valid JWS.
			{1<<16 + 1, 413},
		} {
			resp := c.Do(&acmetest.Request{
				Method: "POST",
				URL:    c.URL("newAccount"),
				Body:   []byte(strings.Repeat(" ", tt.size)),
			})
			if resp.StatusCode != tt.status || resp.Problem == nil || resp.Problem.Type != "urn:ietf:params:acme:error:malformed" {
				t.Errorf("body of %d bytes: got %d %s, want %d malformed", tt.size, resp.StatusCode, resp.Body, tt.status)
			}
		}
	})
}

// TestKeyChangeInner covers malformed inner JWS in key change requests, which
// the script language can't express.
func TestKeyChangeInner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newTestClient(t)
		newAccount := c.URL("newAccount")
		keyChange := c.URL("keyChange")
		account := c.Key("account")
		resp := c.Do(&acmetest.Request{Method: "POST", URL: newAccount, Key: account, Payload: []byte(`{}`)})
		if resp.StatusCode != 201 {
			t.Fatalf("newAccount: %d %s", resp.StatusCode, resp.Body)
		}
		other := c.Key("other")
		resp = c.Do(&acmetest.Request{Method: "POST", URL: newAccount, Key: other, Payload: []byte(`{}`)})
		if resp.StatusCode != 201 {
			t.Fatalf("newAccount: %d %s", resp.StatusCode, resp.Body)
		}

		for _, tt := range []struct {
			name      string
			signer    *acmetest.Key
			protected string
			payload   string
			want      string
		}{
			{
				name:      "inner nonce",
				signer:    c.Key("new1"),
				protected: `{"alg":"ML-DSA-44","jwk":` + c.Key("new1").JWK() + `,"nonce":"x","url":"` + keyChange + `"}`,
				payload:   `{"account":"` + account.KID + `","oldKey":` + account.JWK() + `}`,
				want:      "urn:ietf:params:acme:error:malformed",
			},
			{
				name:      "inner url mismatch",
				signer:    c.Key("new2"),
				protected: `{"alg":"ML-DSA-44","jwk":` + c.Key("new2").JWK() + `,"url":"` + newAccount + `"}`,
				payload:   `{"account":"` + account.KID + `","oldKey":` + account.JWK() + `}`,
				want:      "urn:ietf:params:acme:error:malformed",
			},
			{
				name:      "inner with kid",
				signer:    account,
				protected: `{"alg":"ML-DSA-44","kid":"` + account.KID + `","url":"` + keyChange + `"}`,
				payload:   `{"account":"` + account.KID + `","oldKey":` + account.JWK() + `}`,
				want:      "urn:ietf:params:acme:error:malformed",
			},
			{
				name:      "account mismatch",
				signer:    c.Key("new3"),
				protected: `{"alg":"ML-DSA-44","jwk":` + c.Key("new3").JWK() + `,"url":"` + keyChange + `"}`,
				payload:   `{"account":"` + other.KID + `","oldKey":` + account.JWK() + `}`,
				want:      "urn:ietf:params:acme:error:unauthorized",
			},
			{
				name:      "old key mismatch",
				signer:    c.Key("new4"),
				protected: `{"alg":"ML-DSA-44","jwk":` + c.Key("new4").JWK() + `,"url":"` + keyChange + `"}`,
				payload:   `{"account":"` + account.KID + `","oldKey":` + other.JWK() + `}`,
				want:      "urn:ietf:params:acme:error:unauthorized",
			},
			{
				name:      "inner signed by the wrong key",
				signer:    c.Key("new6"),
				protected: `{"alg":"ML-DSA-44","jwk":` + c.Key("new5").JWK() + `,"url":"` + keyChange + `"}`,
				payload:   `{"account":"` + account.KID + `","oldKey":` + account.JWK() + `}`,
				want:      "urn:ietf:params:acme:error:unauthorized",
			},
			{
				name:      "inner payload not JSON",
				signer:    c.Key("new7"),
				protected: `{"alg":"ML-DSA-44","jwk":` + c.Key("new7").JWK() + `,"url":"` + keyChange + `"}`,
				payload:   `not json`,
				want:      "urn:ietf:params:acme:error:malformed",
			},
		} {
			// Subtests can't run inside a synctest bubble.
			inner := c.Sign(tt.signer, tt.protected, []byte(tt.payload))
			resp := c.Do(&acmetest.Request{Method: "POST", URL: keyChange, Key: account, Payload: inner})
			if resp.Problem == nil || resp.Problem.Type != tt.want {
				t.Errorf("%s: got %d %s, want %s", tt.name, resp.StatusCode, resp.Body, tt.want)
			}
		}

		// The account key is unchanged after all the failures.
		resp = c.Do(&acmetest.Request{Method: "POST", URL: account.KID, Key: account})
		if resp.StatusCode != 200 {
			t.Errorf("account key no longer works: %d %s", resp.StatusCode, resp.Body)
		}
	})
}

// TestAccountsDatabase checks that the CA only opens databases made by
// CreateAccounts.
func TestAccountsDatabase(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		iss, _ := newTestIssuer(t)
		dir := t.TempDir()
		newCA := func(accounts string) error {
			c, err := ca.New(ca.Config{
				WritePrefix: "https://magnolia.test/acme",
				NonceKey:    bytes.Repeat([]byte{42}, 32),
				Accounts:    accounts,
				Issuer:      iss,
				Names:       testNames(t),
			})
			if err == nil {
				c.Close()
			}
			return err
		}

		missing := filepath.Join(dir, "missing.db")
		if err := newCA(missing); err == nil {
			t.Error("CA opened a missing accounts database")
		}
		if _, err := os.Stat(missing); err == nil {
			t.Error("CA created the accounts database")
		}

		empty := filepath.Join(dir, "empty.db")
		if err := os.WriteFile(empty, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := newCA(empty); err == nil {
			t.Error("CA opened an accounts database without the accounts table")
		}

		created := filepath.Join(dir, "accounts.db")
		if err := ca.CreateAccounts(created); err != nil {
			t.Fatal(err)
		}
		if err := ca.CreateAccounts(created); !errors.Is(err, fs.ErrExist) {
			t.Errorf("CreateAccounts over existing file: got %v, want ErrExist", err)
		}
		if err := newCA(created); err != nil {
			t.Error(err)
		}
	})
}
