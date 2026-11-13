package ca_test

import (
	"bytes"
	"errors"
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

// newCA returns a fresh CA with the given issuer. It must be called inside a
// synctest bubble.
func newCA(t testing.TB, iss *ca.Issuer) *ca.CA {
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
