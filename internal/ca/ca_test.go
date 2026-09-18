package ca_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"geomys.org/magnolia/internal/acmetest"
	"geomys.org/magnolia/internal/ca"
)

const directoryURL = "https://magnolia.test/acme/directory"

// newTestCA returns a fresh CA for a test. It must be called inside a
// synctest bubble.
func newTestCA(t testing.TB) (http.Handler, string) {
	t.Helper()
	c, err := ca.New(ca.Config{
		WritePrefix: "https://magnolia.test/acme",
		NonceKey:    bytes.Repeat([]byte{42}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Nonces minted in the same millisecond the CA started are rejected as
	// too old, and fake time only advances when everything is idle.
	time.Sleep(time.Millisecond)
	return c.Handler(), directoryURL
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
