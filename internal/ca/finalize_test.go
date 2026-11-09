package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"

	"geomys.org/magnolia/internal/acmetest"
)

// readyOrder creates an account if needed and a ready order for names, and
// returns the order and finalize URLs.
func readyOrder(t testing.TB, c *acmetest.Client, names ...string) (orderURL, finalizeURL string) {
	t.Helper()
	account := c.Key("account")
	if account.KID == "" {
		resp := c.Do(&acmetest.Request{Method: "POST", URL: c.URL("newAccount"), Key: account, Payload: []byte(`{}`)})
		if resp.StatusCode != 201 {
			t.Fatalf("newAccount: %d %s", resp.StatusCode, resp.Body)
		}
	}
	var ids []string
	for _, n := range names {
		ids = append(ids, `{"type":"dns","value":"`+n+`"}`)
	}
	resp := c.Do(&acmetest.Request{Method: "POST", URL: c.URL("newOrder"), Key: account,
		Payload: []byte(`{"identifiers":[` + strings.Join(ids, ",") + `]}`)})
	if resp.StatusCode != 201 {
		t.Fatalf("newOrder: %d %s", resp.StatusCode, resp.Body)
	}
	obj := resp.JSON.(map[string]any)
	for _, authz := range obj["authorizations"].([]any) {
		resp := c.Do(&acmetest.Request{Method: "POST", URL: authz.(string), Key: account})
		chall := resp.JSON.(map[string]any)["challenges"].([]any)[0].(map[string]any)["url"].(string)
		resp = c.Do(&acmetest.Request{Method: "POST", URL: chall, Key: account, Payload: []byte(`{}`)})
		if resp.StatusCode != 200 {
			t.Fatalf("challenge: %d %s", resp.StatusCode, resp.Body)
		}
	}
	return resp.Header.Get("Location"), obj["finalize"].(string)
}

func finalize(c *acmetest.Client, finalizeURL, csr string) *acmetest.Response {
	return c.Do(&acmetest.Request{Method: "POST", URL: finalizeURL, Key: c.Key("account"),
		Payload: []byte(`{"csr":"` + csr + `"}`)})
}

func encodeCSR(t testing.TB, template *x509.CertificateRequest, key any) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

// TestFinalizeCSR covers CSRs that the script language can't express.
func TestFinalizeCSR(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newTestClient(t)
		orderURL, finalizeURL := readyOrder(t, c, "example.org", "www.example.org")
		names := []string{"example.org", "www.example.org"}
		certKey := c.Key("cert").Priv
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		goodCSR := encodeCSR(t, &x509.CertificateRequest{DNSNames: names}, certKey)
		badSig, err := base64.RawURLEncoding.DecodeString(encodeCSR(t, &x509.CertificateRequest{DNSNames: names}, certKey))
		if err != nil {
			t.Fatal(err)
		}
		badSig[len(badSig)-1] ^= 1

		for _, tt := range []struct {
			name string
			csr  string
		}{
			{"invalid signature", base64.RawURLEncoding.EncodeToString(badSig)},
			{"ECDSA key", encodeCSR(t, &x509.CertificateRequest{DNSNames: names}, ecKey)},
			{"common name not in SANs", encodeCSR(t, &x509.CertificateRequest{DNSNames: names,
				Subject: pkix.Name{CommonName: "other.example.org"}}, certKey)},
			{"IP address", encodeCSR(t, &x509.CertificateRequest{DNSNames: names,
				IPAddresses: []net.IP{net.ParseIP("192.0.2.1")}}, certKey)},
			{"email address", encodeCSR(t, &x509.CertificateRequest{DNSNames: names,
				EmailAddresses: []string{"admin@example.org"}}, certKey)},
			{"padded base64url", encodeCSR(t, &x509.CertificateRequest{DNSNames: names}, certKey) + "="},
			// These are JSON escapes, so the decoded CSR contains CR and LF.
			{"base64url with LF", goodCSR[:40] + `\n` + goodCSR[40:]},
			{"base64url with trailing CRLF", goodCSR + `\r\n`},
		} {
			// Subtests can't run inside a synctest bubble.
			resp := finalize(c, finalizeURL, tt.csr)
			if resp.Problem == nil || resp.Problem.Type != "urn:ietf:params:acme:error:badCSR" {
				t.Errorf("%s: got %d %s, want badCSR", tt.name, resp.StatusCode, resp.Body)
			}
		}

		resp := c.Do(&acmetest.Request{Method: "POST", URL: orderURL, Key: c.Key("account")})
		if status := resp.JSON.(map[string]any)["status"]; status != "ready" {
			t.Fatalf("order is %v after bad CSRs, want ready", status)
		}

		// A common name is allowed if it's one of the DNS names, which may
		// also be repeated.
		resp = finalize(c, finalizeURL, encodeCSR(t, &x509.CertificateRequest{
			Subject:  pkix.Name{CommonName: "example.org"},
			DNSNames: []string{"www.example.org", "example.org", "www.example.org"},
		}, certKey))
		if status := resp.JSON.(map[string]any)["status"]; status != "valid" {
			t.Errorf("got %d %s, want valid", resp.StatusCode, resp.Body)
		}
	})
}

// TestFinalizeConcurrent checks that an order is processing while it's being
// finalized, and that it can't be finalized twice at the same time.
func TestFinalizeConcurrent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h, _ := newTestCA(t)
		srv := httptest.NewTestServer(t, h)
		c := acmetest.NewClient(t, srv.Client(), directoryURL)
		orderURL, finalizeURL := readyOrder(t, c, "example.org")
		csr := c.CSR(c.Key("cert"), &x509.CertificateRequest{DNSNames: []string{"example.org"}})

		// A second client, for the same account, to make requests while the
		// first one is waiting.
		c2 := acmetest.NewClient(t, srv.Client(), directoryURL)
		c2.Keys()["account"] = c.Key("account")

		done := make(chan *acmetest.Response)
		go func() { done <- finalize(c, finalizeURL, csr) }()
		synctest.Wait()

		resp := c2.Do(&acmetest.Request{Method: "POST", URL: orderURL, Key: c2.Key("account")})
		if status := resp.JSON.(map[string]any)["status"]; status != "processing" {
			t.Errorf("order is %v while finalizing, want processing", status)
		}
		resp = finalize(c2, finalizeURL, csr)
		if resp.Problem == nil || resp.Problem.Type != "urn:ietf:params:acme:error:orderNotReady" {
			t.Errorf("concurrent finalize: got %d %s, want orderNotReady", resp.StatusCode, resp.Body)
		}

		resp = <-done
		if status := resp.JSON.(map[string]any)["status"]; status != "valid" {
			t.Errorf("finalize: got %d %s, want valid", resp.StatusCode, resp.Body)
		}
		resp = c2.Do(&acmetest.Request{Method: "POST", URL: orderURL, Key: c2.Key("account")})
		if status := resp.JSON.(map[string]any)["status"]; status != "valid" {
			t.Errorf("order is %v after finalizing, want valid", status)
		}
	})
}
