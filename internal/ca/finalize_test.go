package ca_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"net"
	"net/http/httptest"
	"path"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"geomys.org/magnolia/internal/acmetest"
	"geomys.org/magnolia/internal/lint"
	"geomys.org/magnolia/internal/lockstep"
	"geomys.org/magnolia/internal/mtc"
	"golang.org/x/crypto/cryptobyte"
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

// TestFinalizeFiles checks that the files written at issuance assemble into
// a valid standalone certificate.
func TestFinalizeFiles(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		iss, config := newTestIssuer(t)
		srv := httptest.NewTestServer(t, newTestCAWithIssuer(t, iss))
		logs := config.Logs
		priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			t.Fatal(err)
		}
		certKey := &acmetest.Key{Name: "cert", Priv: priv}

		// Issue four certificates concurrently, so they share a pool after the
		// null entry, covered by the subtrees [0, 4) and [4, 5), and the
		// inclusion proofs in the first are not empty. Each client has its
		// own account.
		names := []string{"a.example", "b.example", "c.example", "d.example"}
		finalizeURLs := make([]string, len(names))
		clients := make([]*acmetest.Client, len(names))
		for i, name := range names {
			clients[i] = acmetest.NewClient(t, srv.Client(), directoryURL)
			_, finalizeURLs[i] = readyOrder(t, clients[i], name, "www."+name)
		}
		certURLs := make([]string, len(names))
		done := make(chan struct{})
		for i, name := range names {
			go func() {
				csr := clients[i].CSR(certKey, &x509.CertificateRequest{DNSNames: []string{name, "www." + name}})
				resp := finalize(clients[i], finalizeURLs[i], csr)
				if resp.StatusCode != 200 {
					t.Errorf("finalize: %d %s", resp.StatusCode, resp.Body)
				}
				certURLs[i], _ = resp.JSON.(map[string]any)["certificate"].(string)
				done <- struct{}{}
			}()
		}
		for range names {
			<-done
		}
		var certURL, name string
		for i, u := range certURLs {
			if strings.Contains(u, "/2-") {
				certURL, name = u, names[i]
			}
		}
		if certURL == "" {
			t.Fatalf("no certificate with index 2: %q", certURLs)
		}

		rest, ok := strings.CutPrefix(certURL, testReadPrefix+"/certificate/1/")
		if !ok {
			t.Fatalf("certificate URL %s isn't under ReadPrefix %s", certURL, testReadPrefix)
		}
		date, file := path.Split(rest)
		indexString, token, ok := strings.Cut(file, "-")
		if !ok {
			t.Fatalf("certificate URL %s doesn't have a token", certURL)
		}
		if len(token) != 8 {
			t.Errorf("token %q is not 8 characters", token)
		}
		index, err := strconv.ParseInt(indexString, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		fetch := func(key string) []byte {
			t.Helper()
			b, err := logs.Backend.Fetch(t.Context(), key)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}

		tbs := fetch("certs/" + date + "tbs/002-" + token)
		// The standalone file followed by the subtrees file is an MTCProof.
		mtcProof := append(fetch("certs/"+date+"standalone/002-"+token), fetch("subtrees/000-4")...)
		s := cryptobyte.String(mtcProof)
		var extensions uint16
		var start, end uint64
		var proofHashes, sigs cryptobyte.String
		if !s.ReadUint16(&extensions) || !s.ReadUint48(&start) || !s.ReadUint48(&end) ||
			!s.ReadUint16LengthPrefixed(&proofHashes) || !s.ReadUint24LengthPrefixed(&sigs) || !s.Empty() {
			t.Fatal("malformed MTCProof")
		}
		if extensions != 0 {
			t.Errorf("got extensions %d, want 0", extensions)
		}
		proof := &mtc.Proof{Start: int64(start), End: int64(end)}
		for !proofHashes.Empty() {
			var h [32]byte
			if !proofHashes.CopyBytes(h[:]) {
				t.Fatal("malformed inclusion proof")
			}
			proof.InclusionProof = append(proof.InclusionProof, h)
		}
		if start != 0 || end != 4 || len(proof.InclusionProof) != 2 {
			t.Errorf("got subtree [%d, %d) and %d proof hashes, want [0, 4) and 2", start, end, len(proof.InclusionProof))
		}
		for !sigs.Empty() {
			var id, sig cryptobyte.String
			if !sigs.ReadUint8LengthPrefixed(&id) || !sigs.ReadUint16LengthPrefixed(&sig) {
				t.Fatal("malformed cosignature")
			}
			cosignerID, err := mtc.NewTrustAnchorID(id)
			if err != nil {
				t.Fatal(err)
			}
			proof.Cosignatures = append(proof.Cosignatures, mtc.Cosignature{CosignerID: cosignerID, Signature: sig})
		}

		der, err := mtc.Certificate(tbs, mtcProof)
		if err != nil {
			t.Fatal(err)
		}
		linter, err := lint.Standalone(lintCosigners(t, logs))
		if err != nil {
			t.Fatal(err)
		}
		if err := linter.Lint(der); err != nil {
			t.Error(err)
		}

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(cert.Signature, mtcProof) {
			t.Errorf("certificate signatureValue doesn't match the files")
		}
		if want := uint64(1<<48 | index); !cert.SerialNumber.IsUint64() || cert.SerialNumber.Uint64() != want {
			t.Errorf("serial number is %v, want %v", cert.SerialNumber, want)
		}
		if want := cert.NotAfter.UTC().Format(time.DateOnly) + "/"; date != want {
			t.Errorf("date directory is %s, want the notAfter date %s", date, want)
		}
		if got, want := strings.Join(cert.DNSNames, ","), name+",www."+name; got != want {
			t.Errorf("DNS names are %s, want %s", got, want)
		}
		if !certKey.Priv.PublicKey().Equal(cert.PublicKey) {
			t.Errorf("public key doesn't match the CSR")
		}
	})
}

func lintCosigners(t testing.TB, logs lockstep.Config) []lint.Cosigner {
	t.Helper()
	var cosigners []lint.Cosigner
	for _, v := range logs.IssuanceVerifiers {
		id, err := mtc.ParseTrustAnchorID(strings.TrimPrefix(v.Name(), "oid/1.3.6.1.4.1."))
		if err != nil {
			t.Fatal(err)
		}
		cosigners = append(cosigners, lint.Cosigner{ID: id, Key: v.PublicKey().(*mldsa.PublicKey)})
	}
	return cosigners
}
