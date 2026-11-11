package ca_test

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"filippo.io/torchwood"
	"geomys.org/magnolia/internal/acmetest"
	"geomys.org/magnolia/internal/lint"
	"geomys.org/magnolia/internal/mtc"
	"geomys.org/magnolia/internal/readpath"
)

// readPathTest is a CA and the read path of its issuer, served by the same
// test server at their respective hosts.
type readPathTest struct {
	t      *testing.T
	dir    string // the local directory of the issuer
	rp     *readpath.ReadPath
	client *http.Client
	acme   *acmetest.Client
	lint   *lint.Linter

	caVerifier *torchwood.CosignatureVerifier
}

// newReadPathTest must be called inside a synctest bubble.
func newReadPathTest(t *testing.T) *readPathTest {
	t.Helper()
	dir := t.TempDir()
	config := newTestIssuerConfigIn(t, dir)
	iss := startTestIssuer(t, config)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	rp, err := readpath.New(readpath.Config{
		CAID:             testCAID,
		ReadPrefix:       testReadPrefix,
		WritePrefix:      "https://magnolia.test/acme",
		NonceKey:         bytes.Repeat([]byte{42}, 32),
		Files:            root.FS(),
		CAVerifier:       config.Logs.IssuanceVerifiers[0],
		EvidenceVerifier: config.Logs.EvidenceVerifiers[0],
		NotBefore:        time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("magnolia.test/", newTestCAWithIssuer(t, iss))
	mux.Handle("read.magnolia.test/", rp.Handler())
	srv := httptest.NewTestServer(t, mux)
	linter, err := lint.Standalone(lintCosigners(t, config.Logs))
	if err != nil {
		t.Fatal(err)
	}
	return &readPathTest{
		t: t, dir: dir, rp: rp, client: srv.Client(), lint: linter,
		caVerifier: config.Logs.IssuanceVerifiers[0],
		acme:       acmetest.NewClient(t, srv.Client(), directoryURL),
	}
}

// issue returns the certificate URL of a new certificate for names.
func (rt *readPathTest) issue(names ...string) string {
	rt.t.Helper()
	_, finalizeURL := readyOrder(rt.t, rt.acme, names...)
	csr := rt.acme.CSR(rt.acme.Key("cert"), &x509.CertificateRequest{DNSNames: names})
	resp := finalize(rt.acme, finalizeURL, csr)
	if resp.StatusCode != 200 {
		rt.t.Fatalf("finalize: %d %s", resp.StatusCode, resp.Body)
	}
	return resp.JSON.(map[string]any)["certificate"].(string)
}

// do sends a request with no body, and optional header name and value pairs.
func (rt *readPathTest) do(method, url string, header ...string) (*http.Response, []byte) {
	rt.t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		rt.t.Fatal(err)
	}
	for i := 0; i < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := rt.client.Do(req)
	if err != nil {
		rt.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		rt.t.Fatal(err)
	}
	return resp, body
}

// get is like do, but fails the test if the status is not want.
func (rt *readPathTest) get(want int, url string, header ...string) (*http.Response, []byte) {
	rt.t.Helper()
	resp, body := rt.do("GET", url, header...)
	if resp.StatusCode != want {
		rt.t.Fatalf("GET %s: got %d %s, want %d", url, resp.StatusCode, body, want)
	}
	return resp, body
}

func (rt *readPathTest) readFile(name string) []byte {
	rt.t.Helper()
	b, err := os.ReadFile(filepath.Join(rt.dir, filepath.FromSlash(name)))
	if err != nil {
		rt.t.Fatal(err)
	}
	return b
}

func (rt *readPathTest) writeFile(name string, data []byte) {
	rt.t.Helper()
	path := filepath.Join(rt.dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		rt.t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		rt.t.Fatal(err)
	}
}

// link returns the target of the Link header with the given relation.
func link(resp *http.Response, rel string) string {
	for _, l := range resp.Header.Values("Link") {
		if target, ok := strings.CutSuffix(l, `>;rel="`+rel+`"`); ok {
			return strings.TrimPrefix(target, "<")
		}
	}
	return ""
}

// decodeChain returns the contents of the PEM blocks of a response body, which
// must have the given types.
func decodeChain(t *testing.T, body []byte, types ...string) [][]byte {
	t.Helper()
	var blocks [][]byte
	for _, typ := range types {
		var b *pem.Block
		b, body = pem.Decode(body)
		if b == nil || b.Type != typ {
			t.Fatalf("expected a %s block", typ)
		}
		blocks = append(blocks, b.Bytes)
	}
	if len(body) != 0 {
		t.Fatalf("trailing data after the PEM blocks: %q", body)
	}
	return blocks
}

func TestReadPathCertificate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := newReadPathTest(t)
		certURL := rt.issue("example.org", "www.example.org")

		// The certificate URL is a capability, so it works with a plain GET.
		resp, body := rt.get(200, certURL)
		if ct := resp.Header.Get("Content-Type"); ct != "application/pem-certificate-chain" {
			t.Errorf("Content-Type is %q", ct)
		}
		if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
			t.Errorf("Cache-Control is %q", cc)
		}
		if resp.Header.Get("Replay-Nonce") != "" {
			t.Error("cacheable response has a Replay-Nonce")
		}
		if link(resp, "index") != directoryURL {
			t.Errorf("missing index link: %q", resp.Header.Values("Link"))
		}
		der := decodeChain(t, body, "CERTIFICATE")[0]
		if err := rt.lint.Lint(der); err != nil {
			t.Error(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(cert.DNSNames, ","); got != "example.org,www.example.org" {
			t.Errorf("DNS names are %s", got)
		}
		if !rt.acme.Key("cert").Priv.PublicKey().Equal(cert.PublicKey) {
			t.Error("public key doesn't match the CSR")
		}

		// The CA certificate is the issuer of the certificate.
		caResp, caBody := rt.get(200, testReadPrefix+"/ca.pem")
		if ct := caResp.Header.Get("Content-Type"); ct != "application/pem-certificate-chain" {
			t.Errorf("ca.pem Content-Type is %q", ct)
		}
		if cc := caResp.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
			t.Errorf("ca.pem Cache-Control is %q", cc)
		}
		caCert, err := x509.ParseCertificate(decodeChain(t, caBody, "CERTIFICATE")[0])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(caCert.RawSubject, cert.RawIssuer) {
			t.Error("CA certificate subject is not the certificate issuer")
		}
		if !bytes.Equal(caCert.SubjectKeyId, cert.AuthorityKeyId) {
			t.Error("CA certificate subject key identifier is not the certificate authority key identifier")
		}
		if !rt.caVerifier.PublicKey().(*mldsa.PublicKey).Equal(caCert.PublicKey) {
			t.Error("CA certificate key is not the CA cosigner key")
		}

		// POST-as-GET works like GET, without verifying the JWS, and returns a
		// nonce that the CA accepts.
		resp, postBody := rt.do("POST", certURL, "Content-Type", "application/jose+json")
		if resp.StatusCode != 200 || !bytes.Equal(postBody, body) {
			t.Errorf("POST: got %d and a different body than GET", resp.StatusCode)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("POST Cache-Control is %q", cc)
		}
		nonce := resp.Header.Get("Replay-Nonce")
		if nonce == "" {
			t.Fatal("POST response has no Replay-Nonce")
		}
		account := rt.acme.Key("account")
		if resp := rt.acme.Do(&acmetest.Request{Method: "POST", URL: account.KID, Key: account,
			Protected: map[string]string{"nonce": `"` + nonce + `"`}}); resp.StatusCode != 200 {
			t.Errorf("CA rejected the read path nonce: %d %s", resp.StatusCode, resp.Body)
		}

		// The properties are only included on request.
		caID := mtc.MustParseTrustAnchorID(testCAID)
		resp, body = rt.get(200, certURL, "Accept", "application/pem-certificate-chain-with-properties")
		if ct := resp.Header.Get("Content-Type"); ct != "application/pem-certificate-chain-with-properties" {
			t.Errorf("Content-Type is %q", ct)
		}
		blocks := decodeChain(t, body, "CERTIFICATE PROPERTIES", "CERTIFICATE")
		if want, _ := mtc.StandaloneProperties(caID); !bytes.Equal(blocks[0], want) {
			t.Errorf("properties are %x, want %x", blocks[0], want)
		}
		if !bytes.Equal(blocks[1], der) {
			t.Error("certificate with properties doesn't match")
		}

		// Other tokens, indexes, and dates don't exist.
		date := cert.NotAfter.UTC().Format(time.DateOnly)
		token := strings.TrimPrefix(certURL[strings.LastIndex(certURL, "/")+1:], "1-")
		prefix := testReadPrefix + "/certificate/1/"
		for _, u := range []string{
			prefix + date + "/1-AAAAAAAA",
			prefix + date + "/2-" + token,
			prefix + date + "/01-" + token,
			prefix + date + "/1-" + strings.ToLower(token),
			prefix + "2000-01-01/1-" + token,
			prefix + "tomorrow/1-" + token,
			prefix + date + "/tbs/001-" + token,
		} {
			resp, body := rt.do("GET", u)
			if resp.StatusCode != 404 {
				t.Errorf("GET %s: got %d %s, want 404", u, resp.StatusCode, body)
			}
		}
		resp, _ = rt.get(404, prefix+date+"/1-AAAAAAAA")
		if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
			t.Errorf("404 Content-Type is %q", ct)
		}
	})
}

func TestReadPathLogs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := newReadPathTest(t)
		certURL := rt.issue("example.org")
		token := certURL[strings.LastIndex(certURL, "-")+1:]

		for _, tt := range []struct {
			path, file  string
			contentType string
			immutable   bool
			gzip        bool
		}{
			{"/issuance/1/checkpoint", "issuance/checkpoint", "text/plain; charset=utf-8", false, false},
			{"/evidence/1/checkpoint", "evidence/checkpoint", "text/plain; charset=utf-8", false, false},
			{"/issuance/1/tile/0/000.p/2", "issuance/tile/0/000.p/2", "application/octet-stream", true, false},
			{"/evidence/1/tile/0/000.p/2", "evidence/tile/0/000.p/2", "application/octet-stream", true, false},
			{"/issuance/1/tile/entries/000.p/2", "issuance/tile/entries/000.p/2", "application/octet-stream", true, true},
			{"/evidence/1/tile/entries/000.p/2", "evidence/tile/entries/000.p/2", "application/octet-stream", true, true},
			{"/issuance/1/subtrees/001-2", "subtrees/001-2", "application/octet-stream", true, false},
		} {
			// Setting Accept-Encoding stops the client from decompressing.
			resp, body := rt.get(200, testReadPrefix+tt.path, "Accept-Encoding", "identity")
			if ct := resp.Header.Get("Content-Type"); ct != tt.contentType {
				t.Errorf("%s: Content-Type is %q, want %q", tt.path, ct, tt.contentType)
			}
			if cc := resp.Header.Get("Cache-Control"); strings.Contains(cc, "immutable") != tt.immutable || cc == "" {
				t.Errorf("%s: Cache-Control is %q", tt.path, cc)
			}
			if ce := resp.Header.Get("Content-Encoding"); (ce == "gzip") != tt.gzip {
				t.Errorf("%s: Content-Encoding is %q", tt.path, ce)
			}
			if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
				t.Errorf("%s: missing Access-Control-Allow-Origin", tt.path)
			}
			if !bytes.Equal(body, rt.readFile(tt.file)) {
				t.Errorf("%s: body doesn't match %s", tt.path, tt.file)
			}
		}

		// Only the documented URLs are served: no directories, no certificate
		// files, no staging bundles, and no other methods.
		date := certURL[len(testReadPrefix+"/certificate/1/"):][:len(time.DateOnly)]
		rt.readFile("certs/" + date + "/tbs/001-" + token)
		for _, path := range []string{
			"",
			"/",
			"/issuance",
			"/issuance/1",
			"/issuance/1/tile",
			"/issuance/1/tile/",
			"/issuance/1/tile/0",
			"/issuance/1/tile/entries",
			"/issuance/1/tile/0/001",
			"/issuance/1/tile/0%2F000.p%2F2%2F",
			"/issuance/1/subtrees",
			"/issuance/2/checkpoint",
			"/issuance/checkpoint",
			"/evidence/1/subtrees/001-2",
			"/certs/" + date + "/tbs/001-" + token,
			"/certificate/1/" + date,
			"/subtrees/001-2",
			"/staging",
		} {
			resp, body := rt.do("GET", testReadPrefix+path)
			if resp.StatusCode != 404 {
				t.Errorf("GET %s: got %d %s, want 404", path, resp.StatusCode, body)
			}
		}
		if resp, _ := rt.do("POST", testReadPrefix+"/issuance/1/checkpoint"); resp.StatusCode != 405 {
			t.Errorf("POST checkpoint: got %d, want 405", resp.StatusCode)
		}
		if resp, body := rt.do("HEAD", testReadPrefix+"/issuance/1/checkpoint"); resp.StatusCode != 200 || len(body) != 0 {
			t.Errorf("HEAD checkpoint: got %d and %d bytes", resp.StatusCode, len(body))
		}
	})
}

func TestReadPathHealth(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		rt := newReadPathTest(t)
		if err := rt.rp.CheckHealth(time.Minute); err != nil {
			t.Error(err)
		}
		// Empty pools are sequenced too, so the checkpoint stays fresh.
		time.Sleep(3 * testSequencingPeriod)
		synctest.Wait()
		if err := rt.rp.CheckHealth(testSequencingPeriod + time.Minute); err != nil {
			t.Error(err)
		}
		time.Sleep(10 * time.Second)
		if err := rt.rp.CheckHealth(5 * time.Second); err == nil {
			t.Error("stale checkpoint is healthy")
		}

		// Each checkpoint must be signed by its log.
		issuance, evidence := rt.readFile("issuance/checkpoint"), rt.readFile("evidence/checkpoint")
		rt.writeFile("issuance/checkpoint", evidence)
		if err := rt.rp.CheckHealth(testSequencingPeriod + time.Minute); err == nil || !strings.Contains(err.Error(), "issuance log") {
			t.Errorf("evidence checkpoint as the issuance checkpoint: got %v", err)
		}
		rt.writeFile("issuance/checkpoint", issuance)
		if err := rt.rp.CheckHealth(testSequencingPeriod + time.Minute); err != nil {
			t.Error(err)
		}
		rt.writeFile("evidence/checkpoint", issuance)
		if err := rt.rp.CheckHealth(testSequencingPeriod + time.Minute); err == nil || !strings.Contains(err.Error(), "evidence log") {
			t.Errorf("issuance checkpoint as the evidence checkpoint: got %v", err)
		}
	})
}
