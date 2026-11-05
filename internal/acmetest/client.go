// Package acmetest is a test harness for ACME servers.
//
// It provides an ML-DSA ACME client that signs requests, tracks nonces and
// account bindings, and checks protocol invariants on every response, along
// with a declarative script language built on it (see [RunScripts]).
package acmetest

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// Key is an account key, optionally bound to an account URL.
type Key struct {
	Name string
	Priv *mldsa.PrivateKey
	// KID is the account URL the key is bound to, or empty.
	KID string
}

// Alg returns the JWS "alg" value for the key.
func (k *Key) Alg() string { return k.Priv.PublicKey().Parameters().String() }

// JWK returns the public JWK of the key, as JSON.
func (k *Key) JWK() string {
	return `{"kty":"AKP","alg":"` + k.Alg() + `","pub":"` +
		base64.RawURLEncoding.EncodeToString(k.Priv.PublicKey().Bytes()) + `"}`
}

// NonceMode selects how the "nonce" header parameter is chosen.
type NonceMode int

const (
	// NonceFresh uses the most recent Replay-Nonce, fetching one if needed.
	NonceFresh NonceMode = iota
	// NonceReuse repeats the nonce spent by the previous signed request.
	NonceReuse
	// NonceInvalid sends a well-formed nonce the server did not issue.
	NonceInvalid
	// NonceMissing omits the header parameter.
	NonceMissing
)

// EmbedMode selects between "kid" and "jwk" in the protected header.
type EmbedMode int

const (
	// EmbedDefault uses "jwk" for newAccount, "kid" if the key is bound, and
	// "jwk" otherwise for revokeCert. Any other target requires a bound key.
	EmbedDefault EmbedMode = iota
	EmbedJWK
	EmbedKID
)

// Request is a request to the ACME server.
type Request struct {
	Method string // GET, HEAD, or POST
	URL    string
	Header http.Header

	// Key signs POST requests. A nil Key with a POST method sends Body raw.
	Key *Key
	// Payload is the JWS payload. Empty means POST-as-GET.
	Payload []byte
	// Body, if set, is sent as-is instead of a signed JWS.
	Body []byte

	// Signing overrides, for negative tests.
	Nonce   NonceMode
	Embed   EmbedMode
	SignKey *Key // signs instead of Key, which still decides the header (including the JWK)
	// Protected maps header parameter names to raw JSON values that replace
	// the computed ones, or are added.
	Protected map[string]string
}

// Response is a response from the ACME server.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	// JSON is the decoded body, if it is JSON.
	JSON any
	// Problem is the decoded problem document, if the response is one.
	Problem *Problem
}

// Problem is an RFC 7807 problem document.
type Problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
}

// Exchange is a request and its response, as recorded in the transcript.
type Exchange struct {
	Request *Request
	// Protected and Payload are the decoded JWS members, for signed requests.
	Protected string
	Payload   string
	Response  *Response
}

// Client is an ACME client that reports protocol violations to a testing.TB.
type Client struct {
	t          testing.TB
	hc         *http.Client
	dirURL     string
	dir        map[string]any
	keys       map[string]*Key
	nonce      string // most recent Replay-Nonce not yet spent
	lastNonce  string // nonce sent by the previous signed request
	seenNonces map[string]bool
	transcript []*Exchange
	// where is a location prefix for fatal errors, set by the script runner.
	where string
}

// fatalf fails the test with a message prefixed by the current location.
func (c *Client) fatalf(format string, args ...any) {
	c.t.Helper()
	if c.where != "" {
		format = c.where + ": " + format
	}
	c.t.Fatalf(format, args...)
}

// NewClient returns a Client that talks to the server at dirURL through hc.
func NewClient(t testing.TB, hc *http.Client, dirURL string) *Client {
	return &Client{
		t:          t,
		hc:         hc,
		dirURL:     dirURL,
		keys:       make(map[string]*Key),
		seenNonces: make(map[string]bool),
	}
}

// Key returns the named key, generating an ML-DSA-44 key on first use.
func (c *Client) Key(name string) *Key {
	if k, ok := c.keys[name]; ok {
		return k
	}
	return c.NewKey(name, mldsa.MLDSA44())
}

// NewKey generates and registers a key with the given parameters.
// It fails the test if the name is already in use.
func (c *Client) NewKey(name string, params mldsa.Parameters) *Key {
	c.t.Helper()
	if _, ok := c.keys[name]; ok {
		c.fatalf("key %q already exists", name)
	}
	priv, err := mldsa.GenerateKey(params)
	if err != nil {
		c.t.Fatal(err)
	}
	k := &Key{Name: name, Priv: priv}
	c.keys[name] = k
	return k
}

// Keys returns all keys created so far.
func (c *Client) Keys() map[string]*Key { return c.keys }

// Directory returns the directory object, fetching it on first use.
func (c *Client) Directory() map[string]any {
	c.t.Helper()
	if c.dir == nil {
		resp := c.Do(&Request{Method: "GET", URL: c.dirURL})
		dir, ok := resp.JSON.(map[string]any)
		if resp.StatusCode != 200 || !ok {
			c.t.Fatalf("fetching directory: status %d, body %s", resp.StatusCode, resp.Body)
		}
		c.dir = dir
	}
	return c.dir
}

// DirectoryURL returns the URL of the directory.
func (c *Client) DirectoryURL() string { return c.dirURL }

// URL returns the URL of a directory field, failing the test if it is
// missing.
func (c *Client) URL(field string) string {
	c.t.Helper()
	u, ok := c.Directory()[field].(string)
	if !ok {
		c.fatalf("directory has no %q field", field)
	}
	return u
}

// lookup returns the directory URL for name without fetching the directory,
// or "" if it is not known yet.
func (c *Client) lookup(name string) string {
	if c.dir == nil {
		return ""
	}
	u, _ := c.dir[name].(string)
	return u
}

// Transcript returns all exchanges so far, oldest first.
func (c *Client) Transcript() []*Exchange { return c.transcript }

// Nonce returns a nonce, fetching a fresh one from newNonce if none is
// available. The nonce is consumed.
func (c *Client) Nonce() string {
	c.t.Helper()
	if c.nonce == "" {
		resp := c.Do(&Request{Method: "HEAD", URL: c.URL("newNonce")})
		if resp.StatusCode != 200 || c.nonce == "" {
			c.t.Fatalf("fetching nonce: status %d, Replay-Nonce %q", resp.StatusCode, c.nonce)
		}
	}
	n := c.nonce
	c.nonce = ""
	return n
}

// Sign returns the Flattened JSON Serialization of payload signed by key
// with the given protected header.
func (c *Client) Sign(key *Key, protected string, payload []byte) []byte {
	c.t.Helper()
	p := base64.RawURLEncoding.EncodeToString([]byte(protected))
	pl := base64.RawURLEncoding.EncodeToString(payload)
	sig, err := key.Priv.Sign(rand.Reader, []byte(p+"."+pl), nil)
	if err != nil {
		c.t.Fatal(err)
	}
	return []byte(`{"protected":"` + p + `","payload":"` + pl + `","signature":"` +
		base64.RawURLEncoding.EncodeToString(sig) + `"}`)
}

// Do sends the request, records the exchange, checks the invariants, and
// returns the response. Transport failures fail the test.
func (c *Client) Do(req *Request) *Response {
	c.t.Helper()
	ex := &Exchange{Request: req}
	var body []byte
	switch {
	case req.Body != nil:
		body = req.Body
	case req.Method == "POST" && req.Key != nil:
		body = c.sign(req, ex)
	case req.Method == "POST":
		c.fatalf("POST %s: no key and no raw body", req.URL)
	}

	r, err := http.NewRequest(req.Method, req.URL, bytes.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	if req.Method == "POST" {
		r.Header.Set("Content-Type", "application/jose+json")
	}
	for k, vs := range req.Header {
		r.Header.Del(k)
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	hr, err := c.hc.Do(r)
	if err != nil {
		c.fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer hr.Body.Close()
	respBody, err := io.ReadAll(hr.Body)
	if err != nil {
		c.fatalf("%s %s: reading body: %v", req.Method, req.URL, err)
	}
	resp := &Response{StatusCode: hr.StatusCode, Header: hr.Header, Body: respBody}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(hr.Header.Get("Content-Type"), ";")[0]))
	if req.Method != "HEAD" && (mediaType == "application/json" || mediaType == "application/problem+json") {
		if err := json.Unmarshal(respBody, &resp.JSON); err != nil {
			c.t.Errorf("%s %s: body is not valid JSON: %v", req.Method, req.URL, err)
		}
		if mediaType == "application/problem+json" {
			resp.Problem = new(Problem)
			json.Unmarshal(respBody, resp.Problem)
		}
	}
	ex.Response = resp
	c.transcript = append(c.transcript, ex)

	if n := hr.Header.Get("Replay-Nonce"); n != "" {
		c.nonce = n
	}
	if req.Method == "POST" && req.Key != nil && resp.StatusCode/100 == 2 {
		if u := c.lookup("newAccount"); u != "" && req.URL == u {
			if loc := hr.Header.Get("Location"); loc != "" {
				req.Key.KID = loc
			}
		}
	}
	c.checkInvariants(ex)
	return resp
}

// Inner returns a JWS suitable as the payload of a keyChange request (RFC
// 8555, Section 7.3.5): signed by key with its JWK embedded, "url" set to url,
// and no nonce.
func (c *Client) Inner(key *Key, url string, payload []byte) []byte {
	c.t.Helper()
	protected := `{"alg":` + quote(key.Alg()) + `,"jwk":` + key.JWK() + `,"url":` + quote(url) + `}`
	return c.Sign(key, protected, payload)
}

// sign builds the signed body for req, and records the decoded members in ex.
func (c *Client) sign(req *Request, ex *Exchange) []byte {
	c.t.Helper()
	signKey := req.Key
	if req.SignKey != nil {
		signKey = req.SignKey
	}
	embed := req.Embed
	if embed == EmbedDefault {
		dir := c.Directory()
		switch {
		case req.URL == dir["newAccount"]:
			embed = EmbedJWK
		case req.Key.KID != "":
			embed = EmbedKID
		case req.URL == dir["revokeCert"]:
			embed = EmbedJWK
		default:
			c.fatalf("POST %s: key %q is not bound to an account", req.URL, req.Key.Name)
		}
	}

	type param struct{ name, value string } // value is raw JSON
	params := []param{{"alg", quote(req.Key.Alg())}}
	switch embed {
	case EmbedJWK:
		params = append(params, param{"jwk", req.Key.JWK()})
	case EmbedKID:
		if _, overridden := req.Protected["kid"]; req.Key.KID == "" && !overridden {
			c.fatalf("POST %s: key %q is not bound to an account", req.URL, req.Key.Name)
		}
		params = append(params, param{"kid", quote(req.Key.KID)})
	}
	switch req.Nonce {
	case NonceFresh:
		n := c.Nonce()
		c.lastNonce = n
		params = append(params, param{"nonce", quote(n)})
	case NonceReuse:
		if c.lastNonce == "" {
			c.fatalf("POST %s: no previous nonce to reuse", req.URL)
		}
		params = append(params, param{"nonce", quote(c.lastNonce)})
	case NonceInvalid:
		var b [24]byte
		rand.Read(b[:])
		params = append(params, param{"nonce", quote(base64.RawURLEncoding.EncodeToString(b[:]))})
	case NonceMissing:
	}
	params = append(params, param{"url", quote(req.URL)})
	for _, name := range slices.Sorted(maps.Keys(req.Protected)) {
		i := slices.IndexFunc(params, func(p param) bool { return p.name == name })
		if i < 0 {
			params = append(params, param{name, req.Protected[name]})
		} else {
			params[i].value = req.Protected[name]
		}
	}

	var h strings.Builder
	for i, p := range params {
		if i > 0 {
			h.WriteString(",")
		}
		fmt.Fprintf(&h, "%s:%s", quote(p.name), p.value)
	}
	ex.Protected = "{" + h.String() + "}"
	ex.Payload = string(req.Payload)
	return c.Sign(signKey, ex.Protected, req.Payload)
}
func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

var base64URL = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// checkInvariants reports every way the response violates the protocol
// properties that are expected of all responses, independently of the request.
func (c *Client) checkInvariants(ex *Exchange) {
	c.t.Helper()
	req, resp := ex.Request, ex.Response
	var violations []string
	fail := func(format string, args ...any) {
		violations = append(violations, fmt.Sprintf(format, args...))
	}
	defer func() {
		if len(violations) > 0 {
			c.t.Errorf("invariants violated:\n\t%s\n%s", strings.Join(violations, "\n\t"), c.dump(ex))
		}
	}()

	nonce := resp.Header.Get("Replay-Nonce")
	switch {
	case nonce == "":
		fail("missing Replay-Nonce")
	case !base64URL.MatchString(nonce):
		fail("Replay-Nonce %q is not base64url", nonce)
	case c.seenNonces[nonce]:
		fail("Replay-Nonce %q was already issued", nonce)
	}
	c.seenNonces[nonce] = true

	if req.URL != c.dirURL {
		want := `<` + c.dirURL + `>;rel="index"`
		found := false
		for _, l := range resp.Header.Values("Link") {
			for v := range strings.SplitSeq(l, ",") {
				if strings.ReplaceAll(strings.TrimSpace(v), " ", "") == want {
					found = true
				}
			}
		}
		if !found {
			fail("missing Link %s", want)
		}
	}

	if req.Method == "HEAD" && len(resp.Body) != 0 {
		fail("HEAD response has a body")
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	switch {
	case resp.StatusCode >= 400:
		if mediaType != "application/problem+json" {
			fail("error response Content-Type is %q", resp.Header.Get("Content-Type"))
			break
		}
		if req.Method == "HEAD" {
			break
		}
		obj, _ := resp.JSON.(map[string]any)
		typ, _ := obj["type"].(string)
		detail, _ := obj["detail"].(string)
		switch {
		case obj == nil:
			fail("problem document is not a JSON object")
		case !strings.HasPrefix(typ, "urn:ietf:params:acme:error:") && !strings.HasPrefix(typ, "https://"):
			fail("problem type %q is not an ACME error", typ)
		case detail == "":
			fail("problem document has no detail")
		}
	case resp.StatusCode/100 == 2:
		if resp.StatusCode == 204 && len(resp.Body) != 0 {
			fail("204 response has a body")
		}
		if len(resp.Body) != 0 && mediaType != "application/json" {
			fail("Content-Type is %q", resp.Header.Get("Content-Type"))
		}
		if len(resp.Body) != 0 {
			if _, ok := resp.JSON.(map[string]any); !ok {
				fail("body is not a JSON object")
			}
		}
		if resp.StatusCode == 201 {
			if loc, err := url.Parse(resp.Header.Get("Location")); err != nil || loc.Scheme != "https" {
				fail("201 response Location %q is not an absolute https URL", resp.Header.Get("Location"))
			}
		}
	}

	if u := c.lookup("newNonce"); u != "" && req.URL == u {
		if resp.Header.Get("Cache-Control") != "no-store" {
			fail("newNonce Cache-Control is %q, want no-store", resp.Header.Get("Cache-Control"))
		}
		if req.Method == "HEAD" && resp.StatusCode != 200 {
			fail("HEAD newNonce status %d, want 200", resp.StatusCode)
		}
		if req.Method == "GET" && resp.StatusCode != 204 {
			fail("GET newNonce status %d, want 204", resp.StatusCode)
		}
	}

	if resp.StatusCode/100 == 2 {
		checkTimestamps("", resp.JSON, fail)
	}

	if resp.StatusCode/100 == 2 && req.Method == "POST" && c.isAccountURL(req.URL) {
		obj, _ := resp.JSON.(map[string]any)
		switch status, _ := obj["status"].(string); status {
		case "valid", "deactivated", "revoked":
		default:
			fail("account status %q is not valid, deactivated, or revoked", status)
		}
	}
}

// timestampFields are the JSON members that ACME defines as RFC 3339
// timestamps: expires, notBefore, notAfter, and validated from RFC 8555, and
// the start and end of suggestedWindow from RFC 9773. The other extensions
// (RFC 8737, RFC 8738, dns-persist-01) define no timestamp members.
var timestampFields = map[string]bool{
	"expires": true, "validated": true, "notBefore": true, "notAfter": true,
	"start": true, "end": true,
}

// checkTimestamps walks a JSON value and reports every timestamp member that
// is not an RFC 3339 string in UTC with whole seconds. RFC 8555 only requires
// RFC 3339, but all its examples use the Z suffix, and a single fixed form
// keeps clients simple.
func checkTimestamps(path string, v any, fail func(string, ...any)) {
	switch v := v.(type) {
	case map[string]any:
		for k, vv := range v {
			p := path + "." + k
			if timestampFields[k] {
				s, ok := vv.(string)
				if !ok {
					fail("%s is not a string", p)
					continue
				}
				if t, err := time.Parse(time.RFC3339, s); err != nil || t.UTC().Format(time.RFC3339) != s {
					fail("%s = %q is not an RFC 3339 UTC timestamp with whole seconds", p, s)
				}
				continue
			}
			checkTimestamps(p, vv, fail)
		}
	case []any:
		for i, vv := range v {
			checkTimestamps(fmt.Sprintf("%s[%d]", path, i), vv, fail)
		}
	}
}

// isAccountURL reports whether u is the newAccount URL or a bound account URL.
func (c *Client) isAccountURL(u string) bool {
	if n := c.lookup("newAccount"); n != "" && n == u {
		return true
	}
	for _, k := range c.keys {
		if k.KID != "" && k.KID == u {
			return true
		}
	}
	return false
}

// dump renders an exchange for a failure message.
func (c *Client) dump(ex *Exchange) string {
	var b strings.Builder
	req := ex.Request
	fmt.Fprintf(&b, "> %s %s", req.Method, req.URL)
	if req.Key != nil {
		fmt.Fprintf(&b, " as %s", req.Key.Name)
	}
	b.WriteString("\n")
	for k, vs := range req.Header {
		for _, v := range vs {
			fmt.Fprintf(&b, "> %s: %s\n", k, v)
		}
	}
	if ex.Protected != "" {
		fmt.Fprintf(&b, "> protected: %s\n", ex.Protected)
		fmt.Fprintf(&b, "> payload: %s\n", ex.Payload)
	} else if req.Body != nil {
		fmt.Fprintf(&b, "> body: %s\n", req.Body)
	}
	if ex.Response == nil {
		return b.String()
	}
	resp := ex.Response
	fmt.Fprintf(&b, "< %d\n", resp.StatusCode)
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(&b, "< %s: %s\n", k, v)
		}
	}
	if len(resp.Body) > 0 {
		fmt.Fprintf(&b, "< %s\n", resp.Body)
	}
	return b.String()
}

// summary renders the transcript so far as one line per exchange.
func (c *Client) summary() string {
	var b strings.Builder
	for i, ex := range c.transcript {
		req := ex.Request
		fmt.Fprintf(&b, "%3d. %s %s", i+1, req.Method, req.URL)
		if req.Key != nil {
			fmt.Fprintf(&b, " as %s", req.Key.Name)
		}
		if ex.Response != nil {
			fmt.Fprintf(&b, " -> %d", ex.Response.StatusCode)
			if ex.Response.Problem != nil {
				fmt.Fprintf(&b, " %s", ex.Response.Problem.Type)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}
