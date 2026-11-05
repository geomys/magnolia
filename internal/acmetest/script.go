package acmetest

import (
	"crypto/mldsa"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// RunScripts runs every *.txt script in dir as a parallel subtest.
//
// Each script runs in its own synctest bubble against a fresh server from
// newServer, which returns the handler and the directory URL. The server is
// wrapped in an httptest in-memory network, so time in scripts is fake and
// sleep statements are instant. The directory is fetched before the first
// case.
//
// # Scripts
//
// A script is a sequence of paragraphs separated by blank lines. Lines
// starting with # are comments. A paragraph is either a single statement or
// a request case: a request line, request directives, and checks.
//
// Statements:
//
//	sleep <duration>          advance time
//	key <name> <ML-DSA-65>    create a key with the given parameter set
//	bind <key> <url>          record that key is the account key at url
//
// Request lines:
//
//	GET <url>
//	HEAD <url>
//	POST <url> [as <key>]
//	POST-as-GET <url> [as <key>]
//
// A URL is an absolute URL or a variable reference, such as $dir.newAccount.
// Requests without "as" use the key named "account". Keys are created on
// first use as ML-DSA-44.
//
// Request directives:
//
//	payload <text>            the JWS payload
//	body <text>               a raw, unsigned request body
//	reqheader <name> <value>  a request header
//	sign nonce reuse|invalid|missing
//	sign jwk                  embed the JWK
//	sign kid                  use the bound account URL as kid
//	sign key <name>           sign with another key
//	sign inner <key>          wrap the payload in a JWS by key with its JWK
//	                          embedded and the request URL, as in keyChange
//	sign header <name> <json> set a protected header parameter, replacing
//	                          the computed one
//
// A <text> argument is the rest of the line, with trailing whitespace
// removed, and may be empty. The payload and body text may instead be the
// following lines, each indented with a single tab, with the tab removed
// and the newline kept:
//
//	payload
//		{"termsOfServiceAgreed": true,
//		 "contact": ["mailto:admin@example.org"]}
//
// Checks:
//
//	<variable> <op> <text>
//	error == <type>           4xx/5xx, problem+json, and the standard ACME error
//	                          type, by its short name (malformed, badNonce)
//	capture <name> = <variable>
//
// Operators are ==, !=, ~, !~, contains, !contains, exists, and !exists.
// The variable's value is compared as text: strings as themselves, anything
// else as canonical JSON (no spaces, sorted members). If a case has no
// $code or error check, the status must be 200.
//
// # Variables
//
// A variable reference is $name, optionally followed by a path into a JSON
// value: .member, [3], or [member=value] to select from an array. Text in
// URLs, payloads, headers, and check operands is expanded, with $$ for a
// literal dollar sign. Captures keep the JSON type of the value.
//
//	$dir       the directory object, so $dir.newAccount is a URL
//	$dirURL    the directory URL
//	$code      the status code of the most recent response
//	$header    its headers, by canonical name, so $header.Location
//	$body      its decoded JSON body
//	$<key>     a key: .url is the bound account URL, .jwk the public JWK,
//	           and .alg the JWS algorithm
//	$<name>    a captured value
//
// On a request line, the response variables refer to the previous case's
// response; on checks and captures, to the current one. A key is bound when
// a newAccount request it signed gets a Location, or by bind, which only
// updates the client's view. Requests to newAccount embed the JWK; other
// requests use the bound account URL as "kid", and are an error for an
// unbound key, except that revokeCert falls back to the JWK.
func RunScripts(t *testing.T, dir string, newServer func(t testing.TB) (http.Handler, string)) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no scripts in %s", dir)
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".txt"), func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			s, err := parseScript(file, string(data))
			if err != nil {
				t.Fatal(err)
			}
			synctest.Test(t, func(t *testing.T) {
				h, dirURL := newServer(t)
				srv := httptest.NewTestServer(t, h)
				c := NewClient(t, srv.Client(), dirURL)
				s.run(t, c)
			})
		})
	}
}

type script struct {
	paragraphs []*paragraph
}

// A paragraph is a statement or a request case.
type paragraph struct {
	file string
	line int

	// Statements. Exactly one is set, or none for a request case.
	sleep time.Duration
	key   [2]string // name, params
	bind  [2]string // key, url

	// Request case.
	method    string // GET, HEAD, POST, POST-as-GET
	url       string
	as        string
	payload   *string
	body      *string
	headers   [][2]string
	nonce     NonceMode
	embed     EmbedMode
	signKey   string
	inner     string
	protected [][2]string // header parameter, raw JSON
	checks    []*check
	captures  []*capture
}

type check struct {
	line int
	// expr is the variable reference, or "" for an error check.
	expr string
	op   string
	want string
}

type capture struct {
	line int
	name string
	expr string
}

var ops = map[string]bool{
	"==": true, "!=": true, "~": true, "!~": true,
	"contains": true, "!contains": true, "exists": true, "!exists": true,
}

var reserved = map[string]bool{"dir": true, "dirURL": true, "code": true, "header": true, "body": true}

var varRef = regexp.MustCompile(`^\$[A-Za-z0-9_-]+([.\[][^ \t]*)?$`)

func parseScript(file, text string) (*script, error) {
	s := new(script)
	var cur *paragraph
	var multiline *string
	lastBlank := true
	lineno := 0
	errorf := func(format string, args ...any) error {
		return fmt.Errorf("%s:%d: %s", file, lineno, fmt.Sprintf(format, args...))
	}
	for line := range strings.SplitSeq(text, "\n") {
		lineno++
		if strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimRight(line, " \t")
		if line == "" {
			multiline = nil
			lastBlank = true
			continue
		}
		if strings.HasPrefix(line, "\t") {
			if multiline == nil {
				return nil, errorf("unexpected indented line")
			}
			*multiline += line[1:] + "\n"
			continue
		}
		multiline = nil

		what, args := splitOneField(line)
		if lastBlank {
			cur = &paragraph{file: file, line: lineno}
			s.paragraphs = append(s.paragraphs, cur)
		} else if cur.method == "" {
			return nil, errorf("a statement must be alone in its paragraph")
		}
		lastBlank = false

		if cur.method == "" {
			switch what {
			case "GET", "HEAD", "POST", "POST-as-GET":
				cur.method = what
				fields := strings.Fields(args)
				switch {
				case len(fields) == 1:
					cur.url = fields[0]
				case len(fields) == 3 && fields[1] == "as" && (what == "POST" || what == "POST-as-GET"):
					cur.url, cur.as = fields[0], fields[2]
				default:
					return nil, errorf("usage: %s <url> [as <key>]", what)
				}
				if !strings.Contains(cur.url, "://") && !varRef.MatchString(cur.url) {
					return nil, errorf("URL must be absolute or a variable reference")
				}
			case "sleep":
				d, err := time.ParseDuration(args)
				if err != nil || d <= 0 {
					return nil, errorf("invalid sleep duration %q", args)
				}
				cur.sleep = d
			case "key":
				name, params := splitOneField(args)
				if name == "" || params == "" || strings.ContainsAny(params, " \t") {
					return nil, errorf("usage: key <name> <ML-DSA-44|ML-DSA-65|ML-DSA-87>")
				}
				if reserved[name] {
					return nil, errorf("%q is a reserved name", name)
				}
				cur.key = [2]string{name, params}
			case "bind":
				k, u := splitOneField(args)
				if k == "" || u == "" || strings.ContainsAny(u, " \t") {
					return nil, errorf("usage: bind <key> <url>")
				}
				cur.bind = [2]string{k, u}
			default:
				return nil, errorf("unknown statement %q", what)
			}
			continue
		}

		switch what {
		case "GET", "HEAD", "POST", "POST-as-GET":
			return nil, errorf("case already has a request")
		case "payload", "body":
			if cur.method != "POST" {
				return nil, errorf("%s requires a POST request", what)
			}
			target := &cur.body
			if what == "payload" {
				target = &cur.payload
			}
			if *target != nil {
				return nil, errorf("duplicate %s", what)
			}
			*target = new(string)
			if args != "" {
				**target = args
			} else {
				multiline = *target
			}
			continue
		case "reqheader":
			k, v := splitOneField(args)
			if k == "" {
				return nil, errorf("usage: reqheader <name> <value>")
			}
			cur.headers = append(cur.headers, [2]string{k, v})
			continue
		case "sign":
			if cur.method != "POST" && cur.method != "POST-as-GET" {
				return nil, errorf("sign requires a POST request")
			}
			k, v := splitOneField(args)
			switch k {
			case "nonce":
				mode, ok := map[string]NonceMode{"reuse": NonceReuse, "invalid": NonceInvalid, "missing": NonceMissing}[v]
				if !ok {
					return nil, errorf("usage: sign nonce reuse|invalid|missing")
				}
				cur.nonce = mode
			case "jwk", "kid":
				if v != "" {
					return nil, errorf("sign %s takes no argument", k)
				}
				cur.embed = map[string]EmbedMode{"jwk": EmbedJWK, "kid": EmbedKID}[k]
			case "key", "inner":
				if v == "" || strings.ContainsAny(v, " \t") {
					return nil, errorf("usage: sign %s <key>", k)
				}
				if k == "key" {
					cur.signKey = v
				} else {
					cur.inner = v
				}
			case "header":
				name, value := splitOneField(v)
				if name == "" || value == "" {
					return nil, errorf("usage: sign header <name> <json>")
				}
				cur.protected = append(cur.protected, [2]string{name, value})
			default:
				return nil, errorf("unknown sign option %q", k)
			}
			continue
		case "capture":
			name, rest := splitOneField(args)
			eq, expr := splitOneField(rest)
			if name == "" || eq != "=" || !varRef.MatchString(expr) {
				return nil, errorf("usage: capture <name> = $<variable>")
			}
			if reserved[name] {
				return nil, errorf("%q is a reserved name", name)
			}
			cur.captures = append(cur.captures, &capture{line: lineno, name: name, expr: expr})
			continue
		}

		chk := &check{line: lineno}
		switch {
		case what == "error":
		case varRef.MatchString(what):
			chk.expr = what
		default:
			return nil, errorf("unknown directive %q", what)
		}
		chk.op, args = splitOneField(args)
		if !ops[chk.op] {
			return nil, errorf("unknown operator %q", chk.op)
		}
		switch {
		case chk.expr == "" && chk.op != "==":
			return nil, errorf("error supports only ==")
		case chk.expr == "" && (args == "" || strings.ContainsAny(args, " \t:")):
			return nil, errorf("usage: error == <type>")
		case chk.op == "exists" || chk.op == "!exists":
			if args != "" {
				return nil, errorf("%s takes no argument", chk.op)
			}
		}
		chk.want = args
		cur.checks = append(cur.checks, chk)
	}
	for _, p := range s.paragraphs {
		if p.method == "" {
			continue
		}
		switch {
		case p.method == "POST" && p.payload == nil && p.body == nil:
			return nil, fmt.Errorf("%s:%d: POST without payload (use POST-as-GET for an empty payload)", p.file, p.line)
		case p.payload != nil && *p.payload == "":
			return nil, fmt.Errorf("%s:%d: empty payload (use POST-as-GET)", p.file, p.line)
		case p.inner != "" && p.payload == nil:
			return nil, fmt.Errorf("%s:%d: sign inner without payload", p.file, p.line)
		}
		hasCode := false
		for _, chk := range p.checks {
			if chk.expr == "$code" || chk.expr == "" {
				hasCode = true
			}
		}
		if !hasCode {
			p.checks = append(p.checks, &check{line: p.line, expr: "$code", op: "==", want: "200"})
		}
	}
	return s, nil
}

func splitOneField(text string) (field, rest string) {
	i := strings.IndexAny(text, " \t")
	if i < 0 {
		return text, ""
	}
	return text[:i], strings.TrimLeft(text[i:], " \t")
}

// scope resolves variable references for a running script.
type scope struct {
	c        *Client
	resp     *Response
	captures map[string]any
}

func (sc *scope) lookup(name string) (any, bool) {
	switch name {
	case "dir":
		return sc.c.Directory(), true
	case "dirURL":
		return sc.c.DirectoryURL(), true
	case "code":
		if sc.resp == nil {
			return nil, false
		}
		return sc.resp.StatusCode, true
	case "header":
		if sc.resp == nil {
			return nil, false
		}
		h := make(map[string]any)
		for k, v := range sc.resp.Header {
			h[k] = v[0]
		}
		return h, true
	case "body":
		if sc.resp == nil {
			return nil, false
		}
		return sc.resp.JSON, true
	}
	if k, ok := sc.c.Keys()[name]; ok {
		var jwk any
		json.Unmarshal([]byte(k.JWK()), &jwk)
		obj := map[string]any{"jwk": jwk, "alg": k.Alg()}
		if k.KID != "" {
			obj["url"] = k.KID
		}
		return obj, true
	}
	v, ok := sc.captures[name]
	return v, ok
}

// key returns the named key, refusing names that are captures.
func (sc *scope) key(name string) (*Key, error) {
	if _, ok := sc.captures[name]; ok {
		return nil, fmt.Errorf("%q is a captured variable, not a key", name)
	}
	return sc.c.Key(name), nil
}

// run executes the script against c, failing t at the first failing paragraph.
func (s *script) run(t *testing.T, c *Client) {
	t.Helper()
	sc := &scope{c: c, captures: make(map[string]any)}
	c.Directory()
	for _, p := range s.paragraphs {
		c.where = fmt.Sprintf("%s:%d", p.file, p.line)
		if err := p.run(sc); err != nil {
			t.Fatalf("%s:%d: %v\n%s\ntranscript:\n%s", p.file, p.line, err, c.lastDump(), c.summary())
		}
		if t.Failed() {
			t.FailNow()
		}
	}
}

// lastDump renders the most recent exchange, if any.
func (c *Client) lastDump() string {
	if len(c.transcript) == 0 {
		return ""
	}
	return c.dump(c.transcript[len(c.transcript)-1])
}

func (p *paragraph) run(sc *scope) error {
	switch {
	case p.sleep != 0:
		time.Sleep(p.sleep)
		return nil
	case p.key[0] != "":
		params, ok := map[string]mldsa.Parameters{
			"ML-DSA-44": mldsa.MLDSA44(), "ML-DSA-65": mldsa.MLDSA65(), "ML-DSA-87": mldsa.MLDSA87(),
		}[p.key[1]]
		if !ok {
			return fmt.Errorf("unknown parameter set %q", p.key[1])
		}
		if _, ok := sc.captures[p.key[0]]; ok {
			return fmt.Errorf("%q is a captured variable, not a key", p.key[0])
		}
		sc.c.NewKey(p.key[0], params)
		return nil
	case p.bind[0] != "":
		k, err := sc.key(p.bind[0])
		if err != nil {
			return err
		}
		u, err := expand(p.bind[1], sc.lookup)
		if err != nil {
			return err
		}
		k.KID = u
		return nil
	}

	req, err := p.request(sc)
	if err != nil {
		return err
	}
	sc.resp = sc.c.Do(req)

	var msgs []string
	for _, chk := range p.checks {
		if msg := chk.run(sc); msg != "" {
			msgs = append(msgs, fmt.Sprintf("%s:%d: %s", p.file, chk.line, msg))
		}
	}
	if len(msgs) > 0 {
		return fmt.Errorf("%s %s\n%s", p.method, p.url, strings.Join(msgs, "\n"))
	}
	for _, cap := range p.captures {
		if _, ok := sc.c.Keys()[cap.name]; ok {
			return fmt.Errorf("%s:%d: %q is a key, not a variable", p.file, cap.line, cap.name)
		}
		v, err := evaluate(cap.expr, sc.lookup)
		if err != nil {
			return fmt.Errorf("%s:%d: %v", p.file, cap.line, err)
		}
		sc.captures[cap.name] = v
	}
	return nil
}

// request builds the Request for the case, with all text expanded.
func (p *paragraph) request(sc *scope) (*Request, error) {
	req := &Request{Method: p.method, Header: make(http.Header), Nonce: p.nonce, Embed: p.embed}
	if p.method == "POST-as-GET" {
		req.Method = "POST"
	}
	u, err := expand(p.url, sc.lookup)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(u, "://") {
		return nil, fmt.Errorf("URL %q is not absolute", u)
	}
	req.URL = u
	if req.Method == "POST" {
		name := p.as
		if name == "" {
			name = "account"
		}
		if req.Key, err = sc.key(name); err != nil {
			return nil, err
		}
	}
	if p.signKey != "" {
		if req.SignKey, err = sc.key(p.signKey); err != nil {
			return nil, err
		}
	}
	if p.payload != nil {
		pl, err := expand(*p.payload, sc.lookup)
		if err != nil {
			return nil, err
		}
		req.Payload = []byte(pl)
		if p.inner != "" {
			k, err := sc.key(p.inner)
			if err != nil {
				return nil, err
			}
			req.Payload = sc.c.Inner(k, req.URL, req.Payload)
		}
	}
	if p.body != nil {
		b, err := expand(*p.body, sc.lookup)
		if err != nil {
			return nil, err
		}
		req.Body = []byte(b)
	}
	for _, h := range p.headers {
		v, err := expand(h[1], sc.lookup)
		if err != nil {
			return nil, err
		}
		req.Header.Add(h[0], v)
	}
	for _, h := range p.protected {
		v, err := expand(h[1], sc.lookup)
		if err != nil {
			return nil, err
		}
		if !jsontext.Value(v).IsValid() {
			return nil, fmt.Errorf("sign header %s: %q is not valid JSON", h[0], v)
		}
		if req.Protected == nil {
			req.Protected = make(map[string]string)
		}
		req.Protected[h[0]] = v
	}
	return req, nil
}

// run evaluates the check and returns a failure message, or "".
func (chk *check) run(sc *scope) string {
	if chk.expr == "" {
		return chk.runError(sc.resp)
	}
	want, err := expand(chk.want, sc.lookup)
	if err != nil {
		return err.Error()
	}
	value, found, err := resolve(chk.expr, sc.lookup)
	if err != nil {
		return err.Error()
	}
	switch chk.op {
	case "exists":
		if !found {
			return fmt.Sprintf("%s does not exist", chk.expr)
		}
		return ""
	case "!exists":
		if found {
			return fmt.Sprintf("%s exists, with value %s", chk.expr, stringify(value))
		}
		return ""
	}
	if !found {
		return fmt.Sprintf("%s does not exist", chk.expr)
	}
	got := stringify(value)
	switch chk.op {
	case "==":
		if got != want {
			return fmt.Sprintf("%s = %q, want %q", chk.expr, got, want)
		}
	case "!=":
		if got == want {
			return fmt.Sprintf("%s = %q, want anything else", chk.expr, got)
		}
	case "~", "!~":
		re, err := regexp.Compile(want)
		if err != nil {
			return fmt.Sprintf("invalid regexp %q: %v", want, err)
		}
		match := re.MatchString(got)
		if chk.op == "~" && !match {
			return fmt.Sprintf("%s = %q, does not match %q", chk.expr, got, want)
		}
		if chk.op == "!~" && match {
			return fmt.Sprintf("%s = %q, matches %q", chk.expr, got, want)
		}
	case "contains":
		if !strings.Contains(got, want) {
			return fmt.Sprintf("%s = %q, does not contain %q", chk.expr, got, want)
		}
	case "!contains":
		if strings.Contains(got, want) {
			return fmt.Sprintf("%s = %q, contains %q", chk.expr, got, want)
		}
	}
	return ""
}

// runError checks that resp is an ACME error of the given standard type.
func (chk *check) runError(resp *Response) string {
	typ := "urn:ietf:params:acme:error:" + chk.want
	switch {
	case resp.StatusCode < 400:
		return fmt.Sprintf("$code = %d, want an error", resp.StatusCode)
	case resp.Problem == nil:
		return "response is not a problem document"
	case resp.Problem.Type != typ:
		return fmt.Sprintf("error = %q, want %q", resp.Problem.Type, typ)
	}
	return ""
}
