package acmetest

import (
	"strings"
	"testing"
)

func TestParseScriptErrors(t *testing.T) {
	for _, tt := range []struct {
		name, script, want string
	}{
		{"check before request", "$code == 200\n", "unknown statement"},
		{"bare URL", "GET directory\n", "URL must be absolute"},
		{"POST without payload", "POST $dir.newAccount\n$code == 201\n", "POST without payload"},
		{"empty payload", "POST $dir.newAccount\npayload\n", "empty payload"},
		{"empty multiline payload", "POST $dir.newAccount\npayload\n$code == 400\n", "empty payload"},
		{"POST-as-GET with payload", "POST-as-GET $dir.newAccount\npayload {}\n", "requires a POST"},
		{"GET with payload", "GET $dirURL\npayload {}\n", "requires a POST"},
		{"GET with sign", "GET $dirURL\nsign jwk\n", "sign requires a POST"},
		{"unknown operator", "GET $dirURL\n$code = 200\n", "unknown operator"},
		{"unknown directive", "GET $dirURL\ncode == 200\n", "unknown directive"},
		{"old json check", "GET $dirURL\njson .x == 1\n", "unknown directive"},
		{"exists with text", "GET $dirURL\n$body.x exists y\n", "takes no argument"},
		{"error operator", "GET $dirURL\nerror != malformed\n", "supports only =="},
		{"error urn", "GET $dirURL\nerror == urn:ietf:params:acme:error:malformed\n", "usage: error"},
		{"two requests", "GET $dirURL\nHEAD $dir.newNonce\n", "already has a request"},
		{"stray indent", "GET $dirURL\n\tfoo\n", "unexpected indented line"},
		{"bad sleep", "sleep soon\n", "invalid sleep duration"},
		{"statement in case", "GET $dirURL\nsleep 1h\n", "unknown directive"},
		{"case in statement", "sleep 1h\nGET $dirURL\n", "must be alone"},
		{"bad sign", "POST $dir.newAccount\npayload {}\nsign foo\n", "unknown sign option"},
		{"sign nonce literal", "POST $dir.newAccount\npayload {}\nsign nonce AAAA\n", "usage: sign nonce"},
		{"sign kid with url", "POST $dir.newAccount\npayload {}\nsign kid https://x\n", "takes no argument"},
		{"sign header without value", "POST $dir.newAccount\npayload {}\nsign header nonce\n", "usage: sign header"},
		{"inner without payload", "POST-as-GET $dir.keyChange\nsign inner bob\n", "sign inner without payload"},
		{"bad capture", "GET $dirURL\ncapture x $body\n", "usage: capture"},
		{"capture text", "GET $dirURL\ncapture x = foo-$body\n", "usage: capture"},
		{"capture reserved", "GET $dirURL\ncapture body = $header.Location\n", "reserved name"},
		{"key reserved", "key dir ML-DSA-44\n", "reserved name"},
		{"bind without url", "bind bob\n", "usage: bind"},
		{"as on GET", "GET $dirURL as bob\n", "usage: GET"},
	} {
		_, err := parseScript("s.txt", tt.script)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want %q", tt.name, err, tt.want)
		}
	}
}

func TestCheckRegexp(t *testing.T) {
	for _, tt := range []struct {
		name, op, pattern, value, want string
	}{
		{"match", "~", "^$pattern$$", "valid", ""},
		{"mismatch", "~", "^$pattern$$", "other", "does not match"},
		{"negative match", "!~", "^$pattern$$", "valid", "matches"},
		{"negative mismatch", "!~", "^$pattern$$", "other", ""},
		{"invalid literal", "~", "(", "valid", "invalid regexp"},
		{"invalid expansion", "~", "$invalid", "valid", "invalid regexp"},
		{"invalid negative expansion", "!~", "$invalid", "valid", "invalid regexp"},
		{"valid after expansion", "~", "$open)valid", "valid", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, err := parseScript("s.txt", "GET $dirURL\n$body.status "+tt.op+" "+tt.pattern+"\n")
			if err != nil {
				t.Fatal(err)
			}
			sc := &scope{
				c:        NewClient(t, nil, "https://ca.test/directory"),
				resp:     &Response{JSON: map[string]any{"status": tt.value}},
				captures: map[string]any{"pattern": "valid", "invalid": "[", "open": "("},
			}
			got := s.paragraphs[0].checks[0].run(sc)
			if tt.want == "" && got != "" || tt.want != "" && !strings.Contains(got, tt.want) {
				t.Errorf("check: %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseEmptyText(t *testing.T) {
	s, err := parseScript("s.txt", "POST $dir.newAccount\nbody\n$header.Foo ==\n")
	if err != nil {
		t.Fatal(err)
	}
	if p := s.paragraphs[0]; p.body == nil || *p.body != "" || p.checks[0].want != "" {
		t.Errorf("body %v checks %+v", p.body, p.checks)
	}
}

func TestParseScript(t *testing.T) {
	s, err := parseScript("s.txt", `# comment
GET $dirURL
$body.newNonce ~ ^https://

key bob ML-DSA-65

POST $dir.newAccount as bob
payload
	{"termsOfServiceAgreed": true,
	 "contact": []}
sign nonce reuse
$code == 201
capture acct = $header.Location

sleep 1h

POST $dir.keyChange as bob
payload {"account": "$bob.url", "oldKey": $bob.jwk}
sign inner carol
error == badPublicKey
$body.detail contains in use

bind carol $bob.url
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.paragraphs) != 6 {
		t.Fatalf("got %d paragraphs, want 6", len(s.paragraphs))
	}
	// The default code check is added.
	if p := s.paragraphs[0]; len(p.checks) != 2 || p.checks[1].expr != "$code" || p.checks[1].want != "200" {
		t.Errorf("paragraph 1 checks: %+v", p.checks)
	}
	if p := s.paragraphs[1]; p.key != [2]string{"bob", "ML-DSA-65"} {
		t.Errorf("paragraph 2: %+v", p)
	}
	p := s.paragraphs[2]
	if p.method != "POST" || p.as != "bob" || p.url != "$dir.newAccount" || p.nonce != NonceReuse {
		t.Errorf("paragraph 3: %+v", p)
	}
	if want := "{\"termsOfServiceAgreed\": true,\n \"contact\": []}\n"; p.payload == nil || *p.payload != want {
		t.Errorf("payload %q, want %q", *p.payload, want)
	}
	if len(p.checks) != 1 || p.checks[0].want != "201" || len(p.captures) != 1 || p.captures[0].expr != "$header.Location" {
		t.Errorf("checks %+v captures %+v", p.checks, p.captures)
	}
	if p := s.paragraphs[3]; p.sleep.Hours() != 1 {
		t.Errorf("paragraph 4: %+v", p)
	}
	p = s.paragraphs[4]
	if p.inner != "carol" || len(p.checks) != 2 || p.checks[0].expr != "" || p.checks[1].expr != "$body.detail" {
		t.Errorf("paragraph 5: %+v", p)
	}
	if p := s.paragraphs[5]; p.bind != [2]string{"carol", "$bob.url"} {
		t.Errorf("paragraph 6: %+v", p)
	}
}

func TestExpand(t *testing.T) {
	vars := map[string]any{
		"account": "https://ca/acct/1",
		"code":    201,
		"body": map[string]any{
			"status":         "valid",
			"n":              float64(2),
			"ok":             true,
			"authorizations": []any{"https://ca/authz/1", "https://ca/authz/2"},
			"challenges": []any{
				map[string]any{"type": "dns-01", "url": "https://ca/chal/1"},
				map[string]any{"type": "http-01", "url": "https://ca/chal/2"},
			},
		},
	}
	lookup := func(name string) (any, bool) { v, ok := vars[name]; return v, ok }
	for _, tt := range []struct{ in, want string }{
		{"$account", "https://ca/acct/1"},
		{"$account/orders", "https://ca/acct/1/orders"},
		{"$code", "201"},
		{"$body.status", "valid"},
		{"$body.n", "2"},
		{"$body.ok", "true"},
		{"$body.authorizations[1]", "https://ca/authz/2"},
		{"$body.challenges[type=http-01].url", "https://ca/chal/2"},
		{"$body.authorizations", `["https://ca/authz/1","https://ca/authz/2"]`},
		{"$body.challenges[0]", `{"type":"dns-01","url":"https://ca/chal/1"}`},
		{"$$body", "$body"},
		{"x $body.status.", "x valid."},
	} {
		got, err := expand(tt.in, lookup)
		if err != nil || got != tt.want {
			t.Errorf("expand(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
	for _, in := range []string{"$nope", "$body.nope", "$body.authorizations[5]", "$", "$body.challenges[type=tls].url"} {
		if got, err := expand(in, lookup); err == nil {
			t.Errorf("expand(%q) = %q, want error", in, got)
		}
	}

	v, err := evaluate("$body.challenges[0]", lookup)
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := v.(map[string]any); !ok || m["type"] != "dns-01" {
		t.Errorf("evaluate kept %T %v, want the object", v, v)
	}
	if v, _ := evaluate("$body.n", lookup); v != float64(2) {
		t.Errorf("evaluate($body.n) = %T %v, want float64 2", v, v)
	}
	if _, found, err := resolve("$body.nope", lookup); found || err != nil {
		t.Errorf("resolve($body.nope) = found %v, err %v; want not found, nil", found, err)
	}
	if _, _, err := resolve("$nope", lookup); err == nil {
		t.Error("resolve($nope) succeeded, want undefined variable error")
	}
}
