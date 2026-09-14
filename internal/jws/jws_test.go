package jws_test

import (
	"bytes"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"geomys.org/magnolia/internal/jws"
)

// vector is one of the JOSE examples from RFC 9964, Appendix A.1, as stored
// in testdata. Each example is a JWS in compact serialization, signed with the
// key expanded from an all-zeros seed.
type vector struct {
	Priv string `json:"priv"`
	JWK  struct {
		KID  string `json:"kid"`
		KTY  string `json:"kty"`
		Alg  string `json:"alg"`
		Pub  string `json:"pub"`
		Priv string `json:"priv"`
	} `json:"jwk"`
	JWS           string `json:"jws"`
	RawToBeSigned string `json:"raw_to_be_signed"`
	RawSignature  string `json:"raw_signature"`
	RawPublicKey  string `json:"raw_public_key"`
}

const frodo = "It’s a dangerous business, Frodo, going out your door."

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// loadVector returns the RFC 9964 example for params, along with the private
// key expanded from its seed. It checks that the key matches the example.
func loadVector(t *testing.T, params mldsa.Parameters) (*vector, *mldsa.PrivateKey) {
	t.Helper()
	data, err := os.ReadFile("testdata/rfc9964-" + strings.ToLower(params.String()) + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	sk, err := mldsa.NewPrivateKey(params, unhex(t, v.Priv))
	if err != nil {
		t.Fatal(err)
	}
	pub := sk.PublicKey().Bytes()
	if !bytes.Equal(pub, unhex(t, v.RawPublicKey)) {
		t.Fatalf("%s: seed does not expand to raw_public_key", params)
	}
	if b64(string(pub)) != v.JWK.Pub {
		t.Fatalf("%s: seed does not expand to jwk.pub", params)
	}
	if v.JWK.KTY != "AKP" || v.JWK.Alg != params.String() {
		t.Fatalf("%s: unexpected JWK kty %q alg %q", params, v.JWK.KTY, v.JWK.Alg)
	}
	return &v, sk
}

// publicJWK returns the public members of the example JWK, in the order used by
// RFC 9964.
func publicJWK(v *vector) string {
	return `{"kid":"` + v.JWK.KID + `","kty":"AKP","alg":"` + v.JWK.Alg + `","pub":"` + v.JWK.Pub + `"}`
}

func flattened(protected, payload, signature string) []byte {
	return []byte(`{"protected":"` + protected + `","payload":"` + payload + `","signature":"` + signature + `"}`)
}

// signParts signs the given protected header and payload, returning the three
// base64url-encoded members of the Flattened JWS JSON Serialization.
func signParts(t *testing.T, sk *mldsa.PrivateKey, protected, payload string) (p, pl, s string) {
	t.Helper()
	p, pl = b64(protected), b64(payload)
	sig, err := sk.SignDeterministic([]byte(p+"."+pl), nil)
	if err != nil {
		t.Fatal(err)
	}
	return p, pl, b64(string(sig))
}

func sign(t *testing.T, sk *mldsa.PrivateKey, protected, payload string) []byte {
	t.Helper()
	return flattened(signParts(t, sk, protected, payload))
}

var allParams = []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()}

// TestRFC9964Vectors verifies the RFC 9964 Appendix A examples verbatim, after
// converting them from compact to flattened serialization.
func TestRFC9964Vectors(t *testing.T) {
	for _, params := range allParams {
		t.Run(params.String(), func(t *testing.T) {
			v, sk := loadVector(t, params)
			pub := sk.PublicKey()

			parts := strings.Split(v.JWS, ".")
			if len(parts) != 3 {
				t.Fatalf("compact JWS has %d parts", len(parts))
			}
			if got, want := parts[0]+"."+parts[1], string(unhex(t, v.RawToBeSigned)); got != want {
				t.Errorf("signing input %q, want %q", got, want)
			}
			sig, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sig, unhex(t, v.RawSignature)) {
				t.Error("signature does not match raw_signature")
			}
			if len(sig) != params.SignatureSize() {
				t.Errorf("signature is %d bytes, want %d", len(sig), params.SignatureSize())
			}
			body := flattened(parts[0], parts[1], parts[2])

			r, err := jws.Verify(body, pub)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if string(r.Payload) != frodo {
				t.Errorf("payload %q, want %q", r.Payload, frodo)
			}
			if r.Nonce != "" || r.URL != "" {
				t.Errorf("nonce %q url %q, want empty", r.Nonce, r.URL)
			}

			kid, err := jws.PeekKID(body)
			if err != nil {
				t.Fatalf("PeekKID: %v", err)
			}
			if kid != v.JWK.KID {
				t.Errorf("kid %q, want %q", kid, v.JWK.KID)
			}

			if _, err := jws.VerifyWithJWK(body); err == nil {
				t.Error("VerifyWithJWK accepted a kid-authenticated JWS")
			}

			for _, other := range allParams {
				if other == params {
					continue
				}
				_, otherKey := loadVector(t, other)
				if _, err := jws.Verify(body, otherKey.PublicKey()); err == nil {
					t.Errorf("Verify accepted the %s JWS with a %s key", params, other)
				}
			}

			corrupted := []byte(parts[2])
			corrupted[len(corrupted)/2] ^= 1
			if _, err := jws.Verify(flattened(parts[0], parts[1], string(corrupted)), pub); err == nil {
				t.Error("Verify accepted a corrupted signature")
			}
		})
	}
}

// TestRFC8555Examples replays the request examples of RFC 8555, Section 7,
// with "alg" changed from ES256 to ML-DSA-44 and the account key replaced by
// the RFC 9964 ML-DSA-44 example key.
func TestRFC8555Examples(t *testing.T) {
	v44, sk44 := loadVector(t, mldsa.MLDSA44())
	v65, sk65 := loadVector(t, mldsa.MLDSA65())
	pub44 := sk44.PublicKey()
	const account = "https://example.com/acme/acct/evOfKhNU60wg"

	t.Run("7.3 new-account", func(t *testing.T) {
		protected := `{
       "alg": "ML-DSA-44",
       "jwk": ` + publicJWK(v44) + `,
       "nonce": "6S8IqOGY7eL2lsGoTZYifg",
       "url": "https://example.com/acme/new-account"
     }`
		payload := `{
       "termsOfServiceAgreed": true,
       "contact": [
         "mailto:cert-admin@example.org",
         "mailto:admin@example.org"
       ]
     }`
		body := sign(t, sk44, protected, payload)

		r, err := jws.VerifyWithJWK(body)
		if err != nil {
			t.Fatalf("VerifyWithJWK: %v", err)
		}
		if !r.PublicKey.Equal(pub44) {
			t.Error("returned public key does not match the JWK")
		}
		if r.Nonce != "6S8IqOGY7eL2lsGoTZYifg" {
			t.Errorf("nonce %q", r.Nonce)
		}
		if r.URL != "https://example.com/acme/new-account" {
			t.Errorf("url %q", r.URL)
		}
		if string(r.Payload) != payload {
			t.Errorf("payload %q", r.Payload)
		}

		if _, err := jws.Verify(body, pub44); err == nil {
			t.Error("Verify accepted a jwk-authenticated JWS")
		}
		if _, err := jws.PeekKID(body); err == nil {
			t.Error("PeekKID accepted a jwk-authenticated JWS")
		}
	})

	t.Run("7.3.2 account update", func(t *testing.T) {
		protected := `{
       "alg": "ML-DSA-44",
       "kid": "` + account + `",
       "nonce": "ax5RnthDqp_Yf4_HZnFLmA",
       "url": "` + account + `"
     }`
		payload := `{
       "contact": [
         "mailto:certificates@example.org",
         "mailto:admin@example.org"
       ]
     }`
		body := sign(t, sk44, protected, payload)

		kid, err := jws.PeekKID(body)
		if err != nil {
			t.Fatalf("PeekKID: %v", err)
		}
		if kid != account {
			t.Errorf("kid %q, want %q", kid, account)
		}
		r, err := jws.Verify(body, pub44)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if r.Nonce != "ax5RnthDqp_Yf4_HZnFLmA" {
			t.Errorf("nonce %q", r.Nonce)
		}
		if r.URL != account {
			t.Errorf("url %q", r.URL)
		}
		if string(r.Payload) != payload {
			t.Errorf("payload %q", r.Payload)
		}

		if _, err := jws.VerifyWithJWK(body); err == nil {
			t.Error("VerifyWithJWK accepted a kid-authenticated JWS")
		}
		if _, err := jws.Verify(body, sk65.PublicKey()); err == nil {
			t.Error("Verify accepted the JWS with a key of the wrong parameter set")
		}
	})

	t.Run("7.3.5 key-change", func(t *testing.T) {
		// The new key is the RFC 9964 ML-DSA-65 example key, and the old
		// (account) key is the ML-DSA-44 one.
		innerProtected := `{
         "alg": "ML-DSA-65",
         "jwk": ` + publicJWK(v65) + `,
         "url": "https://example.com/acme/key-change"
       }`
		innerPayload := `{
         "account": "` + account + `",
         "oldKey": ` + publicJWK(v44) + `
       }`
		inner := sign(t, sk65, innerProtected, innerPayload)

		outerProtected := `{
       "alg": "ML-DSA-44",
       "kid": "` + account + `",
       "nonce": "S9XaOcxP5McpnTcWPIhYuB",
       "url": "https://example.com/acme/key-change"
     }`
		outer := sign(t, sk44, outerProtected, string(inner))

		r, err := jws.Verify(outer, pub44)
		if err != nil {
			t.Fatalf("Verify(outer): %v", err)
		}
		if r.Nonce != "S9XaOcxP5McpnTcWPIhYuB" || r.URL != "https://example.com/acme/key-change" {
			t.Errorf("outer nonce %q url %q", r.Nonce, r.URL)
		}
		if !bytes.Equal(r.Payload, inner) {
			t.Error("outer payload is not the inner JWS")
		}

		ri, err := jws.VerifyWithJWK(r.Payload)
		if err != nil {
			t.Fatalf("VerifyWithJWK(inner): %v", err)
		}
		if !ri.PublicKey.Equal(sk65.PublicKey()) {
			t.Error("inner public key is not the new key")
		}
		if ri.Nonce != "" {
			t.Errorf("inner nonce %q, want empty", ri.Nonce)
		}
		if ri.URL != r.URL {
			t.Errorf("inner url %q does not match outer url %q", ri.URL, r.URL)
		}
		if string(ri.Payload) != innerPayload {
			t.Errorf("inner payload %q", ri.Payload)
		}
	})

	t.Run("7.4.2 POST-as-GET", func(t *testing.T) {
		protected := `{
       "alg": "ML-DSA-44",
       "kid": "` + account + `",
       "nonce": "uQpSjlRb4vQVCjVYAyyUWg",
       "url": "https://example.com/acme/cert/mAt3xBGaobw"
     }`
		body := sign(t, sk44, protected, "")
		if !bytes.Contains(body, []byte(`"payload":""`)) {
			t.Fatalf("expected an empty payload member in %s", body)
		}
		r, err := jws.Verify(body, pub44)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if len(r.Payload) != 0 {
			t.Errorf("payload %q, want empty", r.Payload)
		}
		if r.URL != "https://example.com/acme/cert/mAt3xBGaobw" {
			t.Errorf("url %q", r.URL)
		}
	})

	t.Run("7.5.1 challenge response", func(t *testing.T) {
		protected := `{
       "alg": "ML-DSA-44",
       "kid": "` + account + `",
       "nonce": "Q_s3MWoqT05TrdkM2MTDcw",
       "url": "https://example.com/acme/chall/prV_B7yEyA4"
     }`
		r, err := jws.Verify(sign(t, sk44, protected, "{}"), pub44)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if string(r.Payload) != "{}" {
			t.Errorf("payload %q, want {}", r.Payload)
		}
	})

	t.Run("7.6 revoke-cert with certificate key", func(t *testing.T) {
		protected := `{
       "alg": "ML-DSA-65",
       "jwk": ` + publicJWK(v65) + `,
       "nonce": "JHb54aT_KTXBWQOzGYkt9A",
       "url": "https://example.com/acme/revoke-cert"
     }`
		payload := `{
       "certificate": "MIIEDTCCAvegAwIBAgIRAP8...",
       "reason": 1
     }`
		r, err := jws.VerifyWithJWK(sign(t, sk65, protected, payload))
		if err != nil {
			t.Fatalf("VerifyWithJWK: %v", err)
		}
		if !r.PublicKey.Equal(sk65.PublicKey()) {
			t.Error("returned public key does not match the JWK")
		}
		if r.Nonce != "JHb54aT_KTXBWQOzGYkt9A" || string(r.Payload) != payload {
			t.Errorf("nonce %q payload %q", r.Nonce, r.Payload)
		}
	})
}

// TestAllParameterSets runs the new-account and account update examples with
// each ML-DSA parameter set.
func TestAllParameterSets(t *testing.T) {
	for _, params := range allParams {
		t.Run(params.String(), func(t *testing.T) {
			v, sk := loadVector(t, params)
			alg := params.String()

			body := sign(t, sk, `{"alg":"`+alg+`","jwk":`+publicJWK(v)+`,"nonce":"6S8IqOGY7eL2lsGoTZYifg","url":"https://example.com/acme/new-account"}`,
				`{"termsOfServiceAgreed":true}`)
			r, err := jws.VerifyWithJWK(body)
			if err != nil {
				t.Fatalf("VerifyWithJWK: %v", err)
			}
			if !r.PublicKey.Equal(sk.PublicKey()) || r.PublicKey.Parameters() != params {
				t.Error("returned public key does not match")
			}

			body = sign(t, sk, `{"alg":"`+alg+`","kid":"https://example.com/acme/acct/evOfKhNU60wg","nonce":"ax5RnthDqp_Yf4_HZnFLmA","url":"https://example.com/acme/acct/evOfKhNU60wg"}`,
				`{"contact":["mailto:admin@example.org"]}`)
			if _, err := jws.Verify(body, sk.PublicKey()); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

// TestReject checks that malformed and non-conforming JWS are rejected, and
// that the intended check is the one that fires.
func TestReject(t *testing.T) {
	v44, sk44 := loadVector(t, mldsa.MLDSA44())
	v65, sk65 := loadVector(t, mldsa.MLDSA65())
	pub44 := sk44.PublicKey()
	const account = "https://example.com/acme/acct/evOfKhNU60wg"

	kidHeader := func(alg string) string {
		return `{"alg":"` + alg + `","kid":"` + account + `","nonce":"ax5RnthDqp_Yf4_HZnFLmA","url":"` + account + `"}`
	}
	jwkHeader := func(alg, jwk string) string {
		return `{"alg":"` + alg + `","jwk":` + jwk + `,"nonce":"6S8IqOGY7eL2lsGoTZYifg","url":"https://example.com/acme/new-account"}`
	}
	const payload = `{"contact":["mailto:admin@example.org"]}`
	p, pl, s := signParts(t, sk44, kidHeader("ML-DSA-44"), payload)

	corruptedSig := []byte(s)
	corruptedSig[len(corruptedSig)/2] ^= 1
	tamperedPub := []byte(sk44.PublicKey().Bytes())
	tamperedPub[100] ^= 1
	jwk44 := publicJWK(v44)
	withMember := func(jwk, member string) string {
		return strings.TrimSuffix(jwk, "}") + "," + member + "}"
	}

	tests := []struct {
		name string
		body []byte
		jwk  bool   // verify with VerifyWithJWK instead of Verify
		want string // substring of the error, if it comes from the package
	}{
		// Signature and encoding.
		{"tampered payload", flattened(p, b64(`{"contact":["mailto:evil@example.org"]}`), s), false, "invalid signature"},
		{"tampered protected header", flattened(b64(strings.Replace(kidHeader("ML-DSA-44"), "ax5R", "bx5R", 1)), pl, s), false, "invalid signature"},
		{"corrupted signature", flattened(p, pl, string(corruptedSig)), false, "invalid signature"},
		{"truncated signature", flattened(p, pl, s[:len(s)-8]), false, "invalid signature length"},
		{"empty signature", flattened(p, pl, ""), false, "invalid signature length"},
		{"padded base64url", flattened(p, pl+"=", s), false, "illegal base64"},
		{"standard base64 alphabet", flattened(p, strings.NewReplacer("-", "+", "_", "/").Replace(s), pl), false, "illegal base64"},
		{"newline in base64url", []byte(`{"protected":"` + p + `","payload":"` + pl[:4] + `\n` + pl[4:] + `","signature":"` + s + `"}`), false, "illegal character"},
		{"payload is a number", []byte(`{"protected":"` + p + `","payload":123,"signature":"` + s + `"}`), false, ""},
		{"payload is an object", []byte(`{"protected":"` + p + `","payload":{},"signature":"` + s + `"}`), false, ""},

		// JWS JSON serialization.
		{"empty body", []byte(""), false, ""},
		{"not an object", []byte(`[]`), false, ""},
		{"invalid JSON", []byte(`{"protected":`), false, ""},
		{"compact serialization", []byte(p + "." + pl + "." + s), false, ""},
		{"unprotected header", []byte(`{"protected":"` + p + `","payload":"` + pl + `","signature":"` + s + `","header":{"kid":"` + account + `"}}`), false, "unknown object member name"},
		{"general serialization", []byte(`{"payload":"` + pl + `","signatures":[{"protected":"` + p + `","signature":"` + s + `"}]}`), false, "unknown object member name"},
		{"unknown member", []byte(`{"protected":"` + p + `","payload":"` + pl + `","signature":"` + s + `","x":1}`), false, "unknown object member name"},
		{"duplicate member", []byte(`{"protected":"` + p + `","payload":"` + pl + `","payload":"` + pl + `","signature":"` + s + `"}`), false, "duplicate object member name"},
		{"missing protected", []byte(`{"payload":"` + pl + `","signature":"` + s + `"}`), false, ""},

		// Protected header.
		{"protected is not JSON", sign(t, sk44, "hello", payload), false, ""},
		{"protected is not an object", sign(t, sk44, `"alg"`, payload), false, ""},
		{"protected with invalid UTF-8", sign(t, sk44, "{\"alg\":\"ML-DSA-44\",\"kid\":\"\xff\"}", payload), false, "invalid UTF-8"},
		{"duplicate header parameter", sign(t, sk44, `{"alg":"ML-DSA-44","alg":"ML-DSA-44","kid":"k"}`, payload), false, "duplicate object member name"},
		{"crit header parameter", sign(t, sk44, `{"alg":"ML-DSA-44","kid":"k","crit":["url"],"url":"u"}`, payload), false, "unknown object member name"},
		{"b64 header parameter", sign(t, sk44, `{"alg":"ML-DSA-44","kid":"k","b64":false}`, payload), false, "unknown object member name"},
		{"typ header parameter", sign(t, sk44, `{"alg":"ML-DSA-44","kid":"k","typ":"JOSE"}`, payload), false, "unknown object member name"},
		{"alg none", sign(t, sk44, kidHeader("none"), payload), false, "unsupported algorithm: none"},
		{"alg ES256", sign(t, sk44, kidHeader("ES256"), payload), false, "unsupported algorithm: ES256"},
		{"alg lowercase", sign(t, sk44, kidHeader("ml-dsa-44"), payload), false, "unsupported algorithm"},
		{"alg missing", sign(t, sk44, `{"kid":"k"}`, payload), false, "unsupported algorithm"},
		{"alg does not match key", sign(t, sk44, kidHeader("ML-DSA-65"), payload), false, "do not match"},
		{"kid missing", sign(t, sk44, `{"alg":"ML-DSA-44","nonce":"n","url":"u"}`, payload), false, "KID is required"},
		{"kid empty", sign(t, sk44, `{"alg":"ML-DSA-44","kid":"","nonce":"n","url":"u"}`, payload), false, "KID is required"},
		{"kid and jwk", sign(t, sk44, `{"alg":"ML-DSA-44","kid":"k","jwk":`+jwk44+`}`, payload), false, "JWK is not allowed"},
		{"kid and jwk (VerifyWithJWK)", sign(t, sk44, `{"alg":"ML-DSA-44","kid":"k","jwk":`+jwk44+`}`, payload), true, "KID is not allowed"},
		{"jwk missing (VerifyWithJWK)", sign(t, sk44, kidHeader("ML-DSA-44"), payload), true, "JWK is required"},
		{"jwk null (VerifyWithJWK)", sign(t, sk44, `{"alg":"ML-DSA-44","jwk":null}`, payload), true, "JWK is required"},

		// Embedded JWK.
		{"jwk kty EC", sign(t, sk44, jwkHeader("ML-DSA-44", strings.Replace(jwk44, `"kty":"AKP"`, `"kty":"EC"`, 1)), payload), true, "KTY must be AKP"},
		{"jwk kty missing", sign(t, sk44, jwkHeader("ML-DSA-44", strings.Replace(jwk44, `"kty":"AKP",`, "", 1)), payload), true, "KTY must be AKP"},
		{"jwk alg missing", sign(t, sk44, jwkHeader("ML-DSA-44", strings.Replace(jwk44, `"alg":"ML-DSA-44",`, "", 1)), payload), true, "alg must match"},
		{"jwk alg does not match header", sign(t, sk44, jwkHeader("ML-DSA-44", publicJWK(v65)), payload), true, "alg must match"},
		{"jwk alg does not match key size", sign(t, sk44, jwkHeader("ML-DSA-65", strings.Replace(jwk44, "ML-DSA-44", "ML-DSA-65", 1)), payload), true, "invalid public key"},
		{"jwk alg unsupported", sign(t, sk44, jwkHeader("ES256", strings.Replace(jwk44, "ML-DSA-44", "ES256", 1)), payload), true, "unsupported algorithm: ES256"},
		{"jwk pub missing", sign(t, sk44, jwkHeader("ML-DSA-44", `{"kty":"AKP","alg":"ML-DSA-44"}`), payload), true, "invalid public key"},
		{"jwk pub short", sign(t, sk44, jwkHeader("ML-DSA-44", `{"kty":"AKP","alg":"ML-DSA-44","pub":"AAAA"}`), payload), true, "invalid public key"},
		{"jwk pub padded", sign(t, sk44, jwkHeader("ML-DSA-44", strings.Replace(jwk44, v44.JWK.Pub, v44.JWK.Pub+"==", 1)), payload), true, "illegal base64"},
		{"jwk pub tampered", sign(t, sk44, jwkHeader("ML-DSA-44", `{"kty":"AKP","alg":"ML-DSA-44","pub":"`+b64(string(tamperedPub))+`"}`), payload), true, "invalid signature"},
		{"jwk with priv", sign(t, sk44, jwkHeader("ML-DSA-44", withMember(jwk44, `"priv":"`+v44.JWK.Priv+`"`)), payload), true, "unknown object member name"},
		{"jwk with use", sign(t, sk44, jwkHeader("ML-DSA-44", withMember(jwk44, `"use":"sig"`)), payload), true, "unknown object member name"},
		{"jwk with key_ops", sign(t, sk44, jwkHeader("ML-DSA-44", withMember(jwk44, `"key_ops":["sign"]`)), payload), true, "unknown object member name"},
		{"jwk with x5c", sign(t, sk44, jwkHeader("ML-DSA-44", withMember(jwk44, `"x5c":[]`)), payload), true, "unknown object member name"},
		{"jwk signed by another key", sign(t, sk65, jwkHeader("ML-DSA-44", jwk44), payload), true, "invalid signature"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.jwk {
				_, err = jws.VerifyWithJWK(tt.body)
			} else {
				_, err = jws.Verify(tt.body, pub44)
			}
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}

func TestErrorTypes(t *testing.T) {
	v44, sk44 := loadVector(t, mldsa.MLDSA44())
	_, err := jws.Verify(sign(t, sk44, `{"alg":"ES256","kid":"k"}`, ""), sk44.PublicKey())
	var unsupported *jws.UnsupportedAlgorithmError
	if !errors.As(err, &unsupported) || unsupported.Alg != "ES256" {
		t.Errorf("Verify returned %v, want UnsupportedAlgorithmError for ES256", err)
	}

	_, err = jws.VerifyWithJWK(sign(t, sk44, `{"alg":"ML-DSA-44","jwk":{"kty":"AKP","alg":"ML-DSA-44","pub":"AAAA"}}`, ""))
	var invalidKey *jws.InvalidPublicKeyError
	if !errors.As(err, &invalidKey) || invalidKey.Unwrap() == nil {
		t.Errorf("VerifyWithJWK returned %v, want InvalidPublicKeyError", err)
	}

	_, err = jws.VerifyWithJWK(sign(t, sk44, `{"alg":"ML-DSA-44","jwk":`+publicJWK(v44)+`}`, ""))
	if err != nil {
		t.Errorf("VerifyWithJWK: %v", err)
	}
}

// TestJWKThumbprint checks the thumbprint against the kid values of the RFC 9964
// examples, which per Appendix A are the JWK Thumbprints of the keys.
func TestJWKThumbprint(t *testing.T) {
	for _, params := range allParams {
		t.Run(params.String(), func(t *testing.T) {
			v, sk := loadVector(t, params)
			got, err := jws.JWKThumbprint(sk.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			if got != v.JWK.KID {
				t.Errorf("thumbprint %q, want %q", got, v.JWK.KID)
			}
		})
	}
}

// TestPeekKID checks that PeekKID extracts the kid without verifying the
// signature, so that callers can look up the account key before Verify.
func TestPeekKID(t *testing.T) {
	v44, sk44 := loadVector(t, mldsa.MLDSA44())
	const account = "https://example.com/acme/acct/evOfKhNU60wg"
	p, pl, s := signParts(t, sk44, `{"alg":"ML-DSA-44","kid":"`+account+`","nonce":"n","url":"u"}`, "{}")

	corrupted := []byte(s)
	corrupted[len(corrupted)/2] ^= 1
	kid, err := jws.PeekKID(flattened(p, pl, string(corrupted)))
	if err != nil || kid != account {
		t.Errorf("PeekKID on a corrupted signature returned %q, %v", kid, err)
	}
	kid, err = jws.PeekKID(flattened(p, pl, ""))
	if err != nil || kid != account {
		t.Errorf("PeekKID on an empty signature returned %q, %v", kid, err)
	}

	for _, tt := range []struct {
		name string
		body []byte
		want string
	}{
		{"jwk", sign(t, sk44, `{"alg":"ML-DSA-44","jwk":`+publicJWK(v44)+`}`, ""), "JWK is not allowed"},
		{"kid and jwk", sign(t, sk44, `{"alg":"ML-DSA-44","kid":"k","jwk":`+publicJWK(v44)+`}`, ""), "JWK is not allowed"},
		{"kid missing", sign(t, sk44, `{"alg":"ML-DSA-44"}`, ""), "KID is required"},
		{"kid empty", sign(t, sk44, `{"alg":"ML-DSA-44","kid":""}`, ""), "KID is required"},
		{"unknown header parameter", sign(t, sk44, `{"alg":"ML-DSA-44","kid":"k","typ":"JOSE"}`, ""), "unknown object member name"},
		{"invalid body", []byte("{"), ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			kid, err := jws.PeekKID(tt.body)
			if err == nil {
				t.Fatalf("accepted, returned %q", kid)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
		})
	}
}
