// Package jws implements JSON Web Signature (JWS, RFC 7515) verification only,
// specifically the profile necessary for ACME (RFC 8555) with ML-DSA signatures
// (RFC 9964).
package jws

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"

	"geomys.org/magnolia/internal/acmeerrors"
)

var jsonOptions = json.JoinOptions(
	json.RejectUnknownMembers(true),
	jsonOptionFormatBase64URL,
)

// jsonOptionFormatBase64URL is a JSON option that decodes byte slices with raw
// Base64url. It also rejects explicit null tokens. This can be replaced with
// format:base64url once implemented. See https://go.dev/issue/79071.
var jsonOptionFormatBase64URL = json.WithUnmarshalers(json.UnmarshalFromFunc(func(dec *jsontext.Decoder, b *[]byte) error {
	val, err := dec.ReadValue()
	if err != nil {
		return err
	}
	if k := val.Kind(); k != jsontext.KindString {
		return errors.New("expected string for base64url-encoded value, got " + k.String())
	}
	s, err := jsontext.AppendUnquote(nil, val)
	if err != nil {
		return err
	}
	out, err := base64.RawURLEncoding.AppendDecode((*b)[:0], s)
	if err != nil {
		return err
	}
	if len(s) != base64.RawURLEncoding.EncodedLen(len(out)) {
		i := bytes.IndexAny(s, "\r\n")
		return fmt.Errorf("illegal character %q at offset %d", s[i], i)
	}
	if out == nil {
		out = []byte{}
	}
	*b = out
	return nil
}))

type flattenedJWS struct {
	Payload   []byte `json:"payload"`
	Protected []byte `json:"protected"`
	Signature []byte `json:"signature"`
}

type header struct {
	Alg   string    `json:"alg"`
	Nonce string    `json:"nonce"`
	URL   string    `json:"url"`
	JWK   *mldsaJWK `json:"jwk"`
	KID   string    `json:"kid"`
}

// mldsaJWK represents a JSON Web Key for the ML-DSA algorithm.
// See RFC 7517 and RFC 9964.
type mldsaJWK struct {
	KID string `json:"kid"` // ignored but allowed
	KTY string `json:"kty"` // must be "AKP"
	Alg string `json:"alg"` // "ML-DSA-44", "ML-DSA-65", or "ML-DSA-87"
	Pub []byte `json:"pub"`
}

// Unverified is a parsed JWS whose signature has not been checked yet.
// Callers select the key with KID or JWK, and then call Verify.
type Unverified struct {
	protected []byte
	payload   []byte
	signature []byte

	params mldsa.Parameters
	nonce  string
	url    string
	kid    string
	jwk    *mldsa.PublicKey
}

// Parse decodes a JWS in the Flattened JSON Serialization.
// Exactly one of "kid" and "jwk" must be present.
func Parse(jws []byte) (*Unverified, acmeerrors.Error) {
	var f flattenedJWS
	if err := json.Unmarshal(jws, &f, jsonOptions); err != nil {
		return nil, acmeerrors.New("malformed", 400, "failed to parse JSON:", err.Error())
	}
	var h header
	if err := json.Unmarshal([]byte(f.Protected), &h, jsonOptions); err != nil {
		return nil, acmeerrors.New("malformed", 400, "failed to parse header:", err.Error())
	}
	if h.JWK != nil && h.KID != "" {
		return nil, acmeerrors.New("malformed", 400, "KID and JWK are mutually exclusive")
	}
	if h.JWK == nil && h.KID == "" {
		return nil, acmeerrors.New("malformed", 400, "KID or JWK is required")
	}
	params, err := algToParameters(h.Alg)
	if err != nil {
		return nil, err
	}
	u := &Unverified{
		protected: f.Protected,
		payload:   f.Payload,
		signature: f.Signature,
		params:    params,
		nonce:     h.Nonce,
		url:       h.URL,
		kid:       h.KID,
	}
	if h.JWK != nil {
		if h.JWK.KTY != "AKP" {
			return nil, acmeerrors.New("badPublicKey", 400, "JWK KTY must be AKP")
		}
		if h.JWK.Alg != h.Alg {
			return nil, acmeerrors.New("badPublicKey", 400, "JWK alg must match protected header alg")
		}
		pub, err := mldsa.NewPublicKey(params, h.JWK.Pub)
		if err != nil {
			return nil, acmeerrors.New("badPublicKey", 400, "invalid public key:", err.Error())
		}
		u.jwk = pub
	}
	return u, nil
}

// KID returns the "kid" header parameter, or an error if the JWS carries an
// embedded JWK instead.
func (u *Unverified) KID() (string, acmeerrors.Error) {
	if u.kid == "" {
		return "", acmeerrors.New("malformed", 400, "KID is required in this context")
	}
	return u.kid, nil
}

// JWK returns the public key from the "jwk" header parameter, or an error if
// the JWS carries a "kid" instead.
func (u *Unverified) JWK() (*mldsa.PublicKey, acmeerrors.Error) {
	if u.jwk == nil {
		return nil, acmeerrors.New("malformed", 400, "JWK is required in this context")
	}
	return u.jwk, nil
}

// JWS is a verified JWS.
type JWS struct {
	Nonce   string // base64url-encoded
	URL     string
	Payload []byte
}

// Verify checks the signature with pub. If the JWS carries an embedded JWK,
// pub must be that key.
func (u *Unverified) Verify(pub *mldsa.PublicKey) (*JWS, acmeerrors.Error) {
	if u.jwk != nil && !u.jwk.Equal(pub) {
		return nil, acmeerrors.Internal("public key does not match embedded JWK")
	}
	if pub.Parameters() != u.params {
		return nil, acmeerrors.New("malformed", 400, "alg and key parameters do not match")
	}
	var signed []byte
	signed = append(signed, base64.RawURLEncoding.EncodeToString(u.protected)...)
	signed = append(signed, '.')
	signed = append(signed, base64.RawURLEncoding.EncodeToString(u.payload)...)
	if err := mldsa.Verify(pub, signed, u.signature, nil); err != nil {
		return nil, acmeerrors.New("unauthorized", 403, "signature verification failed:", err.Error())
	}
	return &JWS{
		Nonce:   u.nonce,
		URL:     u.url,
		Payload: u.payload,
	}, nil
}

func algToParameters(alg string) (mldsa.Parameters, acmeerrors.Error) {
	switch alg {
	case "ML-DSA-44":
		return mldsa.MLDSA44(), nil
	case "ML-DSA-65":
		return mldsa.MLDSA65(), nil
	case "ML-DSA-87":
		return mldsa.MLDSA87(), nil
	default:
		err := acmeerrors.New("badSignatureAlgorithm", 400, "unsupported algorithm:", alg)
		err = err.WithField("algorithms", []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
		return mldsa.Parameters{}, err
	}
}

// JWKThumbprint computes the base64url-encoded SHA-256 JWK Thumbprint of a
// public key according to RFC 7638 and RFC 9964.
func JWKThumbprint(pub *mldsa.PublicKey) (string, error) {
	h := sha256.New()
	h.Write([]byte(`{"alg":"`))
	switch pub.Parameters() {
	case mldsa.MLDSA44():
		h.Write([]byte(`ML-DSA-44`))
	case mldsa.MLDSA65():
		h.Write([]byte(`ML-DSA-65`))
	case mldsa.MLDSA87():
		h.Write([]byte(`ML-DSA-87`))
	default:
		return "", errors.New("unsupported algorithm")
	}
	h.Write([]byte(`","kty":"AKP","pub":"`))
	h.Write([]byte(base64.RawURLEncoding.EncodeToString(pub.Bytes())))
	h.Write([]byte(`"}`))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}
