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

func PeekKID(jws []byte) (string, error) {
	var f flattenedJWS
	if err := json.Unmarshal(jws, &f, jsonOptions); err != nil {
		return "", err
	}
	var h header
	if err := json.Unmarshal([]byte(f.Protected), &h, jsonOptions); err != nil {
		return "", err
	}
	if h.JWK != nil {
		return "", errors.New("JWK is not allowed in this context")
	}
	if h.KID == "" {
		return "", errors.New("KID is required in this context")
	}
	return h.KID, nil
}

type JWS struct {
	Nonce   string // base64url-encoded
	URL     string
	Payload []byte
}

type UnsupportedAlgorithmError struct {
	Alg string
}

func (e *UnsupportedAlgorithmError) Error() string {
	return "unsupported algorithm: " + e.Alg
}

func Verify(jws []byte, pub *mldsa.PublicKey) (*JWS, error) {
	var f flattenedJWS
	if err := json.Unmarshal(jws, &f, jsonOptions); err != nil {
		return nil, err
	}
	var h header
	if err := json.Unmarshal([]byte(f.Protected), &h, jsonOptions); err != nil {
		return nil, err
	}
	if h.JWK != nil {
		return nil, errors.New("JWK is not allowed in this context")
	}
	if h.KID == "" {
		return nil, errors.New("KID is required in this context")
	}
	params, err := algToParameters(h.Alg)
	if err != nil {
		return nil, err
	}
	if pub.Parameters() != params {
		return nil, errors.New("public key parameters do not match algorithm")
	}
	var signed []byte
	signed = append(signed, base64.RawURLEncoding.EncodeToString(f.Protected)...)
	signed = append(signed, '.')
	signed = append(signed, base64.RawURLEncoding.EncodeToString(f.Payload)...)
	if err := mldsa.Verify(pub, signed, f.Signature, nil); err != nil {
		return nil, err
	}
	return &JWS{
		Nonce:   h.Nonce,
		URL:     h.URL,
		Payload: f.Payload,
	}, nil
}

func algToParameters(alg string) (mldsa.Parameters, error) {
	switch alg {
	case "ML-DSA-44":
		return mldsa.MLDSA44(), nil
	case "ML-DSA-65":
		return mldsa.MLDSA65(), nil
	case "ML-DSA-87":
		return mldsa.MLDSA87(), nil
	default:
		return mldsa.Parameters{}, &UnsupportedAlgorithmError{Alg: alg}
	}
}

type JWSWithPublicKey struct {
	PublicKey *mldsa.PublicKey
	Nonce     string // base64url-encoded
	URL       string
	Payload   []byte
}

type InvalidPublicKeyError struct {
	Err error
}

func (e *InvalidPublicKeyError) Error() string {
	return "invalid public key: " + e.Err.Error()
}

func (e *InvalidPublicKeyError) Unwrap() error {
	return e.Err
}

func VerifyWithJWK(jws []byte) (*JWSWithPublicKey, error) {
	var f flattenedJWS
	if err := json.Unmarshal(jws, &f, jsonOptions); err != nil {
		return nil, err
	}
	var h header
	if err := json.Unmarshal([]byte(f.Protected), &h, jsonOptions); err != nil {
		return nil, err
	}
	if h.JWK == nil {
		return nil, errors.New("JWK is required in this context")
	}
	if h.KID != "" {
		return nil, errors.New("KID is not allowed in this context")
	}
	params, err := algToParameters(h.Alg)
	if err != nil {
		return nil, err
	}
	if h.JWK.KTY != "AKP" {
		return nil, errors.New("JWK KTY must be AKP")
	}
	if h.JWK.Alg != h.Alg {
		return nil, errors.New("JWK alg must match protected header alg")
	}
	pub, err := mldsa.NewPublicKey(params, h.JWK.Pub)
	if err != nil {
		return nil, &InvalidPublicKeyError{Err: err}
	}
	var signed []byte
	signed = append(signed, base64.RawURLEncoding.EncodeToString(f.Protected)...)
	signed = append(signed, '.')
	signed = append(signed, base64.RawURLEncoding.EncodeToString(f.Payload)...)
	if err := mldsa.Verify(pub, signed, f.Signature, nil); err != nil {
		return nil, err
	}
	return &JWSWithPublicKey{
		PublicKey: pub,
		Nonce:     h.Nonce,
		URL:       h.URL,
		Payload:   f.Payload,
	}, nil
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
