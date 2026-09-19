package ca

import (
	"context"
	"crypto/mldsa"
	"encoding/json/v2"
	"io"
	"maps"
	"mime"
	"net/http"

	"geomys.org/magnolia/internal/acmeerrors"
	"geomys.org/magnolia/internal/jws"
)

// acmeHandler processes a verified request and returns the response, or an
// error to send as a problem document.
type acmeHandler func(payload []byte, r *http.Request) (*response, acmeerrors.Error)

// response is a successful ACME response.
type response struct {
	status  int
	body    any // JSON-encoded, or nil for an empty body
	headers map[string]string
}

// respond returns a response with a 2xx status.
func respond(status int, body any) *response {
	if status < 200 || status > 299 {
		panic("respond: status must be 2xx, errors are acmeerrors.Error values")
	}
	return &response{status: status, body: body}
}

// WithHeader returns a copy of the response with an additional header.
func (r *response) WithHeader(key, value string) *response {
	q := *r
	q.headers = maps.Clone(r.headers)
	if q.headers == nil {
		q.headers = make(map[string]string)
	}
	q.headers[key] = value
	return &q
}

const withKID = true
const withJWK = false

type contextKey string

const kidContextKey contextKey = "kid"
const jwkContextKey contextKey = "jwk"

func acmeMiddleware(ca *CA, next acmeHandler, useKID bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Replay-Nonce", ca.nonceIssuer.Mint())
		w.Header().Set("Link", `<`+ca.writePrefix.String()+`/directory>;rel="index"`)
		mediatype, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mediatype != "application/jose+json" {
			writeError(w, acmeerrors.New("malformed", 415, "invalid Content-Type"))
			return
		}
		body, readErr := io.ReadAll(r.Body)
		if _, ok := readErr.(*http.MaxBytesError); ok {
			writeError(w, acmeerrors.New("malformed", 413, "request body too large"))
			return
		} else if readErr != nil {
			// If the body can't be read, writing a response is futile.
			w.WriteHeader(400)
			return
		}
		u, err := jws.Parse(body)
		if err != nil {
			writeError(w, err)
			return
		}
		var pub *mldsa.PublicKey
		if useKID {
			kid, err := u.KID()
			if err != nil {
				writeError(w, err)
				return
			}
			acct, err := ca.accounts.get(r.Context(), kid)
			if err != nil {
				writeError(w, err)
				return
			}
			pub = acct.key
			r = r.WithContext(context.WithValue(r.Context(), kidContextKey, kid))
		} else {
			pub, err = u.JWK()
			if err != nil {
				writeError(w, err)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), jwkContextKey, pub))
		}
		j, err := u.Verify(pub)
		if err != nil {
			writeError(w, err)
			return
		}
		reqURL := ca.writePrefix.Scheme + "://" + ca.writePrefix.Host + r.URL.RequestURI()
		if j.URL != reqURL {
			writeError(w, acmeerrors.New("unauthorized", 403, "JWS header url mismatch"))
			return
		}
		if err := ca.nonceSpent.Spend(j.Nonce); err != nil {
			writeError(w, err)
			return
		}
		resp, err := next(j.Payload, r)
		if err != nil {
			writeError(w, err)
			return
		}
		writeResponse(w, resp)
	})
}

func plainGETMiddleware(ca *CA, next acmeHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Replay-Nonce", ca.nonceIssuer.Mint())
		w.Header().Set("Link", `<`+ca.writePrefix.String()+`/directory>;rel="index"`)
		resp, err := next(nil, r)
		if err != nil {
			writeError(w, err)
			return
		}
		writeResponse(w, resp)
	})
}

func writeResponse(w http.ResponseWriter, resp *response) {
	if resp.body == nil {
		for k, v := range resp.headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(resp.status)
		return
	}
	out, err := json.Marshal(resp.body)
	if err != nil {
		writeError(w, acmeerrors.Internal("failed to encode response: %w", err))
		return
	}
	for k, v := range resp.headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.status)
	w.Write(out)
}

func writeError(w http.ResponseWriter, err acmeerrors.Error) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	for k, v := range err.Headers() {
		w.Header().Set(k, v)
	}
	w.WriteHeader(err.Status())
	fields := map[string]any{
		"type":   err.Type(),
		"detail": err.Detail(),
	}
	for k, v := range err.Fields() {
		fields[k] = v
	}
	json.MarshalWrite(w, fields)
}
