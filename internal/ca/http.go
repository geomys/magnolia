package ca

import (
	"context"
	"crypto/mldsa"
	"encoding/json/v2"
	"io"
	"mime"
	"net/http"

	"geomys.org/magnolia/internal/acmeerrors"
	"geomys.org/magnolia/internal/jws"
)

func (ca *CA) Handler() http.Handler {
	postPrefix := "POST " + ca.writePrefix.Path
	getPrefix := "GET " + ca.writePrefix.Path
	mux := http.NewServeMux()
	mux.Handle(postPrefix+"/directory", acmeMiddleware(ca, ca.handleDirectory, withKID))
	mux.Handle(getPrefix+"/directory", plainGETMiddleware(ca, ca.handleDirectory))
	mux.Handle(postPrefix+"/nonce", acmeMiddleware(ca, ca.handleNewNonce, withKID))
	mux.Handle(getPrefix+"/nonce", plainGETMiddleware(ca, ca.handleNewNonce))
	return http.MaxBytesHandler(mux, 1<<16) // 64 KiB
}

type acmeHandler func(w http.ResponseWriter, payload []byte, r *http.Request) (any, acmeerrors.Error)

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
			p, ok := ca.accounts.Load(kid)
			if !ok {
				writeError(w, acmeerrors.New("accountDoesNotExist", 400, "unknown account"))
				return
			}
			pub = p.(*mldsa.PublicKey)
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
		resp, err := next(w, j.Payload, r)
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
		resp, err := next(w, nil, r)
		if err != nil {
			writeError(w, err)
			return
		}
		writeResponse(w, resp)
	})
}

func writeResponse(w http.ResponseWriter, resp any) {
	if resp == nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	out, err := json.Marshal(resp)
	if err != nil {
		writeError(w, acmeerrors.Internal("failed to encode response: %w", err))
		return
	}
	w.Write(out)
}

func writeError(w http.ResponseWriter, err acmeerrors.Error) {
	// TODO: check if headers have already been written before.
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Del("Content-Length")
	w.Header().Del("Cache-Control")
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
