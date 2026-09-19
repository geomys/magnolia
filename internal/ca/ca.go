package ca

import (
	"crypto/mldsa"
	"crypto/rand"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"geomys.org/magnolia/internal/acmeerrors"
	"geomys.org/magnolia/internal/jws"
	"geomys.org/magnolia/internal/nonce"
)

type CA struct {
	// writePrefix is the absolute URL prefix of the ACME endpoints, without a
	// trailing slash, such as "https://ca.example.com/acme".
	writePrefix *url.URL
	nonceIssuer *nonce.Issuer
	nonceSpent  *nonce.Spent
	accounts    *accountStore
}

type Config struct {
	WritePrefix string // e.g. "https://ca.example.com/acme"
	NonceKey    []byte // 32 bytes
	Accounts    string // SQLite database path; created if it doesn't exist
}

func New(config Config) (*CA, error) {
	u, err := url.Parse(config.WritePrefix)
	if err != nil {
		return nil, err
	}
	switch {
	case u.Scheme != "https":
		return nil, errors.New("WritePrefix must be an https URL")
	case u.Host == "":
		return nil, errors.New("WritePrefix must have a host")
	case u.RawQuery != "" || u.Fragment != "" || u.User != nil:
		return nil, errors.New("WritePrefix must not have a query, fragment, or userinfo")
	case strings.HasSuffix(u.Path, "/"):
		return nil, errors.New("WritePrefix must not have a trailing slash")
	}
	issuer, err := nonce.NewIssuer(config.NonceKey)
	if err != nil {
		return nil, err
	}
	accounts, err := openAccountStore(config.Accounts)
	if err != nil {
		return nil, err
	}
	return &CA{
		writePrefix: u,
		nonceIssuer: issuer,
		nonceSpent:  nonce.NewSpent(issuer, 300_000),
		accounts:    accounts,
	}, nil
}

func (ca *CA) Close() error {
	return ca.accounts.Close()
}

func (ca *CA) Handler() http.Handler {
	postPrefix := "POST " + ca.writePrefix.Path
	getPrefix := "GET " + ca.writePrefix.Path
	mux := http.NewServeMux()

	mux.Handle(postPrefix+"/directory", acmeMiddleware(ca, ca.handleDirectory, withKID))
	mux.Handle(getPrefix+"/directory", plainGETMiddleware(ca, ca.handleDirectory))

	mux.Handle(postPrefix+"/nonce", acmeMiddleware(ca, ca.handleNewNonce, withKID))
	mux.Handle(getPrefix+"/nonce", plainGETMiddleware(ca, ca.handleNewNonce))

	mux.Handle(postPrefix+"/new-account", acmeMiddleware(ca, ca.handleNewAccount, withJWK))
	mux.Handle(postPrefix+"/account/", acmeMiddleware(ca, ca.handleAccountUpdate, withKID))
	mux.Handle(postPrefix+"/key-change", acmeMiddleware(ca, ca.handleKeyChange, withKID))

	return http.MaxBytesHandler(mux, 1<<16) // 64 KiB
}

func (ca *CA) handleDirectory(w http.ResponseWriter, payload []byte, r *http.Request) (int, any, acmeerrors.Error) {
	if len(payload) != 0 {
		return 0, nil, acmeerrors.New("malformed", 400, "unexpected payload for directory request")
	}
	return 200, map[string]string{
		rand.Text():  "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
		"newNonce":   ca.writePrefix.String() + "/nonce",
		"newAccount": ca.writePrefix.String() + "/new-account",
		"keyChange":  ca.writePrefix.String() + "/key-change",
	}, nil
}

func (ca *CA) handleNewNonce(w http.ResponseWriter, payload []byte, r *http.Request) (int, any, acmeerrors.Error) {
	if len(payload) != 0 {
		return 0, nil, acmeerrors.New("malformed", 400, "unexpected payload for new nonce request")
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		return 204, nil, nil
	}
	return 200, nil, nil
}

func (ca *CA) handleNewAccount(w http.ResponseWriter, payload []byte, r *http.Request) (int, any, acmeerrors.Error) {
	var req struct {
		OnlyExisting bool `json:"onlyReturnExisting"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return 0, nil, acmeerrors.New("malformed", 400, "invalid JSON payload")
	}
	pub := r.Context().Value(jwkContextKey).(*mldsa.PublicKey)
	if req.OnlyExisting {
		acct, err := ca.accounts.lookup(r.Context(), pub)
		if err != nil {
			return 0, nil, err
		}
		return ca.newAccountExists(w, acct)
	}
	kid := ca.writePrefix.String() + "/account/" + rand.Text()
	acct, created, err := ca.accounts.create(r.Context(), pub, kid)
	if err != nil {
		return 0, nil, err
	}
	if !created {
		return ca.newAccountExists(w, acct)
	}
	w.Header().Set("Location", acct.kid)
	return 201, map[string]string{
		"status": "valid",
	}, nil
}

func (ca *CA) newAccountExists(w http.ResponseWriter, acct *account) (int, any, acmeerrors.Error) {
	if acct.deactivated {
		return 0, nil, acmeerrors.New("unauthorized", 401, "account is deactivated")
	}
	w.Header().Set("Location", acct.kid)
	return 200, map[string]string{
		"status": "valid",
	}, nil
}

func (ca *CA) handleAccountUpdate(w http.ResponseWriter, payload []byte, r *http.Request) (int, any, acmeerrors.Error) {
	kid := r.Context().Value(kidContextKey).(string)
	reqURL := ca.writePrefix.Scheme + "://" + ca.writePrefix.Host + r.URL.RequestURI()
	if kid != reqURL {
		return 0, nil, acmeerrors.New("unauthorized", 403, "KID does not match request URL")
	}
	if len(payload) == 0 {
		return 200, map[string]string{
			"status": "valid",
		}, nil
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return 0, nil, acmeerrors.New("malformed", 400, "invalid JSON payload")
	}
	if req.Status == "deactivated" {
		if err := ca.accounts.deactivate(r.Context(), kid); err != nil {
			return 0, nil, err
		}
		return 200, map[string]string{
			"status": "deactivated",
		}, nil
	}
	return 200, map[string]string{
		"status": "valid",
	}, nil
}

func (ca *CA) handleKeyChange(w http.ResponseWriter, payload []byte, r *http.Request) (int, any, acmeerrors.Error) {
	kid := r.Context().Value(kidContextKey).(string)
	reqURL := ca.writePrefix.Scheme + "://" + ca.writePrefix.Host + r.URL.RequestURI()
	u, err := jws.Parse(payload)
	if err != nil {
		return 0, nil, err
	}
	newKey, err := u.JWK()
	if err != nil {
		return 0, nil, err
	}
	j, err := u.Verify(newKey)
	if err != nil {
		return 0, nil, err
	}
	if j.Nonce != "" {
		return 0, nil, acmeerrors.New("malformed", 400, "unexpected nonce in key change request")
	}
	if j.URL != reqURL {
		return 0, nil, acmeerrors.New("malformed", 400, "inner JWS URL does not match request URL")
	}
	var keyChange struct {
		Account string         `json:"account"`
		OldKey  jsontext.Value `json:"oldKey"`
	}
	if err := json.Unmarshal(j.Payload, &keyChange); err != nil {
		return 0, nil, acmeerrors.New("malformed", 400, "invalid JSON payload")
	}
	if keyChange.Account != kid {
		return 0, nil, acmeerrors.New("unauthorized", 403, "account in key change request does not match KID")
	}
	oldKey, err := jws.ParseJWK(keyChange.OldKey)
	if err != nil {
		return 0, nil, err
	}
	if err := ca.accounts.rekey(r.Context(), kid, oldKey, newKey); err != nil {
		return 0, nil, err
	}
	return 200, map[string]string{
		"status": "valid",
	}, nil
}
