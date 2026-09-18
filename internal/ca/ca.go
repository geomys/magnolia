package ca

import (
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"geomys.org/magnolia/internal/acmeerrors"
	"geomys.org/magnolia/internal/nonce"
)

type CA struct {
	// writePrefix is the absolute URL prefix of the ACME endpoints, without a
	// trailing slash, such as "https://ca.example.com/acme".
	writePrefix *url.URL
	nonceIssuer *nonce.Issuer
	nonceSpent  *nonce.Spent

	accounts sync.Map // kid string => *mldsa.PublicKey
}

type Config struct {
	WritePrefix string // e.g. "https://ca.example.com/acme"
	NonceKey    []byte // 32 bytes
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
	return &CA{
		writePrefix: u,
		nonceIssuer: issuer,
		nonceSpent:  nonce.NewSpent(issuer, 300_000),
	}, nil
}

func (ca *CA) handleDirectory(w http.ResponseWriter, payload []byte, r *http.Request) (any, acmeerrors.Error) {
	if len(payload) != 0 {
		return nil, acmeerrors.New("malformed", 400, "unexpected payload for directory request")
	}
	return map[string]string{
		rand.Text(): "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
		"newNonce":  ca.writePrefix.String() + "/nonce",
	}, nil
}

func (ca *CA) handleNewNonce(w http.ResponseWriter, payload []byte, r *http.Request) (any, acmeerrors.Error) {
	if len(payload) != 0 {
		return nil, acmeerrors.New("malformed", 400, "unexpected payload for new nonce request")
	}
	w.Header().Set("Cache-Control", "no-store")
	// RFC 8555, Section 7.2: HEAD responds with 200, GET with 204.
	if r.Method == http.MethodGet {
		w.WriteHeader(http.StatusNoContent)
	}
	return nil, nil
}
