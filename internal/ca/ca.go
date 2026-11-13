package ca

import (
	"crypto/mldsa"
	"crypto/rand"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"geomys.org/magnolia/internal/acmeerrors"
	"geomys.org/magnolia/internal/jws"
	"geomys.org/magnolia/internal/nonce"
)

type CA struct {
	// writePrefix is the absolute URL prefix of the ACME endpoints, without a
	// trailing slash, such as "https://acme.example.com".
	writePrefix *url.URL
	nonceIssuer *nonce.Issuer
	nonceSpent  *nonce.Spent
	accounts    *accountStore
	orders      sync.Map // id string => *[order]
	issuer      *Issuer
}

type Config struct {
	WritePrefix string  // e.g. "https://acme.example.com"
	NonceKey    []byte  // 32 bytes
	Accounts    string  // SQLite database path, created with [CreateAccounts]
	Issuer      *Issuer // MTC CA, must run [Issuer.RunSequencer] separately
}

func New(config Config) (*CA, error) {
	u, err := parsePrefix("WritePrefix", config.WritePrefix)
	if err != nil {
		return nil, err
	}
	if config.Issuer == nil {
		return nil, errors.New("missing Issuer")
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
		issuer:      config.Issuer,
	}, nil
}

// parsePrefix parses an absolute https URL prefix without a trailing slash.
func parsePrefix(name, prefix string) (*url.URL, error) {
	u, err := url.Parse(prefix)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", name, err)
	}
	switch {
	case u.Scheme != "https":
		return nil, fmt.Errorf("%s must be an https URL", name)
	case u.Host == "":
		return nil, fmt.Errorf("%s must have a host", name)
	case u.RawQuery != "" || u.Fragment != "" || u.User != nil:
		return nil, fmt.Errorf("%s must not have a query, fragment, or userinfo", name)
	case strings.HasSuffix(u.Path, "/"):
		return nil, fmt.Errorf("%s must not have a trailing slash", name)
	}
	return u, nil
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

	mux.Handle(postPrefix+"/new-order", acmeMiddleware(ca, ca.handleNewOrder, withKID))
	mux.Handle(postPrefix+"/order/{order}", acmeMiddleware(ca, ca.handleOrder, withKID))
	mux.Handle(postPrefix+"/order/{order}/finalize", acmeMiddleware(ca, ca.handleFinalize, withKID))
	mux.Handle(postPrefix+"/order/{order}/authz/{i}", acmeMiddleware(ca, ca.handleAuthz, withKID))
	mux.Handle(postPrefix+"/order/{order}/authz/{i}/challenge/{type}", acmeMiddleware(ca, ca.handleChallenge, withKID))

	return http.MaxBytesHandler(mux, 1<<16) // 64 KiB
}

func (ca *CA) handleDirectory(payload []byte, r *http.Request) (*response, acmeerrors.Error) {
	if len(payload) != 0 {
		return nil, acmeerrors.New("malformed", 400, "unexpected payload for directory request")
	}
	return respond(200, map[string]string{
		rand.Text():  "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417",
		"newNonce":   ca.writePrefix.String() + "/nonce",
		"newAccount": ca.writePrefix.String() + "/new-account",
		"keyChange":  ca.writePrefix.String() + "/key-change",
		"newOrder":   ca.writePrefix.String() + "/new-order",
	}), nil
}

func (ca *CA) handleNewNonce(payload []byte, r *http.Request) (*response, acmeerrors.Error) {
	if len(payload) != 0 {
		return nil, acmeerrors.New("malformed", 400, "unexpected payload for new nonce request")
	}
	status := 200
	if r.Method == http.MethodGet {
		status = 204
	}
	return respond(status, nil).WithHeader("Cache-Control", "no-store"), nil
}

func (ca *CA) handleNewAccount(payload []byte, r *http.Request) (*response, acmeerrors.Error) {
	var req struct {
		OnlyExisting bool `json:"onlyReturnExisting"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, acmeerrors.New("malformed", 400, "invalid JSON payload")
	}
	pub := r.Context().Value(jwkContextKey).(*mldsa.PublicKey)
	if req.OnlyExisting {
		acct, err := ca.accounts.lookup(r.Context(), pub)
		if err != nil {
			return nil, err
		}
		return newAccountExists(acct)
	}
	kid := ca.writePrefix.String() + "/account/" + rand.Text()
	acct, created, err := ca.accounts.create(r.Context(), pub, kid)
	if err != nil {
		return nil, err
	}
	if !created {
		return newAccountExists(acct)
	}
	return respond(201, map[string]string{
		"status": "valid",
	}).WithHeader("Location", acct.kid), nil
}

func newAccountExists(acct *account) (*response, acmeerrors.Error) {
	if acct.deactivated {
		return nil, acmeerrors.New("unauthorized", 401, "account is deactivated")
	}
	return respond(200, map[string]string{
		"status": "valid",
	}).WithHeader("Location", acct.kid), nil
}

func (ca *CA) handleAccountUpdate(payload []byte, r *http.Request) (*response, acmeerrors.Error) {
	kid := r.Context().Value(kidContextKey).(string)
	reqURL := ca.writePrefix.Scheme + "://" + ca.writePrefix.Host + r.URL.RequestURI()
	if kid != reqURL {
		return nil, acmeerrors.New("unauthorized", 403, "KID does not match request URL")
	}
	if len(payload) == 0 {
		return respond(200, map[string]string{
			"status": "valid",
		}), nil
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, acmeerrors.New("malformed", 400, "invalid JSON payload")
	}
	if req.Status == "deactivated" {
		if err := ca.accounts.deactivate(r.Context(), kid); err != nil {
			return nil, err
		}
		return respond(200, map[string]string{
			"status": "deactivated",
		}), nil
	}
	return respond(200, map[string]string{
		"status": "valid",
	}), nil
}

func (ca *CA) handleKeyChange(payload []byte, r *http.Request) (*response, acmeerrors.Error) {
	kid := r.Context().Value(kidContextKey).(string)
	reqURL := ca.writePrefix.Scheme + "://" + ca.writePrefix.Host + r.URL.RequestURI()
	u, err := jws.Parse(payload)
	if err != nil {
		return nil, err
	}
	newKey, err := u.JWK()
	if err != nil {
		return nil, err
	}
	j, err := u.Verify(newKey)
	if err != nil {
		return nil, err
	}
	if j.Nonce != "" {
		return nil, acmeerrors.New("malformed", 400, "unexpected nonce in key change request")
	}
	if j.URL != reqURL {
		return nil, acmeerrors.New("malformed", 400, "inner JWS URL does not match request URL")
	}
	var keyChange struct {
		Account string         `json:"account"`
		OldKey  jsontext.Value `json:"oldKey"`
	}
	if err := json.Unmarshal(j.Payload, &keyChange); err != nil {
		return nil, acmeerrors.New("malformed", 400, "invalid JSON payload")
	}
	if keyChange.Account != kid {
		return nil, acmeerrors.New("unauthorized", 403, "account in key change request does not match KID")
	}
	oldKey, err := jws.ParseJWK(keyChange.OldKey)
	if err != nil {
		return nil, err
	}
	if err := ca.accounts.rekey(r.Context(), kid, oldKey, newKey); err != nil {
		return nil, err
	}
	return respond(200, map[string]string{
		"status": "valid",
	}), nil
}

func (ca *CA) handleNewOrder(payload []byte, r *http.Request) (*response, acmeerrors.Error) {
	var req struct {
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
		NotBefore *jsontext.Value `json:"notBefore"`
		NotAfter  *jsontext.Value `json:"notAfter"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, acmeerrors.New("malformed", 400, "invalid JSON payload")
	}
	if req.NotBefore != nil {
		return nil, acmeerrors.Custom("unsupportedField", 400, "notBefore not supported in order requests")
	}
	if req.NotAfter != nil {
		return nil, acmeerrors.Custom("unsupportedField", 400, "notAfter not supported in order requests")
	}

	if len(req.Identifiers) == 0 {
		return nil, acmeerrors.New("malformed", 400, "order must include at least one identifier")
	}

	ord := &order{
		id:      rand.Text(),
		account: r.Context().Value(kidContextKey).(string),
		created: time.Now(),

		dnsIdentifiers: make([]string, 0, len(req.Identifiers)),
		authz:          make([]authz, 0, len(req.Identifiers)),
	}
	seen := make(map[string]bool)
	for _, id := range req.Identifiers {
		if id.Type != "dns" {
			return nil, acmeerrors.New("unsupportedIdentifier", 400, "only dns identifiers are supported")
		}
		if seen[id.Value] {
			return nil, acmeerrors.New("malformed", 400, "duplicate identifier %s", id.Value)
		}
		seen[id.Value] = true
		// TODO: validate the identifier!
		// TODO: limit the number and length of identifiers, to bound the size
		// of the log entry, which can't exceed 65535 bytes.
		ord.dnsIdentifiers = append(ord.dnsIdentifiers, id.Value)
		ord.authz = append(ord.authz, authz{token: rand.Text()})
	}
	res := ca.renderOrder(ord)

	ca.orders.Store(ord.id, ord)
	time.AfterFunc(time.Until(ord.expiry()), func() { ca.orders.Delete(ord.id) })

	return respond(201, res).WithHeader("Location", ca.orderURL(ord)), nil
}

func (ca *CA) loadOrder(id string, r *http.Request) (*order, acmeerrors.Error) {
	ordAny, ok := ca.orders.Load(id)
	if !ok {
		return nil, acmeerrors.Custom("orderNotFound", 404, "order does not exist or is expired")
	}
	ord := ordAny.(*order)
	if ord.expiry().Before(time.Now()) {
		return nil, acmeerrors.Custom("orderNotFound", 404, "order does not exist or is expired")
	}
	if ord.account != r.Context().Value(kidContextKey).(string) {
		return nil, acmeerrors.New("unauthorized", 403, "order is not owned by this account")
	}
	return ord, nil
}

func (ca *CA) handleOrder(payload []byte, r *http.Request) (*response, acmeerrors.Error) {
	if len(payload) != 0 {
		return nil, acmeerrors.New("malformed", 400, "unexpected payload for order request")
	}
	ord, err := ca.loadOrder(r.PathValue("order"), r)
	if err != nil {
		return nil, err
	}
	return respond(200, ca.renderOrder(ord)), nil
}

func (ca *CA) handleAuthz(payload []byte, r *http.Request) (*response, acmeerrors.Error) {
	if len(payload) != 0 {
		return nil, acmeerrors.New("malformed", 400, "unexpected payload for authz request")
	}
	ord, err := ca.loadOrder(r.PathValue("order"), r)
	if err != nil {
		return nil, err
	}
	i, err := authzIndex(ord, r.PathValue("i"))
	if err != nil {
		return nil, err
	}
	return respond(200, ca.renderAuthz(ord, i)), nil
}

func authzIndex(ord *order, s string) (int, acmeerrors.Error) {
	i, err := strconv.Atoi(s)
	if err != nil || strconv.Itoa(i) != s || i < 0 {
		return 0, acmeerrors.Custom("authzNotFound", 404, "authz URL is invalid")
	}
	if i >= len(ord.authz) {
		return 0, acmeerrors.Custom("authzNotFound", 404, "authz does not exist")
	}
	return i, nil
}

func (ca *CA) handleChallenge(payload []byte, r *http.Request) (*response, acmeerrors.Error) {
	if len(payload) != 0 {
		if v := jsontext.Value(payload); !v.IsValid() || v.Kind() != jsontext.KindBeginObject {
			return nil, acmeerrors.New("malformed", 400, "challenge payload must be a JSON object")
		}
	}
	ord, err := ca.loadOrder(r.PathValue("order"), r)
	if err != nil {
		return nil, err
	}
	i, err := authzIndex(ord, r.PathValue("i"))
	if err != nil {
		return nil, err
	}
	typ := r.PathValue("type")
	if typ != "http-01" || strings.HasPrefix(ord.dnsIdentifiers[i], "*.") {
		return nil, acmeerrors.Custom("challengeNotFound", 404, "challenge does not exist")
	}

	ord.mu.Lock()
	authz := ord.authz[i]
	if len(payload) != 0 && authz.selectedType == "" {
		// For now, we don't have a VA, so we immediately mark the challenge as
		// validated for testing and prototyping. FIXME!
		now := time.Now()
		authz.selectedType = typ
		authz.started = now
		authz.validated = now
		ord.authz[i] = authz
	}
	ord.mu.Unlock()

	if authz.selectedType != "" && authz.selectedType != typ {
		return nil, acmeerrors.Custom("challengeNotFound", 404, "challenge does not exist")
	}

	return respond(200, ca.renderChallenge(ord, i, authz, typ)).
		WithHeader("Link", `<`+ca.authzURL(ord, i)+`>;rel="up"`), nil
}
