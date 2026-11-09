package ca

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net/http"
	"slices"
	"time"

	"geomys.org/magnolia/internal/acmeerrors"
	"geomys.org/magnolia/internal/lockstep"
)

func (ca *CA) handleFinalize(payload []byte, r *http.Request) (*response, acmeerrors.Error) {
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, acmeerrors.New("malformed", 400, "invalid JSON payload")
	}
	ord, err := ca.loadOrder(r.PathValue("order"), r)
	if err != nil {
		return nil, err
	}
	if status, _, _ := ord.status(); status != "ready" {
		return nil, acmeerrors.New("orderNotReady", 403, "order is %s, not ready", status)
	}
	acct, err := ca.accounts.get(r.Context(), ord.account)
	if err != nil {
		return nil, err
	}
	pub, err := verifyCSR(ord, req.CSR, acct.key)
	if err != nil {
		return nil, err
	}

	// A ready order stops being ready only by being finalized, so it's enough
	// to check that no other request started finalizing it in the meantime.
	issuedAt := time.Now()
	ord.mu.Lock()
	if !ord.issuedAt.IsZero() || ord.err != nil {
		ord.mu.Unlock()
		return nil, acmeerrors.New("orderNotReady", 403, "order is already being finalized")
	}
	ord.issuedAt = issuedAt
	ord.mu.Unlock()

	// TODO: EvidenceLeaf, a minimal record of the authorizations.
	evidence := []byte(ca.orderURL(ord))
	index, err := ca.issuer.issue(r.Context(), pub, ord.dnsIdentifiers, issuedAt, evidence)

	ord.mu.Lock()
	switch {
	case errors.Is(err, lockstep.ErrPoolFull):
		// The entry was not added, so the order can be finalized again.
		ord.issuedAt = time.Time{}
	case err != nil:
		ord.err = err
	default:
		ord.index = index
	}
	ord.mu.Unlock()
	if err != nil {
		return nil, err
	}

	return respond(200, ca.renderOrder(ord)).
		WithHeader("Location", ca.orderURL(ord)), nil
}

// verifyCSR checks that the base64url-encoded CSR is validly signed by an
// ML-DSA key other than the account key, and requests exactly the order's
// identifiers. It returns the CSR's public key.
func verifyCSR(ord *order, b64 string, accountKey *mldsa.PublicKey) (*mldsa.PublicKey, acmeerrors.Error) {
	der, err := base64.RawURLEncoding.Strict().DecodeString(b64)
	// The decoder ignores CR and LF, even in strict mode.
	if err != nil || len(b64) != base64.RawURLEncoding.EncodedLen(len(der)) {
		return nil, acmeerrors.New("badCSR", 400, "CSR is not valid base64url")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, acmeerrors.New("badCSR", 400, "couldn't parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, acmeerrors.New("badCSR", 400, "invalid CSR signature: %w", err)
	}
	pub, ok := csr.PublicKey.(*mldsa.PublicKey)
	if !ok {
		return nil, acmeerrors.New("badCSR", 400, "CSR public key is not ML-DSA")
	}
	if pub.Equal(accountKey) {
		return nil, acmeerrors.New("badCSR", 400, "CSR public key must not be the account key")
	}
	if len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 {
		return nil, acmeerrors.New("badCSR", 400, "CSR must only request DNS names")
	}
	if cn := csr.Subject.CommonName; cn != "" && !slices.Contains(csr.DNSNames, cn) {
		return nil, acmeerrors.New("badCSR", 400, "CSR common name %q is not one of its DNS names", cn)
	}
	got := slices.Compact(slices.Sorted(slices.Values(csr.DNSNames)))
	want := slices.Sorted(slices.Values(ord.dnsIdentifiers))
	if !slices.Equal(got, want) {
		return nil, acmeerrors.New("badCSR", 400, "CSR names %q don't match the order identifiers %q", got, want)
	}
	return pub, nil
}
