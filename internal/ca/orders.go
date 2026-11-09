package ca

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"geomys.org/magnolia/internal/acmeerrors"
	"geomys.org/magnolia/internal/mtc"
)

type order struct {
	id             string
	account        string
	created        time.Time
	dnsIdentifiers []string // with "*." prefix for wildcards

	// mu protects err, issuedAt, index, token, and the contents of authz.
	// len(authz) and copies of authz elements don't require holding mu.
	mu       sync.Mutex
	err      acmeerrors.Error
	issuedAt time.Time // set when finalization starts
	index    int64     // != 0 once the order is valid
	token    string    // random token in the certificate path
	authz    []authz   // one per dnsIdentifier
}

type authz struct {
	token        string
	selectedType string
	started      time.Time
	validated    time.Time
	err          acmeerrors.Error
}

type issuedCert struct {
	notAfter time.Time
	index    int64
	token    string
}

// status returns the order's status and, if valid, the issued certificate,
// or if invalid, the associated error.
func (ord *order) status() (status string, cert *issuedCert, err acmeerrors.Error) {
	ord.mu.Lock()
	defer ord.mu.Unlock()

	if ord.err != nil {
		return "invalid", nil, ord.err
	}
	if ord.index != 0 {
		_, notAfter := mtc.Validity(ord.issuedAt)
		return "valid", &issuedCert{notAfter: notAfter, index: ord.index, token: ord.token}, nil
	}
	if !ord.issuedAt.IsZero() {
		return "processing", nil, nil
	}

	status = "ready"
	for _, a := range ord.authz {
		switch a.authzStatus() {
		case "pending":
			status = "pending"
		case "valid":
		case "invalid":
			return "invalid", nil, acmeerrors.New("unauthorized", 400, "authorization failed, check challenge for details")
		}
	}
	return status, nil, nil
}

func (ord *order) expiry() time.Time {
	return ord.created.Add(3 * time.Hour)
}

func (a *authz) authzStatus() string {
	status := a.challStatus()
	if status == "processing" {
		return "pending"
	}
	return status
}

func (a *authz) challStatus() string {
	switch {
	case a.token == "",
		a.selectedType == "" && !a.started.IsZero(),
		a.selectedType != "" && a.started.IsZero(),
		a.started.IsZero() && !a.validated.IsZero(),
		a.started.IsZero() && a.err != nil,
		!a.validated.IsZero() && a.err != nil:
		panic("challenge is in an inconsistent state")
	case a.err != nil:
		return "invalid"
	case !a.validated.IsZero():
		return "valid"
	case !a.started.IsZero():
		return "processing"
	default:
		return "pending"
	}
}

func (ca *CA) orderURL(ord *order) string {
	return fmt.Sprintf("%s/order/%s", ca.writePrefix.String(), ord.id)
}

func (ca *CA) authzURL(ord *order, i int) string {
	return fmt.Sprintf("%s/order/%s/authz/%d", ca.writePrefix.String(), ord.id, i)
}

func (ca *CA) challengeURL(ord *order, i int, challengeType string) string {
	return fmt.Sprintf("%s/order/%s/authz/%d/challenge/%s", ca.writePrefix.String(), ord.id, i, challengeType)
}

func (ca *CA) certificateURL(cert *issuedCert) string {
	return fmt.Sprintf("%s/certificate/%s/%s/%d-%s", ca.writePrefix.String(), ca.issuer.logID, cert.notAfter.Format(time.DateOnly), cert.index, cert.token)
}

func (ca *CA) renderOrder(ord *order) map[string]any {
	status, cert, ordErr := ord.status()

	j := map[string]any{
		"status":   status,
		"expires":  ord.expiry().UTC().Format(time.RFC3339),
		"finalize": ca.orderURL(ord) + "/finalize",
	}

	authzURLs := make([]string, 0, len(ord.authz))
	for i := range ord.authz {
		authzURLs = append(authzURLs, ca.authzURL(ord, i))
	}
	j["authorizations"] = authzURLs

	ids := make([]map[string]string, 0, len(ord.dnsIdentifiers))
	for _, id := range ord.dnsIdentifiers {
		ids = append(ids, map[string]string{
			"type":  "dns",
			"value": id,
		})
	}
	j["identifiers"] = ids

	if ordErr != nil {
		j["error"] = acmeerrors.Render(ordErr)
	}
	if cert != nil {
		j["certificate"] = ca.certificateURL(cert)
	}

	return j
}

func (ca *CA) renderAuthz(ord *order, i int) map[string]any {
	ord.mu.Lock()
	authz := ord.authz[i]
	ord.mu.Unlock()

	id, isWildcard := strings.CutPrefix(ord.dnsIdentifiers[i], "*.")
	j := map[string]any{
		"status":  authz.authzStatus(),
		"expires": ord.expiry().UTC().Format(time.RFC3339),
		"identifier": map[string]string{
			"type":  "dns",
			"value": id,
		},
	}
	if isWildcard {
		j["wildcard"] = true
	}

	switch {
	case authz.selectedType != "":
		j["challenges"] = []map[string]any{ca.renderChallenge(ord, i, authz, authz.selectedType)}
	case !isWildcard:
		j["challenges"] = []map[string]any{ca.renderChallenge(ord, i, authz, "http-01")}
	default:
		// TODO: we don't support wildcard challenges yet.
		j["challenges"] = []map[string]any{}
	}

	return j
}

func (ca *CA) renderChallenge(ord *order, i int, authz authz, challengeType string) map[string]any {
	c := map[string]any{
		"type":   challengeType,
		"status": authz.challStatus(),
		"url":    ca.challengeURL(ord, i, challengeType),
		"token":  authz.token,
	}
	if !authz.validated.IsZero() {
		c["validated"] = authz.validated.UTC().Format(time.RFC3339)
	}
	if authz.err != nil {
		c["error"] = acmeerrors.Render(authz.err)
	}
	return c
}
