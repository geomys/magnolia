// Package lint lints Magnolia certificates with zlint.
package lint

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"text/template"

	"geomys.org/magnolia/internal/mtc"
	zx509 "github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3"
	zlintlint "github.com/zmap/zlint/v3/lint"
	"golang.org/x/mod/sumdb/tlog"
)

// ignored are the lints that don't apply to MTCs or to the profile,
// with the reasons listed in doc/profile.md.
var ignored = map[string]bool{
	// id-alg-mtcProof is not a BRs signature algorithm, but CQRP allows it.
	"e_signature_algorithm_not_supported": true,
	// The BRs only list RSA and ECDSA key encodings, but CQRP allows ML-DSA.
	"e_algorithm_identifier_improper_encoding": true,
	// AIA is a SHOULD since SC-104.
	"e_sub_cert_aia_missing": true,
	// AIA is a SHOULD since SC-104.
	"w_sub_cert_aia_does_not_contain_issuing_ca_url": true,
	// The BRs don't recommend it.
	"w_ext_subject_key_identifier_missing_sub_cert": true,
	// MTCs have no SCTs.
	"n_ct_sct_policy_count_unsatisfied": true,
}

// A Linter lints certificates with zlint, skipping the lints listed in
// doc/profile.md. Any result other than pass, NA, or NE is a failure.
//
// A Linter is safe for concurrent use.
type Linter struct {
	registry    zlintlint.Registry
	preIssuance bool
}

// PreIssuance returns a Linter for TBSCertificates before their entry is added
// to the log, as returned by [mtc.TBSCertificate]. Lint builds the certificate
// with [mtc.PlaceholderProof].
func PreIssuance() (*Linter, error) {
	return newLinter(config{}, true)
}

// A Cosigner is a cosigner whose signatures standalone certificates must carry.
type Cosigner struct {
	ID  mtc.TrustAnchorID
	Key *mldsa.PublicKey
}

// Standalone returns a Linter for standalone certificates, which must carry
// valid cosignatures from all the given cosigners.
func Standalone(cosigners []Cosigner) (*Linter, error) {
	if len(cosigners) == 0 {
		return nil, errors.New("no cosigners")
	}
	c := config{Mode: "standalone"}
	for _, cosigner := range cosigners {
		if cosigner.ID == (mtc.TrustAnchorID{}) || cosigner.Key == nil {
			return nil, errors.New("missing cosigner ID or key")
		}
		spki, err := x509.MarshalPKIXPublicKey(cosigner.Key)
		if err != nil {
			return nil, fmt.Errorf("cosigner %v: %w", cosigner.ID, err)
		}
		c.Cosigners = append(c.Cosigners, configCosigner{
			ID:        cosigner.ID.String(),
			PublicKey: base64.StdEncoding.EncodeToString(spki),
		})
	}
	return newLinter(c, false)
}

// A Subtree is a landmark subtree.
type Subtree struct {
	Start, End int64
	Hash       tlog.Hash
}

// Landmark returns a Linter for landmark-relative certificates of one
// landmark, whose two landmark subtrees (draft-ietf-plants-merkle-tree-certs-07,
// Section 6.4.1) are given.
func Landmark(subtrees [2]Subtree) (*Linter, error) {
	c := config{Mode: "landmark"}
	for _, s := range subtrees {
		c.Subtrees = append(c.Subtrees, configSubtree{
			Start: s.Start, End: s.End, Hash: hex.EncodeToString(s.Hash[:]),
		})
	}
	return newLinter(c, false)
}

// config is the configuration of e_mtc_proof_verifies.
type config struct {
	Mode      string
	Cosigners []configCosigner
	Subtrees  []configSubtree
}

type configCosigner struct {
	ID        string // ASCII representation
	PublicKey string // base64-encoded SubjectPublicKeyInfo
}

type configSubtree struct {
	Start, End int64
	Hash       string // hex-encoded
}

// configTemplate renders a [config] as TOML. The values are digits, dots,
// base64, and hex, so they need no escaping.
var configTemplate = template.Must(template.New("config").Parse(`[e_mtc_proof_verifies]
Mode = "{{.Mode}}"
{{range .Cosigners}}
[[e_mtc_proof_verifies.Cosigners]]
ID = "{{.ID}}"
PublicKey = "{{.PublicKey}}"
Required = true
{{end}}
{{- range .Subtrees}}
[[e_mtc_proof_verifies.Subtrees]]
Start = {{.Start}}
End = {{.End}}
Hash = "{{.Hash}}"
{{end}}`))

func newLinter(c config, preIssuance bool) (*Linter, error) {
	// Filter fails if any excluded name is not a registered lint, which
	// catches lints renamed or removed by zlint updates.
	registry, err := zlintlint.GlobalRegistry().Filter(zlintlint.FilterOptions{
		ExcludeNames: slices.Sorted(maps.Keys(ignored)),
		ExcludeSources: []zlintlint.LintSource{
			// Magnolia doesn't issue EV certificates.
			zlintlint.CABFEVGuidelines,
			// Magnolia doesn't use the ETSI EN 319 412-5 qcStatements extension.
			zlintlint.EtsiEsi,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("filtering zlint registry: %w", err)
	}
	var toml strings.Builder
	if err := configTemplate.Execute(&toml, c); err != nil {
		return nil, fmt.Errorf("rendering zlint configuration: %w", err)
	}
	zc, err := zlintlint.NewConfigFromString(toml.String())
	if err != nil {
		return nil, fmt.Errorf("parsing zlint configuration: %w", err)
	}
	registry.SetConfiguration(zc)
	return &Linter{registry: registry, preIssuance: preIssuance}, nil
}

// Lint lints der, which is a TBSCertificate for a [PreIssuance] Linter and a
// Certificate otherwise. It returns an [*Error] if any lint fails.
func (l *Linter) Lint(der []byte) error {
	if l.preIssuance {
		cert, err := mtc.Certificate(der, mtc.PlaceholderProof())
		if err != nil {
			return fmt.Errorf("building placeholder certificate: %w", err)
		}
		der = cert
	}
	cert, err := zx509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}
	rs := zlint.LintCertificateEx(cert, l.registry)
	var failed []Result
	for name, r := range rs.Results {
		switch r.Status {
		case zlintlint.Pass, zlintlint.NA, zlintlint.NE:
			continue
		}
		failed = append(failed, Result{Name: name, Status: r.Status.String(), Details: r.Details})
	}
	if len(failed) == 0 {
		return nil
	}
	slices.SortFunc(failed, func(a, b Result) int { return strings.Compare(a.Name, b.Name) })
	return &Error{Results: failed}
}

// An Error lists the lints that failed.
type Error struct {
	Results []Result
}

// A Result is the result of a failed lint.
type Result struct {
	Name    string
	Status  string
	Details string
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("failed lints: ")
	for i, r := range e.Results {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s (%s", r.Name, r.Status)
		if r.Details != "" {
			fmt.Fprintf(&b, ": %s", r.Details)
		}
		b.WriteString(")")
	}
	return b.String()
}
