// Package caconfig implements the configuration file of magnolia-ca, which is
// also used by magnolia-keygen to create the keys and logs, and by
// magnolia-read-path to serve them.
package caconfig

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"time"

	"filippo.io/torchwood"
	"geomys.org/magnolia/internal/durable"
	"geomys.org/magnolia/internal/immutable"
	"golang.org/x/crypto/hkdf"
	"gopkg.in/yaml.v3"
)

// Config is the YAML configuration file of magnolia-ca and
// magnolia-read-path. Keys are the lowercase field names, such as
// "writeprefix".
type Config struct {
	// Listen are the addresses magnolia-ca listens on, e.g. ":443".
	Listen []string

	// ReadListen are the addresses magnolia-read-path listens on, e.g. ":443".
	ReadListen []string

	// ACME configures how the CA automatically obtains certificates for its
	// HTTPS endpoints. Optional. If missing, the CA will listen for plain HTTP
	// or h2c.
	ACME struct {
		// Cache is the path to the directory where keys and certificates will
		// be stored. It will be created if it doesn't already exist.
		Cache string

		// Directory is an ACME directory URL to request a certificate from.
		// Defaults to Let's Encrypt Production. Optional.
		Directory string
	}

	// WritePrefix is the full URL of the ACME endpoints, such as
	// "https://acme.example.com", without a trailing slash. The ACME
	// directory is served at WritePrefix + "/directory". See doc/urls.md.
	//
	// If the ACME client is enabled, the CA will obtain a certificate for the
	// host of this URL.
	WritePrefix string

	// Accounts is the path to the SQLite database of ACME accounts.
	// magnolia-keygen creates it if it doesn't exist.
	Accounts string

	// NonceKey is the path to the PEM file of the key used to issue and verify
	// ACME nonces. magnolia-keygen creates it if it doesn't exist.
	NonceKey string

	// NameLists is the path to the directory where the list of top-level
	// domains, the Public Suffix List, and the special-purpose address
	// registries are cached. It will be created if it doesn't already exist.
	NameLists string

	// NoNameLimit disables the limit of 10 identifiers per order.
	// It is meant for experiments.
	NoNameLimit bool

	Issuer IssuerConfig
}

type IssuerConfig struct {
	// CAID is the CA ID, such as "66252.1". The CA cosigner is named
	// "oid/1.3.6.1.4.1." + CAID, and the issuance log origin is
	// "oid/1.3.6.1.4.1." + CAID + ".0.1".
	CAID string

	// EvidenceOrigin is the origin of the evidence log, as a schema-less URL,
	// such as "read.example.com/66252.1/evidence/1".
	EvidenceOrigin string

	// ReadPrefix is the full URL of the read path of this issuer, such as
	// "https://read.example.com/66252.1", without a trailing slash.
	// Certificate URLs are under it, and the issuance log is served at
	// ReadPrefix + "/issuance/1". See doc/urls.md.
	ReadPrefix string

	// CAVerifierKey and EvidenceVerifierKey are the verifier keys of the CA
	// cosigner and of the evidence log, as printed by magnolia-keygen. They
	// are required by magnolia-read-path, which doesn't read the Seed. If
	// set, magnolia-ca and magnolia-keygen check that they match the Seed.
	CAVerifierKey       string
	EvidenceVerifierKey string

	// NotBefore is the UTC date the Seed was generated, such as "2026-11-11".
	// It is the notBefore of the CA certificate served by magnolia-read-path,
	// which requires it.
	NotBefore string

	// Seed is the path to the PEM file of the secret seed from which the
	// private keys of the CA cosigner and of the evidence log are derived.
	// The file is bound to the CA ID. magnolia-keygen creates it if it
	// doesn't exist.
	Seed string

	// Lock is the path to the SQLite database that stores the latest
	// checkpoints of the logs. magnolia-keygen creates it if it doesn't exist.
	Lock string

	// LocalDirectory is the path to a local directory where the logs and
	// certificates will be stored. It must be dedicated to this issuer. It
	// will be created if it doesn't already exist.
	LocalDirectory string

	// Period is the time between sequence operations, as milliseconds.
	//
	// Defaults to 1000 milliseconds (1 second).
	Period int

	// PoolSize is the maximum number of entries pending in the sequencing
	// pool. If the pool is full, finalize requests are rejected with a 503.
	// Since the pool is sequenced every Period, it works as a qps limit. Zero
	// means no limit.
	PoolSize int
}

// Load reads and parses a configuration file. Unknown keys are rejected.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	d.KnownFields(true)
	c := &Config{}
	if err := d.Decode(c); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return c, nil
}

const (
	issuerSeedType = "MAGNOLIA ISSUER SEED"
	nonceKeyType   = "MAGNOLIA NONCE KEY"
	caIDHeader     = "CA-ID"
)

// GenerateIssuerSeed creates a new issuer seed file for the CA ID.
// It fails if the file already exists.
func GenerateIssuerSeed(path, caID string) error {
	return writeNewPEM(path, &pem.Block{
		Type:    issuerSeedType,
		Headers: map[string]string{caIDHeader: caID},
		Bytes:   randomKey(),
	})
}

// GenerateNonceKey creates a new nonce key file.
// It fails if the file already exists.
func GenerateNonceKey(path string) error {
	return writeNewPEM(path, &pem.Block{
		Type:  nonceKeyType,
		Bytes: randomKey(),
	})
}

func randomKey() []byte {
	k := make([]byte, 32)
	rand.Read(k)
	return k
}

// ReadNonceKey reads a nonce key file created by [GenerateNonceKey].
func ReadNonceKey(path string) ([]byte, error) {
	return readPEM(path, nonceKeyType, map[string]string{})
}

func readIssuerSeed(path, caID string) ([]byte, error) {
	return readPEM(path, issuerSeedType, map[string]string{caIDHeader: caID})
}

func readPEM(path, typ string, headers map[string]string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, rest := pem.Decode(data)
	switch {
	case b == nil:
		return nil, fmt.Errorf("%s: not a PEM file", path)
	case len(bytes.TrimSpace(rest)) != 0:
		return nil, fmt.Errorf("%s: trailing data after PEM block", path)
	case b.Type != typ:
		return nil, fmt.Errorf("%s: PEM type is %q, expected %q", path, b.Type, typ)
	case !maps.Equal(b.Headers, headers):
		return nil, fmt.Errorf("%s: PEM headers are %v, expected %v", path, b.Headers, headers)
	case len(b.Bytes) != 32:
		return nil, fmt.Errorf("%s: key is %d bytes, expected 32", path, len(b.Bytes))
	}
	return b.Bytes, nil
}

// writeNewPEM durably creates a new read-only, immutable file.
func writeNewPEM(path string, b *pem.Block) error {
	if err := durable.CreateFile(path, pem.EncodeToMemory(b), 0o400); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	immutable.Set(f)
	return f.Close()
}

// IssuanceOrigin returns the origin of issuance log 1 of the CA.
func (c *IssuerConfig) IssuanceOrigin() string {
	return "oid/1.3.6.1.4.1." + c.CAID + ".0.1"
}

// SequencingPeriod returns Period as a duration, or its default.
func (c *IssuerConfig) SequencingPeriod() time.Duration {
	if c.Period <= 0 {
		return 1 * time.Second
	}
	return time.Duration(c.Period) * time.Millisecond
}

// NotBeforeDate returns NotBefore as a time, at midnight UTC.
func (c *IssuerConfig) NotBeforeDate() (time.Time, error) {
	if c.NotBefore == "" {
		return time.Time{}, errors.New("missing NotBefore")
	}
	t, err := time.Parse(time.DateOnly, c.NotBefore)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid NotBefore: %w", err)
	}
	return t, nil
}

// Verifiers returns the verifiers of the CA cosigner and of the evidence log,
// from CAVerifierKey and EvidenceVerifierKey.
func (c *IssuerConfig) Verifiers() (caCosigner, evidenceLog *torchwood.CosignatureVerifier, err error) {
	caCosigner, err = parseVerifierKey("CAVerifierKey", c.CAVerifierKey, "oid/1.3.6.1.4.1."+c.CAID)
	if err != nil {
		return nil, nil, err
	}
	evidenceLog, err = parseVerifierKey("EvidenceVerifierKey", c.EvidenceVerifierKey, c.EvidenceOrigin)
	if err != nil {
		return nil, nil, err
	}
	return caCosigner, evidenceLog, nil
}

// parseVerifierKey parses the verifier key in the named field, which must be
// for a cosigner with the given name.
func parseVerifierKey(field, vkey, name string) (*torchwood.CosignatureVerifier, error) {
	if vkey == "" {
		return nil, fmt.Errorf("missing %s", field)
	}
	v, err := torchwood.NewCosignatureVerifier(vkey)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", field, err)
	}
	if v.Name() != name {
		return nil, fmt.Errorf("%s is for %q, expected %q", field, v.Name(), name)
	}
	return v, nil
}

// Signers reads the issuer seed, and returns the CA cosigner and the evidence
// log signer derived from it. If CAVerifierKey or EvidenceVerifierKey are set,
// they must match them.
func (c *IssuerConfig) Signers() (caCosigner, evidenceLog *torchwood.CosignatureSigner, err error) {
	switch {
	case c.CAID == "":
		return nil, nil, errors.New("missing CAID")
	case c.EvidenceOrigin == "":
		return nil, nil, errors.New("missing EvidenceOrigin")
	}
	seed, err := readIssuerSeed(c.Seed, c.CAID)
	if err != nil {
		return nil, nil, err
	}
	caCosigner, err = cosignatureSigner(seed, "magnolia ML-DSA-44 CA cosigner key", "oid/1.3.6.1.4.1."+c.CAID)
	if err != nil {
		return nil, nil, err
	}
	evidenceLog, err = cosignatureSigner(seed, "magnolia ML-DSA-44 evidence log key", c.EvidenceOrigin)
	if err != nil {
		return nil, nil, err
	}
	if err := checkVerifierKey("CAVerifierKey", c.CAVerifierKey, caCosigner); err != nil {
		return nil, nil, err
	}
	if err := checkVerifierKey("EvidenceVerifierKey", c.EvidenceVerifierKey, evidenceLog); err != nil {
		return nil, nil, err
	}
	return caCosigner, evidenceLog, nil
}

// checkVerifierKey checks that the verifier key in the named field, if set, is
// the one of signer.
func checkVerifierKey(field, vkey string, signer *torchwood.CosignatureSigner) error {
	if vkey == "" {
		return nil
	}
	want := signer.Verifier()
	v, err := parseVerifierKey(field, vkey, want.Name())
	if err != nil {
		return err
	}
	if v.String() != want.String() {
		return fmt.Errorf("%s doesn't match the seed, expected %s", field, want)
	}
	return nil
}

// cosignatureSigner derives an ML-DSA-44 key from seed, and returns a
// c2sp.org/tlog-cosignature signer for it named name.
func cosignatureSigner(seed []byte, label, name string) (*torchwood.CosignatureSigner, error) {
	secret := make([]byte, mldsa.PrivateKeySize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, seed, []byte(label), []byte(name)), secret); err != nil {
		return nil, err
	}
	k, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), secret)
	if err != nil {
		return nil, err
	}
	return torchwood.NewCosignatureSigner(name, k)
}
