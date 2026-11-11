package caconfig

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKeyFiles(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.pem")
	noncePath := filepath.Join(dir, "nonce.pem")

	if err := GenerateIssuerSeed(seedPath, "66252.99999.1"); err != nil {
		t.Fatal(err)
	}
	if err := GenerateNonceKey(noncePath); err != nil {
		t.Fatal(err)
	}
	if err := GenerateIssuerSeed(seedPath, "66252.99999.1"); !errors.Is(err, fs.ErrExist) {
		t.Errorf("GenerateIssuerSeed over existing file: got %v, want ErrExist", err)
	}
	if err := GenerateNonceKey(noncePath); !errors.Is(err, fs.ErrExist) {
		t.Errorf("GenerateNonceKey over existing file: got %v, want ErrExist", err)
	}

	pemData, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(pemData), "-----BEGIN MAGNOLIA ISSUER SEED-----\nCA-ID: 66252.99999.1\n\n") {
		t.Errorf("unexpected issuer seed file:\n%s", pemData)
	}

	seed, err := readIssuerSeed(seedPath, "66252.99999.1")
	if err != nil {
		t.Fatal(err)
	}
	nonceKey, err := ReadNonceKey(noncePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 32 || len(nonceKey) != 32 || string(seed) == string(nonceKey) {
		t.Errorf("unexpected keys %x and %x", seed, nonceKey)
	}

	if _, err := readIssuerSeed(seedPath, "66252.99999.2"); err == nil {
		t.Error("issuer seed read with the wrong CA ID")
	}
	if _, err := readIssuerSeed(noncePath, "66252.99999.1"); err == nil {
		t.Error("nonce key read as issuer seed")
	}
	if _, err := ReadNonceKey(seedPath); err == nil {
		t.Error("issuer seed read as nonce key")
	}

	for name, contents := range map[string]string{
		"raw":      strings.Repeat("A", 32),
		"trailing": string(pemData) + "x",
		"short":    "-----BEGIN MAGNOLIA NONCE KEY-----\nAAAA\n-----END MAGNOLIA NONCE KEY-----\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadNonceKey(path); err == nil {
			t.Errorf("%s: nonce key accepted", name)
		}
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "magnolia-ca.yaml")
	if err := os.WriteFile(path, []byte(`
listen: [":443"]
readlisten: [":8443"]
writeprefix: https://ca.example.com/acme
issuer:
  caid: "66252.99999.1"
  notbefore: 2026-11-11
  period: 500
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.WritePrefix != "https://ca.example.com/acme" || c.Issuer.CAID != "66252.99999.1" || c.Issuer.Period != 500 {
		t.Errorf("unexpected config %+v", c)
	}
	if len(c.ReadListen) != 1 || c.ReadListen[0] != ":8443" {
		t.Errorf("unexpected ReadListen %q", c.ReadListen)
	}
	if got, err := c.Issuer.NotBeforeDate(); err != nil {
		t.Error(err)
	} else if want := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Errorf("NotBefore is %v, want %v", got, want)
	}
	for _, notBefore := range []string{"", "2026-11-11T12:00:00Z", "2026-11-31", "11/11/2026"} {
		ic := c.Issuer
		ic.NotBefore = notBefore
		if got, err := ic.NotBeforeDate(); err == nil {
			t.Errorf("NotBefore %q: got %v, want an error", notBefore, got)
		}
	}

	if err := os.WriteFile(path, []byte("WritePrefix: https://ca.example.com/acme\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("unknown key accepted")
	}
}

func TestSigners(t *testing.T) {
	c := &IssuerConfig{
		CAID:           "66252.99999.1",
		EvidenceOrigin: "read.magnolia.test/66252.99999.1/evidence/1",
		Seed:           filepath.Join(t.TempDir(), "seed.pem"),
	}
	if _, _, err := c.Signers(); err == nil {
		t.Error("Signers succeeded without a seed")
	}
	if err := GenerateIssuerSeed(c.Seed, c.CAID); err != nil {
		t.Fatal(err)
	}
	caCosigner, evidenceLog, err := c.Signers()
	if err != nil {
		t.Fatal(err)
	}
	if name := caCosigner.Verifier().Name(); name != "oid/1.3.6.1.4.1.66252.99999.1" {
		t.Errorf("CA cosigner name is %q", name)
	}
	if name := evidenceLog.Verifier().Name(); name != c.EvidenceOrigin {
		t.Errorf("evidence log signer name is %q", name)
	}
	if c.IssuanceOrigin() != "oid/1.3.6.1.4.1.66252.99999.1.0.1" {
		t.Errorf("issuance origin is %q", c.IssuanceOrigin())
	}

	// The read path gets the verifier keys from the configuration instead,
	// and Signers checks them against the seed.
	if _, _, err := c.Verifiers(); err == nil {
		t.Error("Verifiers succeeded without verifier keys")
	}
	c.CAVerifierKey = caCosigner.Verifier().String()
	if _, _, err := c.Verifiers(); err == nil {
		t.Error("Verifiers succeeded without EvidenceVerifierKey")
	}
	c.EvidenceVerifierKey = evidenceLog.Verifier().String()
	if ca, evidence, err := c.Verifiers(); err != nil {
		t.Error(err)
	} else if ca.String() != c.CAVerifierKey || evidence.String() != c.EvidenceVerifierKey {
		t.Error("Verifiers don't match the signers")
	}
	otherSeed := &IssuerConfig{CAID: c.CAID, EvidenceOrigin: c.EvidenceOrigin,
		Seed: filepath.Join(t.TempDir(), "seed.pem")}
	if err := GenerateIssuerSeed(otherSeed.Seed, otherSeed.CAID); err != nil {
		t.Fatal(err)
	}
	otherCA, otherEvidence, err := otherSeed.Signers()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ ca, evidence string }{
		{"not a vkey", c.EvidenceVerifierKey},
		{c.CAVerifierKey, "not a vkey"},
		{c.EvidenceVerifierKey, c.EvidenceVerifierKey},
		{c.CAVerifierKey, c.CAVerifierKey},
	} {
		other := *c
		other.CAVerifierKey, other.EvidenceVerifierKey = tt.ca, tt.evidence
		if _, _, err := other.Verifiers(); err == nil {
			t.Errorf("Verifiers succeeded with %q and %q", tt.ca, tt.evidence)
		}
		if _, _, err := other.Signers(); err == nil {
			t.Errorf("Signers succeeded with %q and %q", tt.ca, tt.evidence)
		}
	}
	for _, tt := range []struct{ ca, evidence string }{
		{otherCA.Verifier().String(), c.EvidenceVerifierKey},
		{c.CAVerifierKey, otherEvidence.Verifier().String()},
		{otherCA.Verifier().String(), ""},
		{"", otherEvidence.Verifier().String()},
	} {
		other := *c
		other.CAVerifierKey, other.EvidenceVerifierKey = tt.ca, tt.evidence
		if _, _, err := other.Signers(); err == nil {
			t.Errorf("Signers succeeded with the verifier keys of another seed")
		}
	}

	caCosigner2, evidenceLog2, err := c.Signers()
	if err != nil {
		t.Fatal(err)
	}
	if caCosigner2.Verifier().String() != caCosigner.Verifier().String() ||
		evidenceLog2.Verifier().String() != evidenceLog.Verifier().String() {
		t.Error("keys changed across Signers calls")
	}

	// The evidence log key is bound to its origin.
	other := *c
	other.EvidenceOrigin = "read.magnolia.test/66252.99999.1/evidence/2"
	other.EvidenceVerifierKey = ""
	caCosigner3, evidenceLog3, err := other.Signers()
	if err != nil {
		t.Fatal(err)
	}
	if caCosigner3.Verifier().String() != caCosigner.Verifier().String() {
		t.Error("CA cosigner key depends on the evidence origin")
	}
	if strings.SplitN(evidenceLog3.Verifier().String(), "+", 3)[2] == strings.SplitN(evidenceLog.Verifier().String(), "+", 3)[2] {
		t.Error("evidence log key doesn't depend on its origin")
	}

	for _, c := range []IssuerConfig{
		{EvidenceOrigin: c.EvidenceOrigin, Seed: c.Seed},
		{CAID: c.CAID, Seed: c.Seed},
		{CAID: "66252.99999.2", EvidenceOrigin: c.EvidenceOrigin, Seed: c.Seed},
	} {
		if _, _, err := c.Signers(); err == nil {
			t.Errorf("Signers succeeded with %+v", c)
		}
	}
}

func TestSequencingPeriod(t *testing.T) {
	if d := (&IssuerConfig{}).SequencingPeriod(); d != time.Second {
		t.Errorf("default period is %v", d)
	}
	if d := (&IssuerConfig{Period: 250}).SequencingPeriod(); d != 250*time.Millisecond {
		t.Errorf("period is %v", d)
	}
}
