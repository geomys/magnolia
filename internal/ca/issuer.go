package ca

import (
	"context"
	"crypto/mldsa"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"geomys.org/magnolia/internal/lockstep"
	"geomys.org/magnolia/internal/mtc"
)

// An Issuer is an MTC CA, as defined in draft-ietf-plants-merkle-tree-certs-07,
// with its issuance and evidence logs.
//
// A [CA] is an ACME CA which can use one or more Issuers.
//
// Each CA cosigner key is a separate MTC CA, with its own CA ID, so rotating
// keys means moving issuance to a new Issuer.
type Issuer struct {
	logs   *lockstep.Logs
	period time.Duration
}

type IssuerConfig struct {
	// CAID is the CA ID, such as "66252.1".
	CAID string

	// Logs is the configuration of the issuance and evidence logs.
	//
	// The issuance log origin must be the representation of log 1 of the CA,
	// such as "oid/1.3.6.1.4.1.66252.1.0.1".
	//
	// The issuance log verifiers must be the ML-DSA cosigners, including the CA
	// cosigner (with a name such as "oid/1.3.6.1.4.1.66252.1").
	Logs lockstep.Config

	// SequencingPeriod is how often [Issuer.RunSequencer] sequences the logs.
	SequencingPeriod time.Duration
}

// oidPrefix is prepended to the ASCII representation of a trust anchor ID to
// represent it as a log origin or cosigner name, as specified in
// https://c2sp.org/mtc-tlog@v0.1.0#representing-trust-anchor-ids.
const oidPrefix = "oid/1.3.6.1.4.1."

// newIssuer checks the configuration, and returns an Issuer without logs.
func newIssuer(c *IssuerConfig) (*Issuer, error) {
	caID, err := mtc.ParseTrustAnchorID(c.CAID)
	if err != nil {
		return nil, err
	}
	// Only log 1 is ever used, per doc/profile.md.
	logID, err := mtc.ParseTrustAnchorID(c.CAID + ".0.1")
	if err != nil {
		return nil, err
	}
	if c.Logs.IssuanceOrigin != oidPrefix+logID.String() {
		return nil, fmt.Errorf("issuance log origin must be %q", oidPrefix+logID.String())
	}
	if c.SequencingPeriod <= 0 {
		return nil, errors.New("SequencingPeriod must be positive")
	}
	var cosigners []mtc.TrustAnchorID
	for _, v := range c.Logs.IssuanceVerifiers {
		name, ok := strings.CutPrefix(v.Name(), oidPrefix)
		if !ok {
			return nil, fmt.Errorf("issuance log verifier %q is not named after a trust anchor ID", v.Name())
		}
		id, err := mtc.ParseTrustAnchorID(name)
		if err != nil {
			return nil, fmt.Errorf("issuance log verifier %q: %w", v.Name(), err)
		}
		if slices.Contains(cosigners, id) {
			return nil, fmt.Errorf("duplicate issuance log verifier %q", v.Name())
		}
		if _, ok := v.PublicKey().(*mldsa.PublicKey); !ok {
			return nil, fmt.Errorf("issuance log verifier %q is not an ML-DSA cosigner", v.Name())
		}
		cosigners = append(cosigners, id)
	}
	if !slices.Contains(cosigners, caID) {
		return nil, fmt.Errorf("issuance log verifiers must include the CA cosigner %q", oidPrefix+caID.String())
	}
	return &Issuer{period: c.SequencingPeriod}, nil
}

// CreateIssuer creates the logs of a new Issuer. The issuance log starts with a
// null entry, so that no certificate has index 0, and the evidence log starts
// with the placeholder "null". See [lockstep.CreateLogs].
func CreateIssuer(ctx context.Context, config IssuerConfig) error {
	if _, err := newIssuer(&config); err != nil {
		return err
	}
	return lockstep.CreateLogs(ctx, config.Logs, &lockstep.PendingLogEntry{
		IssuanceLeaf: mtc.NullLogEntry(),
		EvidenceLeaf: []byte("null"),
	})
}

// LoadIssuer loads an Issuer created with [CreateIssuer].
func LoadIssuer(ctx context.Context, config IssuerConfig) (*Issuer, error) {
	iss, err := newIssuer(&config)
	if err != nil {
		return nil, err
	}
	logs, size, err := lockstep.LoadLogs(ctx, config.Logs)
	if err != nil {
		return nil, err
	}
	// No certificate may have index 0, which CreateIssuer fills with a null entry.
	if size == 0 {
		return nil, errors.New("issuance log is empty, it must be created with CreateIssuer")
	}
	iss.logs = logs
	return iss, nil
}

// RunSequencer runs the log sequencer until ctx is canceled or a fatal error
// occurs. See [lockstep.Logs.RunSequencer].
func (iss *Issuer) RunSequencer(ctx context.Context) error {
	return iss.logs.RunSequencer(ctx, iss.period)
}
