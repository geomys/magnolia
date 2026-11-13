package ca

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"geomys.org/magnolia/internal/acmeerrors"
	"geomys.org/magnolia/internal/lint"
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
	logger     *slog.Logger
	logs       *lockstep.Logs
	backend    lockstep.Backend
	readPrefix *url.URL
	period     time.Duration
	caID       mtc.TrustAnchorID
	cosigners  []mtc.TrustAnchorID // in the order of the issuance log verifiers
	preLint    *lint.Linter
	postLint   *lint.Linter
}

type IssuerConfig struct {
	// CAID is the CA ID, such as "66252.1".
	CAID string

	// ReadPrefix is the absolute URL prefix of the read path of this issuer,
	// without a trailing slash, such as "https://read.example.com/66252.1".
	// See doc/urls.md. Certificates are served at
	//
	//     ReadPrefix + "/certificate/1/<notAfter date>/<index>-<token>"
	//
	// where 1 is the log number.
	ReadPrefix string

	// Logs is the configuration of the issuance and evidence logs.
	// Its Logger is also used by the Issuer.
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
	readPrefix, err := parsePrefix("ReadPrefix", c.ReadPrefix)
	if err != nil {
		return nil, err
	}
	if c.SequencingPeriod <= 0 {
		return nil, errors.New("SequencingPeriod must be positive")
	}
	if c.Logs.SubtreesSigned != nil {
		return nil, errors.New("Logs.SubtreesSigned must be nil, it's set by the Issuer")
	}
	var cosigners []mtc.TrustAnchorID
	var lintCosigners []lint.Cosigner
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
		key, ok := v.PublicKey().(*mldsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("issuance log verifier %q is not an ML-DSA cosigner", v.Name())
		}
		cosigners = append(cosigners, id)
		lintCosigners = append(lintCosigners, lint.Cosigner{ID: id, Key: key})
	}
	if !slices.Contains(cosigners, caID) {
		return nil, fmt.Errorf("issuance log verifiers must include the CA cosigner %q", oidPrefix+caID.String())
	}
	preLint, err := lint.PreIssuance()
	if err != nil {
		return nil, err
	}
	postLint, err := lint.Standalone(lintCosigners)
	if err != nil {
		return nil, err
	}
	return &Issuer{
		logger:     c.Logs.Logger,
		backend:    c.Logs.Backend,
		readPrefix: readPrefix,
		period:     c.SequencingPeriod,
		caID:       caID,
		cosigners:  cosigners,
		preLint:    preLint,
		postLint:   postLint,
	}, nil
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
	config.Logs.SubtreesSigned = iss.subtreesSigned
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

// issueTimeout bounds issuance. Sequencing a pool takes at most 15s, after
// waiting for up to a sequencing period, which is expected to be short.
//
// It is a variable so that tests can use long sequencing periods.
var issueTimeout = 30 * time.Second

// issue builds and lints the TBSCertificate, adds its entry to the log, waits
// for it to be sequenced and cosigned, assembles and lints the standalone
// certificate, and writes its files, with token in their paths. It returns the
// index of the entry.
//
// If it returns [lockstep.ErrPoolFull], the entry was not added to the log.
//
// Once the entry is added, the certificate is issued regardless of what the
// client does, so issue doesn't respect the cancellation of ctx.
func (iss *Issuer) issue(ctx context.Context, pub *mldsa.PublicKey, dnsNames []string, issuedAt time.Time, token string, evidence []byte) (int64, acmeerrors.Error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), issueTimeout)
	defer cancel()

	tbs, err := mtc.TBSCertificate(&mtc.Template{
		CAID:      iss.caID,
		IssuedAt:  issuedAt,
		PublicKey: pub,
		DNSNames:  dnsNames,
	})
	if err != nil {
		return 0, acmeerrors.New("rejectedIdentifier", 400, "couldn't build certificate: %w", err)
	}
	if err := iss.preLint.Lint(tbs); err != nil {
		return 0, acmeerrors.Internal("pre-issuance lint failed: %w", err)
	}
	entry, err := mtc.LogEntry(tbs)
	if err != nil {
		return 0, acmeerrors.New("rejectedIdentifier", 400, "couldn't build log entry: %w", err)
	}

	se, err := iss.logs.AddLeaf(ctx, &lockstep.PendingLogEntry{IssuanceLeaf: entry, EvidenceLeaf: evidence})
	if errors.Is(err, lockstep.ErrPoolFull) {
		return 0, lockstep.ErrPoolFull
	}
	if err != nil {
		return 0, acmeerrors.Internal("couldn't sequence certificate: %w", err)
	}
	if se.Index == 0 {
		return 0, acmeerrors.Internal("certificate was sequenced at index 0, reserved for the null entry")
	}

	if err := mtc.SetSerial(tbs, se.Index); err != nil {
		return 0, acmeerrors.Internal("couldn't set serial number: %w", err)
	}
	proof := &mtc.Proof{
		Start:          se.Subtree.Start,
		End:            se.Subtree.End,
		InclusionProof: se.Proof,
		Cosignatures:   iss.cosignatures(se.Subtree),
	}
	proofBytes, err := proof.Bytes()
	if err != nil {
		return 0, acmeerrors.Internal("couldn't encode proof: %w", err)
	}
	cert, err := mtc.Certificate(tbs, proofBytes)
	if err != nil {
		return 0, acmeerrors.Internal("couldn't assemble certificate: %w", err)
	}
	if err := iss.postLint.Lint(cert); err != nil {
		// TODO: increment a metric, and trigger a page alert.
		iss.logger.ErrorContext(ctx, "post-issuance lint failed", "index", se.Index, "err", err)
		return 0, acmeerrors.Internal("post-issuance lint failed: %w", err)
	}

	_, notAfter := mtc.Validity(issuedAt)
	standalone, err := proof.BytesWithoutSignatures()
	if err != nil {
		return 0, acmeerrors.Internal("couldn't encode standalone proof: %w", err)
	}
	if err := iss.backend.Upload(ctx, certFileKey(notAfter, "tbs", se.Index, token), tbs, optsCertFile); err != nil {
		return 0, acmeerrors.Internal("couldn't write TBSCertificate: %w", err)
	}
	if err := iss.backend.Upload(ctx, certFileKey(notAfter, "standalone", se.Index, token), standalone, optsCertFile); err != nil {
		return 0, acmeerrors.Internal("couldn't write standalone proof: %w", err)
	}
	return se.Index, nil
}

// cosignatures returns the cosignatures of a subtree, ordered by cosigner ID.
func (iss *Issuer) cosignatures(st *lockstep.SignedSubtree) []mtc.Cosignature {
	var cs []mtc.Cosignature
	for i, sig := range st.Signatures {
		cs = append(cs, mtc.Cosignature{CosignerID: iss.cosigners[i], Signature: sig.Signature})
	}
	slices.SortFunc(cs, func(a, b mtc.Cosignature) int {
		return mtc.CompareCosignerIDs(a.CosignerID, b.CosignerID)
	})
	return cs
}

// Certificates are stored in the issuer backend, under certs/ and subtrees/
// next to issuance/ and evidence/. certs/ is sharded by notAfter UTC date, so
// directories can be pruned once certificates expire.
//
//	certs/<YYYY-MM-DD>/tbs/<index>-<token>          TBSCertificate, with the serial number set
//	certs/<YYYY-MM-DD>/standalone/<index>-<token>   MTCProof up to the signatures field
//	certs/<YYYY-MM-DD>/landmark/<index>-<token>     MTCProof with no signatures, by the landmarker
//	subtrees/<start>-<end>                          MTCProof signatures field
//
// Standalone certificates are split into TBS (tbs/), per-certificate proof
// (standalone/), and per-subtree cosignatures (subtrees/).
//
// Landmark certificates are split into TBS (tbs/) and proof (landmark/).
//
// <index> and <start> are split into groups of three digits like tile indexes
// in c2sp.org/tlog-tiles paths, to keep directories small, so for example the
// subtree [1234067, 1234100) is at subtrees/x001/x234/067-1234100.
//
// <token> is a short random string, generated at issuance, so that certificate
// paths can't be predicted from the index and certificates can't be scraped by
// enumerating them.

var optsCertFile = &lockstep.UploadOptions{Immutable: true}

func certFileKey(notAfter time.Time, kind string, index int64, token string) string {
	return "certs/" + notAfter.Format(time.DateOnly) + "/" + kind + "/" + indexPath(index) + "-" + token
}

// certToken returns a random 40-bit token, encoded as 8 base32 characters.
func certToken() string {
	b := make([]byte, 5)
	rand.Read(b)
	return base32.StdEncoding.EncodeToString(b)
}

func subtreeKey(st *lockstep.SignedSubtree) string {
	return "subtrees/" + indexPath(st.Start) + "-" + strconv.FormatInt(st.End, 10)
}

// indexPath formats n like a tile index in c2sp.org/tlog-tiles paths.
func indexPath(n int64) string {
	s := fmt.Sprintf("%03d", n%1000)
	for n >= 1000 {
		n /= 1000
		s = fmt.Sprintf("x%03d/", n%1000) + s
	}
	return s
}

// subtreesSigned is the [lockstep.Config.SubtreesSigned] hook.
// It writes the subtrees files with the standalone cosignatures.
func (iss *Issuer) subtreesSigned(ctx context.Context, subtrees []*lockstep.SignedSubtree) error {
	for _, st := range subtrees {
		b, err := mtc.SignaturesBytes(iss.cosignatures(st))
		if err != nil {
			return fmt.Errorf("encoding cosignatures of [%d, %d): %w", st.Start, st.End, err)
		}
		if err := iss.backend.Upload(ctx, subtreeKey(st), b, optsCertFile); err != nil {
			return fmt.Errorf("writing cosignatures of [%d, %d): %w", st.Start, st.End, err)
		}
	}
	return nil
}
