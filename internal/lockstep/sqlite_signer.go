package lockstep

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	mathrand "math/rand/v2"
	"slices"
	"sync"
	"time"

	"filippo.io/torchwood"
	"geomys.org/magnolia/internal/acmeerrors"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"
)

var ErrLogNotFound = errors.New("log not found")

// A CheckpointSigner signs the checkpoints of a pair of logs, and keeps track
// of the latest ones, refusing to sign trees that don't extend them. It also
// signs subtrees for entries added to the first log. It is modeled after a
// c2sp.org/tlog-witness, including the sign-subtree call, so that it can be
// backed by a signer that maintains its own state, such as an HSM.
//
// The two logs are always updated together, and always have the same size.
//
// All its methods must be usable concurrently.
type CheckpointSigner interface {
	// Create signs and stores the checkpoints of the two empty trees. It must
	// fail if the logs already exist.
	Create(ctx context.Context) (first, second []byte, err error)

	// Checkpoints returns the latest checkpoints of the two logs.
	//
	// It must return [ErrLogNotFound] if the logs don't exist.
	Checkpoints(ctx context.Context) (first, second []byte, err error)

	// Update signs and stores the checkpoints of the two new trees, atomically
	// checking that the latest trees have size u.OldSize, and that the new
	// trees are consistent with them. It returns the new checkpoints, which
	// replace the latest ones.
	//
	// It also checks that u.FirstSubtrees are the subtrees covering the new
	// entries of the first log, [u.OldSize, u.First.N), in order, as described
	// in draft-ietf-plants-merkle-tree-certs, Section 4.5, and that they are
	// included in u.First. It returns their subtree cosignatures, in the same
	// order.
	//
	// If Update returns an error, the latest checkpoints might or might not
	// have been replaced. One will never be updated without the other.
	Update(ctx context.Context, u CheckpointUpdate) (first, second []byte, firstSubtrees [][]SubtreeSignature, err error)
}

// A CheckpointUpdate is the input to [CheckpointSigner.Update].
type CheckpointUpdate struct {
	OldSize int64

	First         tlog.Tree
	FirstProof    tlog.TreeProof
	FirstSubtrees []Subtree

	Second      tlog.Tree
	SecondProof tlog.TreeProof
}

// A Subtree is a subtree [Start, End) of a log, as defined in
// draft-ietf-plants-merkle-tree-certs, Section 4.1, with its hash and a subtree
// consistency proof to the tree it is included in.
type Subtree struct {
	Start, End int64
	Hash       tlog.Hash
	Proof      torchwood.SubtreeProof
}

// A SubtreeSignature is a c2sp.org/tlog-cosignature subtree cosignature.
type SubtreeSignature struct {
	Cosigner  string
	KeyHash   uint32
	Signature []byte
}

// SQLiteSigner is a [CheckpointSigner] that signs with in-memory keys, and
// stores the latest checkpoints in a SQLite database.
//
// The checkpoints are stored in a single row of the locks table, keyed by the
// origin of the first log, so that they are always updated atomically. Updates
// are performed in an IMMEDIATE transaction, so the database can be safely
// shared with other processes.
type SQLiteSigner struct {
	mu       sync.Mutex
	conn     *sqlite.Conn
	duration prometheus.Summary
	log      *slog.Logger

	firstOrigin   string
	firstSigners  []*torchwood.CosignatureSigner
	secondOrigin  string
	secondSigners []*torchwood.CosignatureSigner
}

var _ CheckpointSigner = &SQLiteSigner{}

func NewSQLiteSigner(ctx context.Context, path string, l *slog.Logger,
	firstOrigin string, firstSigners []*torchwood.CosignatureSigner,
	secondOrigin string, secondSigners []*torchwood.CosignatureSigner) (*SQLiteSigner, error) {
	duration := prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name:       "sqlite_update_duration_seconds",
			Help:       "Duration of SQLite checkpoint updates.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
			MaxAge:     1 * time.Minute,
			AgeBuckets: 6,
		},
	)

	conn, err := sqlite.OpenConn(path, sqlite.OpenReadWrite|sqlite.OpenWAL|sqlite.OpenURI)
	if err != nil {
		return nil, fmt.Errorf(`failed to open SQLite lock database (hint: to avoid misconfiguration, the lock database must be created manually with "CREATE TABLE locks (origin TEXT PRIMARY KEY, body BLOB NOT NULL) STRICT"): %w`, err)
	}
	if err := sqlitex.ExecuteTransient(conn, "PRAGMA synchronous = FULL", nil); err != nil {
		conn.Close()
		return nil, err
	}
	if err := sqlitex.ExecuteTransient(conn, "PRAGMA fullfsync = TRUE;", nil); err != nil {
		conn.Close()
		return nil, err
	}

	return &SQLiteSigner{
		conn:          conn,
		duration:      duration,
		log:           l,
		firstOrigin:   firstOrigin,
		firstSigners:  firstSigners,
		secondOrigin:  secondOrigin,
		secondSigners: secondSigners,
	}, nil
}

func (s *SQLiteSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.Close()
}

func (s *SQLiteSigner) Create(ctx context.Context) (first, second []byte, err error) {
	tree, err := hashTreeHead(0, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't compute empty tree head: %w", err)
	}
	c1, err := signCheckpoint(s.firstOrigin, signers(s.firstSigners), tree)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't sign empty tree head for %q: %w", s.firstOrigin, err)
	}
	c2, err := signCheckpoint(s.secondOrigin, signers(s.secondSigners), tree)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't sign empty tree head for %q: %w", s.secondOrigin, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	err = sqlitex.Execute(s.conn, `INSERT INTO locks (origin, body) VALUES (?, ?)
		ON CONFLICT(origin) DO NOTHING`, &sqlitex.ExecOptions{
		Args: []any{s.firstOrigin, joinLockCheckpoints(c1, c2)},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't create checkpoints in SQLite: %w", err)
	}
	if s.conn.Changes() == 0 {
		return nil, nil, errors.New("checkpoints already exist in SQLite")
	}
	return c1, c2, nil
}

func (s *SQLiteSigner) Checkpoints(ctx context.Context) (first, second []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetch()
}

// fetch returns the latest checkpoints. s.mu must be held.
func (s *SQLiteSigner) fetch() (first, second []byte, err error) {
	var body []byte
	err = sqlitex.Execute(s.conn, "SELECT body FROM locks WHERE origin = ?", &sqlitex.ExecOptions{
		Args: []any{s.firstOrigin},
		ResultFunc: func(stmt *sqlite.Stmt) error {
			body = make([]byte, stmt.GetLen("body"))
			stmt.GetBytes("body", body)
			return nil
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't fetch checkpoints from SQLite: %w", err)
	}
	if body == nil {
		return nil, nil, ErrLogNotFound
	}
	c1, c2, err := splitLockCheckpoints(body)
	if err != nil {
		return nil, nil, fmt.Errorf("couldn't split checkpoints from SQLite: %w", err)
	}
	return c1, c2, nil
}

func (s *SQLiteSigner) Update(ctx context.Context, u CheckpointUpdate) (first, second []byte, firstSubtrees [][]SubtreeSignature, err error) {
	defer prometheus.NewTimer(s.duration).ObserveDuration()
	s.mu.Lock()
	defer s.mu.Unlock()
	endFn, err := sqlitex.ImmediateTransaction(s.conn)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't begin SQLite transaction: %w", err)
	}
	defer endFn(&err)

	old1, old2, err := s.fetch()
	if err != nil {
		return nil, nil, nil, err
	}
	oc1, err := openCheckpoint(s.firstOrigin, verifiers(s.firstSigners), old1)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't open checkpoint for %q from SQLite: %w", s.firstOrigin, err)
	}
	oc2, err := openCheckpoint(s.secondOrigin, verifiers(s.secondSigners), old2)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't open checkpoint for %q from SQLite: %w", s.secondOrigin, err)
	}
	if oc1.N != u.OldSize || oc2.N != u.OldSize {
		return nil, nil, nil, fmt.Errorf("latest checkpoints have sizes %d and %d, not %d", oc1.N, oc2.N, u.OldSize)
	}
	if u.First.N != u.Second.N {
		return nil, nil, nil, fmt.Errorf("new tree sizes do not match: %d != %d", u.First.N, u.Second.N)
	}
	if err := checkTree(u.FirstProof, u.First, oc1.Tree); err != nil {
		return nil, nil, nil, fmt.Errorf("new tree for %q is not consistent with latest checkpoint: %w", s.firstOrigin, err)
	}
	if err := checkTree(u.SecondProof, u.Second, oc2.Tree); err != nil {
		return nil, nil, nil, fmt.Errorf("new tree for %q is not consistent with latest checkpoint: %w", s.secondOrigin, err)
	}
	var ranges [][2]int64
	switch start, end := u.OldSize, u.First.N; end {
	case start:
	case start + 1:
		ranges = [][2]int64{{start, end}}
	default:
		// Two or more entries are always covered by two non-empty subtrees.
		leftStart, mid, err := torchwood.CoverInterval(start, end)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("couldn't compute covering subtrees: %w", err)
		}
		ranges = [][2]int64{{leftStart, mid}, {mid, end}}
	}
	if len(u.FirstSubtrees) != len(ranges) {
		return nil, nil, nil, fmt.Errorf("got %d subtrees, expected the %d covering [%d, %d)",
			len(u.FirstSubtrees), len(ranges), u.OldSize, u.First.N)
	}
	for i, st := range u.FirstSubtrees {
		if st.Start != ranges[i][0] || st.End != ranges[i][1] {
			return nil, nil, nil, fmt.Errorf("subtree [%d, %d) is not the covering subtree [%d, %d)",
				st.Start, st.End, ranges[i][0], ranges[i][1])
		}
		if err := torchwood.CheckSubtree(st.Proof, u.First.N, u.First.Hash, st.Start, st.End, st.Hash); err != nil {
			return nil, nil, nil, fmt.Errorf("subtree [%d, %d) is not included in new tree for %q: %w", st.Start, st.End, s.firstOrigin, err)
		}
	}

	c1, err := signCheckpoint(s.firstOrigin, signers(s.firstSigners), u.First)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't sign checkpoint for %q: %w", s.firstOrigin, err)
	}
	c2, err := signCheckpoint(s.secondOrigin, signers(s.secondSigners), u.Second)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't sign checkpoint for %q: %w", s.secondOrigin, err)
	}
	for _, st := range u.FirstSubtrees {
		sigs, err := signSubtree(s.firstOrigin, s.firstSigners, st)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("couldn't sign subtree [%d, %d) for %q: %w", st.Start, st.End, s.firstOrigin, err)
		}
		firstSubtrees = append(firstSubtrees, sigs)
	}
	err = sqlitex.Execute(s.conn, "UPDATE locks SET body = ? WHERE origin = ?", &sqlitex.ExecOptions{
		Args: []any{joinLockCheckpoints(c1, c2), s.firstOrigin},
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("couldn't update checkpoints in SQLite: %w", err)
	}
	if s.conn.Changes() != 1 {
		return nil, nil, nil, fmt.Errorf("unexpected number of SQLite rows updated: %d", s.conn.Changes())
	}
	return c1, c2, firstSubtrees, nil
}

func (s *SQLiteSigner) Metrics() []prometheus.Collector {
	return []prometheus.Collector{s.duration}
}

// joinLockCheckpoints encodes the checkpoints of the two logs as a single
// lock database entry, so that they are always updated atomically.
func joinLockCheckpoints(c1, c2 []byte) []byte {
	return slices.Concat(c1, []byte("\n"), c2)
}

func splitLockCheckpoints(b []byte) (c1, c2 []byte, err error) {
	body, rest, ok := bytes.Cut(b, []byte("\n\n"))
	if !ok {
		return nil, nil, errors.New("missing first checkpoint signatures")
	}
	sigs, c2, ok := bytes.Cut(rest, []byte("\n\n"))
	if !ok {
		return nil, nil, errors.New("missing second checkpoint")
	}
	return b[:len(body)+len("\n\n")+len(sigs)+len("\n")], c2, nil
}

// checkTree verifies that p proves that newTree extends oldTree. Unlike
// [tlog.CheckTree], it accepts an empty oldTree.
func checkTree(p tlog.TreeProof, newTree, oldTree tlog.Tree) error {
	if oldTree.N == 0 {
		if len(p) != 0 {
			return errors.New("non-empty proof from empty tree")
		}
		if newTree.N == 0 && newTree.Hash != oldTree.Hash {
			return errors.New("empty tree hash mismatch")
		}
		return nil
	}
	return tlog.CheckTree(p, newTree.N, newTree.Hash, oldTree.N, oldTree.Hash)
}

func signers(s []*torchwood.CosignatureSigner) []note.Signer {
	signers := make([]note.Signer, len(s))
	for i, cs := range s {
		signers[i] = cs
	}
	return signers
}

func verifiers(s []*torchwood.CosignatureSigner) []*torchwood.CosignatureVerifier {
	verifiers := make([]*torchwood.CosignatureVerifier, len(s))
	for i, cs := range s {
		verifiers[i] = cs.Verifier()
	}
	return verifiers
}

// signCheckpoint signs the tree and returns a c2sp.org/checkpoint.
func signCheckpoint(origin string, signers []note.Signer, tree tlog.Tree) ([]byte, acmeerrors.Error) {
	// Randomize the order to enforce forward-compatible client behavior.
	signers = slices.Clone(signers)
	mathrand.Shuffle(len(signers), func(i, j int) { signers[i], signers[j] = signers[j], signers[i] })

	signedNote, err := note.Sign(&note.Note{
		Text: torchwood.Checkpoint{
			Origin: origin, N: tree.N, Hash: tree.Hash,
		}.String(),
		UnverifiedSigs: greaseSignatures(signers),
	}, signers...)
	if err != nil {
		return nil, acmeerrors.Internal("couldn't sign note: %w", err)
	}
	return signedNote, nil
}

// signSubtree produces a subtree cosignature with each signer.
func signSubtree(origin string, signers []*torchwood.CosignatureSigner, st Subtree) ([]SubtreeSignature, error) {
	var sigs []SubtreeSignature
	for _, s := range signers {
		sig, err := s.SignSubtreeRaw(origin, st.Start, st.End, st.Hash)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, SubtreeSignature{Cosigner: s.Name(), KeyHash: s.KeyHash(), Signature: sig})
	}
	return sigs, nil
}

// greaseSignatures produces unverifiable but otherwise correct signatures.
// Clients MUST ignore unknown signatures, and including some "grease" ones
// ensures they do.
func greaseSignatures(signers []note.Signer) []note.Signature {
	g := make([]byte, 5+mathrand.IntN(100))
	rand.Read(g)
	signatures := []note.Signature{
		{Name: "grease.invalid", Hash: binary.BigEndian.Uint32(g), Base64: base64.StdEncoding.EncodeToString(g)},
	}
	for _, s := range signers {
		g := make([]byte, 5+mathrand.IntN(100))
		h := sha256.Sum256(append([]byte("grease\n"), byte(mathrand.IntN(100))))
		copy(g[:4], h[:])
		rand.Read(g[4:])
		keyHash := binary.BigEndian.Uint32(g)
		if keyHash == s.KeyHash() {
			continue
		}
		signatures = append(signatures, note.Signature{
			Name: s.Name(), Hash: keyHash, Base64: base64.StdEncoding.EncodeToString(g),
		})
	}
	mathrand.Shuffle(len(signatures), func(i, j int) { signatures[i], signatures[j] = signatures[j], signatures[i] })
	return signatures
}
