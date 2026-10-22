package lockstep_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mathrand "math/rand/v2"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/torchwood"
	"geomys.org/magnolia/internal/lockstep"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const tileWidth = torchwood.TileWidth

const issuanceOrigin = "example.com/TestLogs/issuance"
const evidenceOrigin = "example.com/TestLogs/evidence"

type TestLogs struct {
	Logs   *lockstep.Logs
	Config lockstep.Config
	t      testing.TB
	l      *slog.LevelVar

	// sequenced records the entries acknowledged by the AddLeaf wait
	// functions, by index, so that CheckLog can verify that every acknowledged
	// entry is published at that index in both logs. It is shared across
	// reloads.
	sequenced *sequencedEntries
}

type sequencedEntries struct {
	mu sync.Mutex
	m  map[int64]*lockstep.PendingLogEntry
}

func newTestConfig(t testing.TB) lockstep.Config {
	t.Helper()
	return lockstep.Config{
		Logger:          slog.New(testLogHandler(t)),
		Backend:         NewMemoryBackend(t),
		Lock:            NewMemoryLockBackend(t),
		IssuanceOrigin:  issuanceOrigin,
		IssuanceSigners: []*torchwood.CosignatureSigner{newTestSigner(t, issuanceOrigin)},
		EvidenceOrigin:  evidenceOrigin,
		EvidenceSigners: []*torchwood.CosignatureSigner{newTestSigner(t, evidenceOrigin)},
	}
}

func newTestSigner(t testing.TB, name string) *torchwood.CosignatureSigner {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	fatalIfErr(t, err)
	s, err := torchwood.NewCosignatureSigner(name, key)
	fatalIfErr(t, err)
	t.Logf("%s key: %x", name, key)
	return s
}

func NewEmptyTestLogs(t testing.TB) *TestLogs {
	t.Helper()
	return NewEmptyTestLogsWithConfig(t, newTestConfig(t))
}

func NewEmptyTestLogsWithConfig(t testing.TB, config lockstep.Config) *TestLogs {
	t.Helper()
	logLevel := &slog.LevelVar{}
	logLevel.Set(slog.LevelDebug)
	config.Logger = slog.New(&levelHandler{config.Logger.Handler(), logLevel})
	fatalIfErr(t, lockstep.CreateLogs(t.Context(), config))
	tl := &TestLogs{t: t, Config: config, l: logLevel,
		sequenced: &sequencedEntries{m: make(map[int64]*lockstep.PendingLogEntry)}}
	tl.CheckLog(0)
	logs, err := lockstep.LoadLogs(context.Background(), config)
	fatalIfErr(t, err)
	tl.Logs = logs
	tl.CheckLog(0)
	return tl
}

func testLogHandler(t testing.TB) slog.Handler {
	return slog.NewTextHandler(writerFunc(func(p []byte) (n int, err error) {
		t.Logf("%s", p)
		return len(p), nil
	}), &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				src := a.Value.Any().(*slog.Source)
				a.Value = slog.StringValue(fmt.Sprintf("%s:%d", filepath.Base(src.File), src.Line))
			}
			return a
		},
	})
}

// levelHandler filters a handler by a level that can be changed after the
// Config is copied into the Logs.
type levelHandler struct {
	slog.Handler
	level *slog.LevelVar
}

func (h *levelHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= h.level.Level() && h.Handler.Enabled(ctx, l)
}

func (h *levelHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &levelHandler{h.Handler.WithAttrs(attrs), h.level}
}

func (h *levelHandler) WithGroup(name string) slog.Handler {
	return &levelHandler{h.Handler.WithGroup(name), h.level}
}

type writerFunc func(p []byte) (n int, err error)

func (f writerFunc) Write(p []byte) (n int, err error) {
	return f(p)
}

func (tl *TestLogs) Quiet() {
	tl.l.Set(slog.LevelWarn)
}

func ReloadLogs(t testing.TB, tl *TestLogs) *TestLogs {
	t.Helper()
	logs, err := lockstep.LoadLogs(context.Background(), tl.Config)
	fatalIfErr(t, err)
	return &TestLogs{t: t,
		Logs:      logs,
		Config:    tl.Config,
		l:         tl.l,
		sequenced: tl.sequenced,
	}
}

// logSide describes one of the two logs, for test helpers that operate on
// each of them in turn.
type logSide struct {
	name    string
	prefix  string
	origin  string
	signers []*torchwood.CosignatureSigner
	leaf    func(*lockstep.PendingLogEntry) []byte
}

func (tl *TestLogs) sides() [2]logSide {
	return [2]logSide{
		{"issuance", "issuance/", tl.Config.IssuanceOrigin, tl.Config.IssuanceSigners,
			func(e *lockstep.PendingLogEntry) []byte { return e.IssuanceLeaf }},
		{"evidence", "evidence/", tl.Config.EvidenceOrigin, tl.Config.EvidenceSigners,
			func(e *lockstep.PendingLogEntry) []byte { return e.EvidenceLeaf }},
	}
}

// lockCheckpoints returns the issuance and evidence checkpoints committed to
// the lock backend.
func (tl *TestLogs) lockCheckpoints() (ic, ec torchwood.Checkpoint) {
	t := tl.t
	t.Helper()
	lock, err := tl.Config.Lock.Fetch(context.Background(), tl.Config.IssuanceOrigin)
	fatalIfErr(t, err)
	ib, eb, err := lockstep.SplitLockCheckpoints(lock.Bytes())
	fatalIfErr(t, err)
	ic = openCheckpoint(t, tl.Config.IssuanceOrigin, tl.Config.IssuanceSigners, ib)
	ec = openCheckpoint(t, tl.Config.EvidenceOrigin, tl.Config.EvidenceSigners, eb)
	return ic, ec
}

// CheckLog verifies the state of both logs. If size is not negative, the lock
// checkpoints must be for trees of that size. The checkpoints in object storage
// may lag behind the lock checkpoints, but must be consistent with them, and
// both published trees are fully verified against their checkpoint and data
// tiles. Every entry acknowledged by a wait function must be published at its
// index in both logs.
//
// It returns the sizes of the published issuance and evidence trees.
func (tl *TestLogs) CheckLog(size int64) (published [2]int64) {
	t := tl.t
	t.Helper()

	ic, ec := tl.lockCheckpoints()
	if ic.N != ec.N {
		t.Errorf("lock checkpoints are out of lockstep: issuance %d, evidence %d", ic.N, ec.N)
	}
	if size >= 0 && ic.N != size {
		t.Errorf("expected size %d, got %d", size, ic.N)
	}

	for i, side := range tl.sides() {
		lockCheckpoint := [2]torchwood.Checkpoint{ic, ec}[i]
		published[i] = tl.checkSide(side, lockCheckpoint)
	}
	return published
}

func (tl *TestLogs) checkSide(side logSide, lockCheckpoint torchwood.Checkpoint) int64 {
	t := tl.t
	t.Helper()
	ctx := context.Background()

	b, err := tl.Config.Backend.Fetch(ctx, side.prefix+"checkpoint")
	fatalIfErr(t, err)
	c := openCheckpoint(t, side.origin, side.signers, b)

	if c.N > lockCheckpoint.N {
		t.Errorf("%s checkpoint in object storage (%d) is newer than lock checkpoint (%d)", side.name, c.N, lockCheckpoint.N)
	}
	if c.N == lockCheckpoint.N && c.Hash != lockCheckpoint.Hash {
		t.Errorf("%s checkpoint and lock checkpoint have different hash", side.name)
	}

	entries := make(map[int64][]byte)
	if c.N == 0 {
		expected := sha256.Sum256([]byte{})
		if c.Hash != expected {
			t.Errorf("empty %s log should have empty string hash", side.name)
		}
	} else {
		tree := tlog.Tree{N: c.N, Hash: c.Hash}
		var indexes []int64
		for n := int64(0); n < c.N; n++ {
			indexes = append(indexes, tlog.StoredHashIndex(0, n))
		}
		// tlog.TileHashReader checks the inclusion of every hash in the
		// provided tree, so this checks the validity of the whole Merkle tree.
		leafHashes, err := tlog.TileHashReader(tree, &tileReader{tl, side.prefix}).ReadHashes(indexes)
		fatalIfErr(t, err)

		lastTile := tlog.TileForIndex(torchwood.TileHeight, tlog.StoredHashIndex(0, c.N-1))
		lastTile.L = -1
		for n := int64(0); n <= lastTile.N; n++ {
			tile := tlog.Tile{H: torchwood.TileHeight, L: -1, N: n, W: tileWidth}
			if n == lastTile.N {
				tile = lastTile
			}
			b, err := tl.Config.Backend.Fetch(ctx, side.prefix+torchwood.TilePath(tile))
			fatalIfErr(t, err)
			r, err := gzip.NewReader(bytes.NewReader(b))
			fatalIfErr(t, err)
			b, err = io.ReadAll(r)
			fatalIfErr(t, err)

			for i := 0; i < tile.W; i++ {
				e, rest, err := torchwood.ReadTileEntry(b)
				if err != nil {
					t.Fatalf("invalid %s data tile %v: %v", side.name, tile, err)
				}
				b = rest

				idx := n*tileWidth + int64(i)
				got := tlog.RecordHash(e)
				if exp := leafHashes[idx]; got != exp {
					t.Errorf("%s tile leaf entry %d hashes to %v, level 0 hash is %v", side.name, idx, got, exp)
				}
				if len(e) == 0 {
					t.Errorf("empty %s entry at index %d", side.name, idx)
				}
				entries[idx] = e
			}
			if len(b) != 0 {
				t.Errorf("invalid %s data tile %v: trailing data", side.name, tile)
			}
		}
	}

	tl.sequenced.mu.Lock()
	defer tl.sequenced.mu.Unlock()
	for idx, pe := range tl.sequenced.m {
		if idx >= c.N {
			t.Errorf("acknowledged entry %d is not published in the %s log (size %d)", idx, side.name, c.N)
			continue
		}
		if !bytes.Equal(entries[idx], side.leaf(pe)) {
			t.Errorf("acknowledged entry %d does not match the published %s entry", idx, side.name)
		}
	}

	return c.N
}

func openCheckpoint(t testing.TB, origin string, signers []*torchwood.CosignatureSigner, b []byte) torchwood.Checkpoint {
	t.Helper()
	var verifiers []note.Verifier
	for _, s := range signers {
		verifiers = append(verifiers, s.Verifier())
	}
	n, err := note.Open(b, note.VerifierList(verifiers...))
	fatalIfErr(t, err)
	if len(n.Sigs) != len(signers) {
		t.Errorf("checkpoint has %d signatures, want %d", len(n.Sigs), len(signers))
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	fatalIfErr(t, err)
	if c.Origin != origin {
		t.Errorf("origin line is %q, expected %q", c.Origin, origin)
	}
	if c.Extension != "" {
		t.Errorf("unexpected extension %q", c.Extension)
	}
	return c
}

// signCheckpoint signs an arbitrary tree head, to craft corrupted state.
func signCheckpoint(t testing.TB, origin string, signers []*torchwood.CosignatureSigner, tree tlog.Tree) []byte {
	t.Helper()
	var ss []note.Signer
	for _, s := range signers {
		ss = append(ss, s)
	}
	b, err := note.Sign(&note.Note{Text: torchwood.Checkpoint{
		Origin: origin, Tree: tree,
	}.String()}, ss...)
	fatalIfErr(t, err)
	return b
}

func (tl *TestLogs) StartSequencer() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	tl.t.Cleanup(func() {
		// Wait for the sequencer to exit, or it might log (or error) after the
		// test is complete.
		cancel()
		<-done
	})
	go func() {
		defer close(done)
		err := tl.Logs.RunSequencer(ctx, 50*time.Millisecond)
		if err != nil && !errors.Is(err, context.Canceled) {
			tl.t.Errorf("RunSequencer returned an error: %v", err)
		}
	}()
}

func waitFuncWrapper(t testing.TB, tl *TestLogs, e *lockstep.PendingLogEntry, expectSuccess bool,
	f lockstep.WaitEntryFunc,
) lockstep.WaitEntryFunc {
	t.Helper()
	var called bool
	fw := func(ctx context.Context) (lockstep.SequencedEntry, error) {
		t.Helper()
		called = true
		se, err := f(ctx)
		if !expectSuccess {
			if err == nil {
				t.Error("expected an error")
			}
		} else if err != nil {
			t.Error(err)
		} else {
			if se.Leaf != e {
				t.Error("SequencedEntry.Leaf is not the submitted entry")
			}
			tl.sequenced.mu.Lock()
			if prev, ok := tl.sequenced.m[se.Index]; ok && prev != e {
				t.Errorf("index %d was assigned to two different entries", se.Index)
			}
			tl.sequenced.m[se.Index] = e
			tl.sequenced.mu.Unlock()
		}
		return se, err
	}
	t.Cleanup(func() {
		t.Helper()
		if !called {
			fw(context.Background())
		}
	})
	return fw
}

// testEntry returns an entry whose leaves are determined by seed, with
// different contents for the two logs so that a mix-up would be detected.
func testEntry(seed uint64) *lockstep.PendingLogEntry {
	var s [32]byte
	binary.BigEndian.PutUint64(s[:], seed)
	r := mathrand.NewChaCha8(s)
	leaf := func(prefix string) []byte {
		b := make([]byte, len(prefix)+1+int(r.Uint64()%64))
		copy(b, prefix)
		r.Read(b[len(prefix):])
		return b
	}
	return &lockstep.PendingLogEntry{
		IssuanceLeaf: leaf("issuance:"),
		EvidenceLeaf: leaf("evidence:"),
	}
}

// testPaddedEntry is like testEntry, but with leaves the size of a typical
// certificate, for benchmarks that care about how much data the logs move.
func testPaddedEntry(seed uint64) *lockstep.PendingLogEntry {
	e := testEntry(seed)
	e.IssuanceLeaf = append(e.IssuanceLeaf, bytes.Repeat([]byte("A"), 1500)...)
	e.EvidenceLeaf = append(e.EvidenceLeaf, bytes.Repeat([]byte("B"), 500)...)
	return e
}

func addEntry(t testing.TB, tl *TestLogs) lockstep.WaitEntryFunc {
	t.Helper()
	return addEntryWithSeed(t, tl, mathrand.Uint64())
}

func addEntryWithSeed(t testing.TB, tl *TestLogs, seed uint64) lockstep.WaitEntryFunc {
	t.Helper()
	e := testEntry(seed)
	f := tl.Logs.AddLeaf(context.Background(), e)
	return waitFuncWrapper(t, tl, e, true, f)
}

func addEntryExpectFailure(t testing.TB, tl *TestLogs) lockstep.WaitEntryFunc {
	t.Helper()
	return addEntryExpectFailureWithSeed(t, tl, mathrand.Uint64())
}

func addEntryExpectFailureWithSeed(t testing.TB, tl *TestLogs, seed uint64) lockstep.WaitEntryFunc {
	t.Helper()
	e := testEntry(seed)
	f := tl.Logs.AddLeaf(context.Background(), e)
	return waitFuncWrapper(t, tl, e, false, f)
}

type tileReader struct {
	tl     *TestLogs
	prefix string
}

func (r *tileReader) Height() int {
	return torchwood.TileHeight
}

func (r *tileReader) ReadTiles(tiles []tlog.Tile) (data [][]byte, err error) {
	for _, t := range tiles {
		b, err := r.tl.Config.Backend.Fetch(context.Background(), r.prefix+torchwood.TilePath(t))
		if err != nil {
			return nil, err
		}
		data = append(data, b)
	}
	return data, nil
}

func (r *tileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) {}

type MemoryBackend struct {
	t   testing.TB
	mu  sync.Mutex
	m   map[string][]byte
	imm map[string]bool
	del map[string]bool

	uploads atomic.Uint64

	UploadCallback func(key string, data []byte) (apply bool, err error)
}

func NewMemoryBackend(t testing.TB) *MemoryBackend {
	return &MemoryBackend{
		t: t, m: make(map[string][]byte), imm: make(map[string]bool), del: make(map[string]bool),
	}
}

func (b *MemoryBackend) Upload(ctx context.Context, key string, data []byte, opts *lockstep.UploadOptions) error {
	b.uploads.Add(1)
	if len(data) == 0 {
		b.t.Errorf("uploaded key %q with empty data", key)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var finalErr error
	if b.UploadCallback != nil {
		apply, err := b.UploadCallback(key, data)
		finalErr = err
		if !apply {
			return finalErr
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.imm[key] && !bytes.Equal(b.m[key], data) {
		b.t.Errorf("immutable key %q was modified", key)
	}
	if b.del[key] {
		b.t.Errorf("deleted key %q was re-uploaded", key)
	}
	b.m[key] = data
	b.imm[key] = opts != nil && opts.Immutable
	return finalErr
}

// failUpload returns an UploadCallback that fails uploads of keys with the
// given prefix. If persist is true, the upload is applied anyway, simulating
// an error after the write went through, such as a response timeout.
func failUpload(prefix string, persist bool) func(key string, data []byte) (apply bool, err error) {
	return func(key string, data []byte) (apply bool, err error) {
		if strings.HasPrefix(key, prefix) {
			return persist, fmt.Errorf("%s upload error", prefix)
		}
		return true, nil
	}
}

func (b *MemoryBackend) Fetch(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok := b.m[key]
	if !ok {
		return nil, fmt.Errorf("key %q not found", key)
	}
	if b.del[key] {
		b.t.Errorf("deleted key %q was fetched", key)
		return nil, fmt.Errorf("key %q not found", key)
	}
	return data, nil
}

func (b *MemoryBackend) Discard(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.m[key]; !ok {
		b.t.Errorf("deleted missing key %q", key)
		return fmt.Errorf("key %q not found", key)
	}
	if b.del[key] {
		b.t.Errorf("deleted key %q was deleted again", key)
		return fmt.Errorf("key %q not found", key)
	}
	b.del[key] = true
	return nil
}

func (b *MemoryBackend) Metrics() []prometheus.Collector { return nil }

type MemoryLockBackend struct {
	t  testing.TB
	mu sync.Mutex
	m  map[string][]byte

	ReplaceCallback func(old lockstep.LockedCheckpoint, new []byte) (apply bool, err error)
}

type memoryLockCheckpoint struct {
	origin string
	data   []byte
}

func (c *memoryLockCheckpoint) Bytes() []byte {
	return c.data
}

func NewMemoryLockBackend(t testing.TB) *MemoryLockBackend {
	return &MemoryLockBackend{
		t: t, m: make(map[string][]byte),
	}
}

func (b *MemoryLockBackend) Fetch(ctx context.Context, origin string) (lockstep.LockedCheckpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok := b.m[origin]
	if !ok {
		return nil, lockstep.ErrLogNotFound
	}
	return &memoryLockCheckpoint{origin: origin, data: data}, nil
}

func (b *MemoryLockBackend) Create(ctx context.Context, origin string, new []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.m[origin]; ok {
		return fmt.Errorf("log %q already exists", origin)
	}
	b.m[origin] = new
	return nil
}

func (b *MemoryLockBackend) Replace(ctx context.Context, old lockstep.LockedCheckpoint, new []byte) (lockstep.LockedCheckpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var finalErr error
	if b.ReplaceCallback != nil {
		apply, err := b.ReplaceCallback(old, new)
		finalErr = err
		if !apply {
			return nil, finalErr
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if old == nil {
		b.t.Errorf("Replace called with nil old checkpoint")
		return nil, fmt.Errorf("old checkpoint is nil")
	}
	oldc := old.(*memoryLockCheckpoint)
	if current, ok := b.m[oldc.origin]; !ok {
		return nil, fmt.Errorf("log %q not found", oldc.origin)
	} else if !bytes.Equal(current, oldc.data) {
		return nil, fmt.Errorf("log %q has changed", oldc.origin)
	}
	b.m[oldc.origin] = new
	return &memoryLockCheckpoint{origin: oldc.origin, data: new}, finalErr
}

// failLock returns a ReplaceCallback that fails every update. If persist is
// true, the update is applied anyway.
func failLock(persist bool) func(old lockstep.LockedCheckpoint, new []byte) (apply bool, err error) {
	return func(old lockstep.LockedCheckpoint, new []byte) (apply bool, err error) {
		return persist, errors.New("lock replace error")
	}
}

func fatalIfErr(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
