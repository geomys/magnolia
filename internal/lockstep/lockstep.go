package lockstep

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	mathrand "math/rand/v2"
	"slices"
	"sync"
	"testing"
	"time"

	"filippo.io/torchwood"
	"geomys.org/magnolia/internal/acmeerrors"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	Logger  *slog.Logger
	Backend Backend
	Lock    LockBackend

	PoolSize int

	IssuanceOrigin  string
	IssuanceSigners []*torchwood.CosignatureSigner
	EvidenceOrigin  string
	EvidenceSigners []*torchwood.CosignatureSigner
}

func (c *Config) validate() error {
	if c.IssuanceOrigin == "" || c.EvidenceOrigin == "" {
		return errors.New("log origins must not be empty")
	}
	if c.IssuanceOrigin == c.EvidenceOrigin {
		return errors.New("issuance and evidence logs must have different origins")
	}
	if len(c.IssuanceSigners) == 0 || len(c.EvidenceSigners) == 0 {
		return errors.New("logs must have at least one signer")
	}
	return nil
}

type Logs struct {
	c Config

	// issuanceLog, evidenceLog, and lockCheckpoint are owned by sequencePool.
	issuanceLog    tlogState
	evidenceLog    tlogState
	lockCheckpoint LockedCheckpoint

	// poolGate is acquired by AddLeaf before poolMu, while the sequencer
	// takes poolMu directly, so that sequencing doesn't have to queue behind
	// multiple AddLeaf calls under load. It's a one-slot channel so that
	// it can be selected with a context and a timeout.
	poolGate chan struct{}
	// poolMu is held for the entire duration of AddLeaf, and by
	// RunSequencer while rotating currentPool. This guarantees that
	// AddLeaf will never add to a pool that already started sequencing.
	poolMu      sync.Mutex
	currentPool *pool
}

type tlogState struct {
	tree tlog.Tree
	// edgeTiles is a map from level to the right-most tile of that level.
	edgeTiles map[int]tileWithBytes
}

func hashTreeHead(n int64, r tlog.HashReader) (tlog.Tree, error) {
	rootHash, err := tlog.TreeHash(n, r)
	if err != nil {
		return tlog.Tree{}, acmeerrors.Internal("couldn't compute tree hash: %w", err)
	}
	return tlog.Tree{N: n, Hash: rootHash}, nil
}

type tileWithBytes struct {
	tlog.Tile
	B []byte
}

func (t tileWithBytes) Path() string {
	return torchwood.TilePath(t.Tile)
}

func (t tileWithBytes) String() string {
	return fmt.Sprintf("%s#%d", torchwood.TilePath(t.Tile), len(t.B))
}

var ErrLogExists = errors.New("checkpoints already exist, refusing to initialize logs")

func CreateLogs(ctx context.Context, config Config) error {
	if err := config.validate(); err != nil {
		return err
	}
	_, err := config.Lock.Fetch(ctx, config.IssuanceOrigin)
	if err == nil {
		return ErrLogExists
	}
	if !errors.Is(err, ErrLogNotFound) {
		return fmt.Errorf("couldn't fetch checkpoints from lock database: %w", err)
	}
	if _, err := config.Backend.Fetch(ctx, "issuance/checkpoint"); err == nil {
		return fmt.Errorf("issuance checkpoint missing from database but present in object storage")
	}
	if _, err := config.Backend.Fetch(ctx, "evidence/checkpoint"); err == nil {
		return fmt.Errorf("evidence checkpoint missing from database but present in object storage")
	}

	tree, err := hashTreeHead(0, nil)
	if err != nil {
		return fmt.Errorf("couldn't compute empty tree head: %w", err)
	}
	ic, err := signCheckpoint(config.IssuanceOrigin, signers(config.IssuanceSigners), tree)
	if err != nil {
		return fmt.Errorf("couldn't sign empty issuance tree head: %w", err)
	}
	ec, err := signCheckpoint(config.EvidenceOrigin, signers(config.EvidenceSigners), tree)
	if err != nil {
		return fmt.Errorf("couldn't sign empty evidence tree head: %w", err)
	}

	if err := config.Lock.Create(ctx, config.IssuanceOrigin, joinLockCheckpoints(ic, ec)); err != nil {
		return fmt.Errorf("couldn't create checkpoints in lock database: %w", err)
	}
	if err := config.Backend.Upload(ctx, "issuance/checkpoint", ic, optsCheckpoint); err != nil {
		return fmt.Errorf("couldn't upload issuance checkpoint: %w", err)
	}
	if err := config.Backend.Upload(ctx, "evidence/checkpoint", ec, optsCheckpoint); err != nil {
		return fmt.Errorf("couldn't upload evidence checkpoint: %w", err)
	}

	config.Logger.InfoContext(ctx, "created logs",
		"issuance", config.IssuanceOrigin, "evidence", config.EvidenceOrigin)
	return nil
}

func LoadLogs(ctx context.Context, config Config) (*Logs, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}

	// Load the checkpoints from the lock database. If we crashed during
	// serialization, the ones in the lock database are going to be the latest.
	lock, err := config.Lock.Fetch(ctx, config.IssuanceOrigin)
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch checkpoints from lock database: %w", err)
	}
	config.Logger.DebugContext(ctx, "loaded checkpoints", "checkpoints", lock.Bytes())
	issuanceLock, evidenceLock, err := splitLockCheckpoints(lock.Bytes())
	if err != nil {
		return nil, fmt.Errorf("couldn't split checkpoints from lock database: %w", err)
	}
	ic, err := openCheckpoint(config.IssuanceOrigin, config.IssuanceSigners, issuanceLock)
	if err != nil {
		return nil, fmt.Errorf("couldn't open issuance checkpoint from lock database: %w", err)
	}
	ec, err := openCheckpoint(config.EvidenceOrigin, config.EvidenceSigners, evidenceLock)
	if err != nil {
		return nil, fmt.Errorf("couldn't open evidence checkpoint from lock database: %w", err)
	}

	// Load the checkpoints from the object storage backend, verify them, and
	// compare them to the lock checkpoint.
	issuanceCheckpoint, err := config.Backend.Fetch(ctx, "issuance/checkpoint")
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch issuance checkpoint from object storage: %w", err)
	}
	config.Logger.DebugContext(ctx, "loaded issuance checkpoint from object storage", "checkpoint", issuanceCheckpoint)
	ic1, err := openCheckpoint(config.IssuanceOrigin, config.IssuanceSigners, issuanceCheckpoint)
	if err != nil {
		return nil, fmt.Errorf("couldn't open issuance checkpoint from object storage: %w", err)
	}
	evidenceCheckpoint, err := config.Backend.Fetch(ctx, "evidence/checkpoint")
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch evidence checkpoint from object storage: %w", err)
	}
	config.Logger.DebugContext(ctx, "loaded evidence checkpoint from object storage", "checkpoint", evidenceCheckpoint)
	ec1, err := openCheckpoint(config.EvidenceOrigin, config.EvidenceSigners, evidenceCheckpoint)
	if err != nil {
		return nil, fmt.Errorf("couldn't open evidence checkpoint from object storage: %w", err)
	}

	switch {
	case ic.N != ec.N:
		return nil, fmt.Errorf("issuance and evidence checkpoints have different sizes: %d != %d", ic.N, ec.N)
	case ic1.N == ic.N && ic1.Hash != ic.Hash:
		return nil, fmt.Errorf("issuance checkpoint hash mismatch: %x != %x", ic1.Hash, ic.Hash)
	case ec1.N == ec.N && ec1.Hash != ec.Hash:
		return nil, fmt.Errorf("evidence checkpoint hash mismatch: %x != %x", ec1.Hash, ec.Hash)
	case ic1.N > ic.N:
		return nil, fmt.Errorf("issuance checkpoint in object storage is newer than lock checkpoint: %d > %d", ic1.N, ic.N)
	case ec1.N > ec.N:
		return nil, fmt.Errorf("evidence checkpoint in object storage is newer than lock checkpoint: %d > %d", ec1.N, ec.N)
	case ic1.N < ic.N || ec1.N < ec.N:
		// It's possible that we crashed between committing a new checkpoint to
		// the lock backend and uploading it to the object storage backend.
		// Apply the staged tiles before continuing.
		config.Logger.WarnContext(ctx, "checkpoint in object storage is older than lock checkpoint",
			"size", ic.N, "old_issuance_size", ic1.N, "old_evidence_size", ec1.N)
		stagedUploads, err := fetchAndDecompress(ctx, config.Backend, stagingPath(ic.Tree, ec.Tree))
		if err != nil {
			return nil, fmt.Errorf("couldn't fetch staged uploads: %w", err)
		}
		if err := applyStagedUploads(ctx, config.Backend, stagedUploads); err != nil {
			return nil, fmt.Errorf("couldn't apply staged uploads: %w", err)
		}
	}

	// Fetch the tiles on the right edge, and verify them against the checkpoint.
	logNames := [2]string{"issuance", "evidence"}
	edgeTiles := [2]map[int]tileWithBytes{make(map[int]tileWithBytes), make(map[int]tileWithBytes)}
	for i, c := range [...]torchwood.Checkpoint{ic, ec} {
		edgeTiles, logName := edgeTiles[i], logNames[i]
		pathPrefix := logName + "/"
		if c.N == 0 {
			continue
		}
		// Fetch the right-most edge tiles by reading the last leaf.
		// TileHashReader will fetch and verify the right tiles as a
		// side-effect.
		if _, err := tlog.TileHashReader(c.Tree, &tileReader{
			fetch: func(key string) ([]byte, error) {
				return config.Backend.Fetch(ctx, pathPrefix+key)
			},
			saveTiles: func(tiles []tlog.Tile, data [][]byte) {
				for i, tile := range tiles {
					if t, ok := edgeTiles[tile.L]; !ok || t.N < tile.N || (t.N == tile.N && t.W < tile.W) {
						edgeTiles[tile.L] = tileWithBytes{tile, data[i]}
					}
				}
			}}).ReadHashes([]int64{tlog.StoredHashIndex(0, c.N-1)}); err != nil {
			return nil, fmt.Errorf("couldn't fetch %s right edge tiles: %w", logName, err)
		}

		// Fetch the right-most data tile.
		dataTile := edgeTiles[0]
		dataTile.L = -1
		dataTile.B, err = fetchAndDecompress(ctx, config.Backend, pathPrefix+dataTile.Path())
		if err != nil {
			return nil, fmt.Errorf("couldn't fetch %s right edge data tile: %w", logName, err)
		}
		edgeTiles[-1] = dataTile

		// Verify the data tile against the level 0 tile.
		b := edgeTiles[-1].B
		start := torchwood.TileWidth * dataTile.N
		for i := start; i < start+int64(dataTile.W); i++ {
			e, rest, err := torchwood.ReadTileEntry(b)
			if err != nil {
				return nil, fmt.Errorf("invalid %s data tile %v: %w", logName, dataTile.Tile, err)
			}
			b = rest

			got := tlog.RecordHash(e)
			exp, err := tlog.HashFromTile(edgeTiles[0].Tile, edgeTiles[0].B, tlog.StoredHashIndex(0, i))
			if err != nil {
				return nil, fmt.Errorf("couldn't extract hash for %s leaf %d: %w", logName, i, err)
			}
			if got != exp {
				return nil, fmt.Errorf("%s tile leaf entry %d hashes to %v, level 0 hash is %v", logName, i, got, exp)
			}
		}
		if len(b) != 0 {
			return nil, fmt.Errorf("%s data tile %v has %d trailing bytes", logName, dataTile.Tile, len(b))
		}
	}

	config.Logger.InfoContext(ctx, "loaded logs",
		"issuance", config.IssuanceOrigin,
		"evidence", config.EvidenceOrigin,
		"size", ic.N)

	return &Logs{
		c: config,
		issuanceLog: tlogState{
			tree:      ic.Tree,
			edgeTiles: edgeTiles[0],
		},
		evidenceLog: tlogState{
			tree:      ec.Tree,
			edgeTiles: edgeTiles[1],
		},
		lockCheckpoint: lock,
		poolGate:       make(chan struct{}, 1),
		currentPool:    newPool(),
	}, nil
}

// joinLockCheckpoints encodes the issuance and evidence checkpoints as a single
// lock database entry, so that they are always updated atomically.
func joinLockCheckpoints(ic, ec []byte) []byte {
	return slices.Concat(ic, []byte("\n"), ec)
}

func splitLockCheckpoints(b []byte) (ic, ec []byte, err error) {
	body, rest, ok := bytes.Cut(b, []byte("\n\n"))
	if !ok {
		return nil, nil, errors.New("missing issuance checkpoint signatures")
	}
	sigs, ec, ok := bytes.Cut(rest, []byte("\n\n"))
	if !ok {
		return nil, nil, errors.New("missing evidence checkpoint")
	}
	return b[:len(body)+len("\n\n")+len(sigs)+len("\n")], ec, nil
}

func openCheckpoint(origin string, signers []*torchwood.CosignatureSigner, b []byte) (torchwood.Checkpoint, error) {
	var verifiers []note.Verifier
	for _, s := range signers {
		verifiers = append(verifiers, s.Verifier())
	}
	n, err := note.Open(b, note.VerifierList(verifiers...))
	if err != nil {
		return torchwood.Checkpoint{}, fmt.Errorf("couldn't verify checkpoint signature: %w", err)
	}
	if len(n.Sigs) != len(signers) {
		return torchwood.Checkpoint{}, fmt.Errorf("expected %d cosignatures, got %d", len(signers), len(n.Sigs))
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return torchwood.Checkpoint{}, fmt.Errorf("couldn't parse checkpoint: %w", err)
	}

	if c.Origin != origin {
		return torchwood.Checkpoint{}, fmt.Errorf("checkpoint name is %q, not %q", c.Origin, origin)
	}
	if c.Extension != "" {
		return torchwood.Checkpoint{}, fmt.Errorf("unexpected checkpoint extension %q", c.Extension)
	}

	return c, nil
}

type tileReader struct {
	fetch     func(key string) ([]byte, error)
	saveTiles func(tiles []tlog.Tile, data [][]byte)
}

func (r *tileReader) Height() int {
	return torchwood.TileHeight
}

func (r *tileReader) ReadTiles(tiles []tlog.Tile) (data [][]byte, err error) {
	for _, t := range tiles {
		b, err := r.fetch(torchwood.TilePath(t))
		if err != nil {
			return nil, err
		}
		data = append(data, b)
	}
	return data, nil
}

func (r *tileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) { r.saveTiles(tiles, data) }

type pool struct {
	pendingLeaves []*PendingLogEntry

	// done is closed when the pool has been sequenced and
	// the results below are ready.
	done chan struct{}

	err acmeerrors.Error
	// firstLeafIndex is the 0-based index of pendingLeaves[0] in the tree, and
	// every following entry is sequenced contiguously.
	firstLeafIndex int64
}

type PendingLogEntry struct {
	IssuanceLeaf []byte
	EvidenceLeaf []byte
}

func newPool() *pool { return &pool{done: make(chan struct{})} }

var errPoolFull = acmeerrors.Custom("poolFull", 503, "the pool is full, try again later")

type WaitEntryFunc func(ctx context.Context) (SequencedEntry, error)

type SequencedEntry struct {
	Index int64
	Leaf  *PendingLogEntry
}

// AddLeaf adds leaf to the current pool. It returns a function that will
// wait until the pool is sequenced and return the sequenced leaf.
func (ls *Logs) AddLeaf(ctx context.Context, leaf *PendingLogEntry) WaitEntryFunc {
	errFunc := func(format string, a ...any) WaitEntryFunc {
		return func(ctx context.Context) (SequencedEntry, error) {
			return SequencedEntry{}, acmeerrors.Internal(format, a...)
		}
	}

	if len(leaf.IssuanceLeaf) > 65535 || len(leaf.EvidenceLeaf) > 65535 {
		return errFunc("leaf too large: issuance %d, evidence %d", len(leaf.IssuanceLeaf), len(leaf.EvidenceLeaf))
	}
	if len(leaf.IssuanceLeaf) == 0 || len(leaf.EvidenceLeaf) == 0 {
		return errFunc("leaf cannot be empty: issuance %d, evidence %d", len(leaf.IssuanceLeaf), len(leaf.EvidenceLeaf))
	}

	select {
	case ls.poolGate <- struct{}{}:
		defer func() { <-ls.poolGate }()
	case <-ctx.Done():
		err := ctx.Err()
		return errFunc("context canceled while queued for the pool: %w", err)
	}
	ls.poolMu.Lock()
	defer ls.poolMu.Unlock()
	if err := ctx.Err(); err != nil {
		return errFunc("context canceled while queued for the pool: %w", err)
	}
	if testingOnlyPauseAddLeaf != nil {
		testingOnlyPauseAddLeaf()
	}
	p := ls.currentPool
	if err := p.err; err != nil {
		return func(ctx context.Context) (SequencedEntry, error) { return SequencedEntry{}, err }
	}
	n := len(p.pendingLeaves)
	if ls.c.PoolSize > 0 && n >= ls.c.PoolSize {
		return func(ctx context.Context) (SequencedEntry, error) { return SequencedEntry{}, errPoolFull }
	}
	p.pendingLeaves = append(p.pendingLeaves, leaf)
	return func(ctx context.Context) (SequencedEntry, error) {
		select {
		case <-ctx.Done():
			return SequencedEntry{}, acmeerrors.Internal("context canceled while waiting for sequencing: %w", ctx.Err())
		case <-p.done:
			if err := ctx.Err(); err != nil {
				return SequencedEntry{}, acmeerrors.Internal("context canceled while waiting for sequencing: %w", ctx.Err())
			}
			if p.err != nil {
				return SequencedEntry{}, p.err
			}
			idx := p.firstLeafIndex + int64(n)
			return SequencedEntry{Index: idx, Leaf: leaf}, nil
		}
	}
}

func (ls *Logs) RunSequencer(ctx context.Context, period time.Duration) (err error) {
	// If the sequencer stops, return errors for all pending and future leaves.
	defer func() {
		ls.poolMu.Lock()
		defer ls.poolMu.Unlock()
		ls.currentPool.err = acmeerrors.Internal("sequencer stopped: %w", err)
		close(ls.currentPool.done)
	}()

	// Randomly stagger the sequencers to avoid conflicting for resources.
	if !testing.Testing() {
		time.Sleep(time.Duration(mathrand.Int64N(int64(period))))
	}

	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := ls.sequence(ctx); err != nil {
				return err
			}
		}
	}
}

// sequenceTimeout is the maximum time a whole sequencing can take, but
// non-fatal network operations (staging bundle and checkpoint uploads) are
// subject to strictTimeout, as we'd rather fail a pool than accumulate backlog.
const sequenceTimeout = 15 * time.Second
const strictTimeout = 1 * time.Second

var errFatal = errors.New("fatal sequencing error")

func (ls *Logs) sequence(ctx context.Context) error {
	ls.poolMu.Lock()
	p := ls.currentPool
	ls.currentPool = newPool()
	ls.poolMu.Unlock()

	if testingOnlyPoolSwapped != nil {
		testingOnlyPoolSwapped()
	}

	return ls.sequencePool(ctx, p)
}

func (ls *Logs) sequencePool(ctx context.Context, p *pool) (err acmeerrors.Error) {
	if ls.issuanceLog.tree.N != ls.evidenceLog.tree.N {
		return acmeerrors.Internal("%w: issuance and evidence log tree sizes do not match: %d != %d", errFatal, ls.issuanceLog.tree.N, ls.evidenceLog.tree.N)
	}
	oldTree := ls.issuanceLog.tree
	oldSize := oldTree.N
	start := time.Now()
	seqLog := ls.c.Logger.With("old_tree_size", oldSize,
		"entries", len(p.pendingLeaves), "start", start)
	defer func() {
		if err != nil {
			p.err = err
			seqLog.ErrorContext(ctx, "pool sequencing failed",
				"elapsed", time.Since(start), "err", err)

			// Non-fatal errors are delivered to the requests waiting on this
			// pool, but do not break the sequencer loop.
			if !errors.Is(err, errFatal) {
				err = nil
			}
		}

		close(p.done)
	}()

	ctx, cancel := context.WithTimeout(ctx, sequenceTimeout)
	defer cancel()

	var tileUploads []*uploadAction
	var newStates [2]tlogState // 0: issuanceLog, 1: evidenceLog
	pendingLeaf := [2]func(p *PendingLogEntry) []byte{
		func(p *PendingLogEntry) []byte { return p.IssuanceLeaf },
		func(p *PendingLogEntry) []byte { return p.EvidenceLeaf },
	}
	pathPrefix := [2]string{"issuance/", "evidence/"}
	for i, l := range []*tlogState{&ls.issuanceLog, &ls.evidenceLog} {
		newState := &newStates[i]
		pendingLeaf := pendingLeaf[i]
		pathPrefix := pathPrefix[i]

		edgeTiles := maps.Clone(l.edgeTiles)
		var dataTile []byte
		// Load the current partial data tile, if any.
		if t, ok := edgeTiles[-1]; ok && t.W < torchwood.TileWidth {
			dataTile = bytes.Clone(t.B)
		}
		hashReader := torchwood.NewHashReaderOverlay(l.tree.N, l.edgeTilesHashReader())
		n := l.tree.N
		for _, pl := range p.pendingLeaves {
			leaf := pendingLeaf(pl)
			var e error
			dataTile, e = torchwood.AppendTileEntry(dataTile, leaf)
			if e != nil {
				return acmeerrors.Internal("couldn't append leaf to data tile: %w", e)
			}

			// Compute the new tree hashes and add them to the hashReader overlay
			// (we will use them later to insert more leaves and finally to produce
			// the new tiles).
			if err := hashReader.AppendRecordHash(tlog.RecordHash(leaf)); err != nil {
				return acmeerrors.Internal("couldn't compute new hashes for leaf %d: %w", n, err)
			}

			n++

			// If the data tile is full, stage it.
			if n%torchwood.TileWidth == 0 {
				tile := tlog.TileForIndex(torchwood.TileHeight, tlog.StoredHashIndex(0, n-1))
				tile.L = -1
				edgeTiles[-1] = tileWithBytes{tile, dataTile}

				gzipData, err := compress(dataTile)
				if err != nil {
					return acmeerrors.Internal("couldn't compress data tile: %w", err)
				}
				ls.c.Logger.DebugContext(ctx, "staging full data tile", "tree_size", n,
					"tile", tile, "size", len(dataTile), "gzip_size", len(gzipData))

				tileUploads = append(tileUploads, &uploadAction{
					pathPrefix + torchwood.TilePath(tile), gzipData, optsDataTile})
				dataTile = nil
			}
		}

		// Stage leftover partial data tile, if any.
		if n != l.tree.N && n%torchwood.TileWidth != 0 {
			tile := tlog.TileForIndex(torchwood.TileHeight, tlog.StoredHashIndex(0, n-1))
			tile.L = -1
			edgeTiles[-1] = tileWithBytes{tile, dataTile}
			gzipData, err := compress(dataTile)
			if err != nil {
				return acmeerrors.Internal("couldn't compress data tile: %w", err)
			}
			ls.c.Logger.DebugContext(ctx, "staging partial data tile", "tree_size", n,
				"tile", tile, "size", len(dataTile), "gzip_size", len(gzipData))
			tileUploads = append(tileUploads, &uploadAction{
				pathPrefix + torchwood.TilePath(tile), gzipData, optsDataTile})
		}

		// Produce and stage new tree tiles.
		tiles := tlog.NewTiles(torchwood.TileHeight, l.tree.N, n)
		for _, tile := range tiles {
			data, err := tlog.ReadTileData(tile, hashReader)
			if err != nil {
				return acmeerrors.Internal("couldn't generate tile %v: %w", tile, err)
			}
			// Assuming NewTilesForSize produces tiles in order, this tile should
			// always be further right than the one in edgeTiles, but double check.
			if t0, ok := edgeTiles[tile.L]; !ok || t0.N < tile.N || (t0.N == tile.N && t0.W < tile.W) {
				edgeTiles[tile.L] = tileWithBytes{tile, data}
			}
			ls.c.Logger.DebugContext(ctx, "staging tree tile", "old_tree_size", oldSize,
				"tree_size", n, "tile", tile, "size", len(data))
			tileUploads = append(tileUploads, &uploadAction{
				pathPrefix + torchwood.TilePath(tile), data, optsHashTile})
		}

		tree, err := hashTreeHead(n, hashReader)
		if err != nil {
			return acmeerrors.Internal("couldn't compute tree head: %w", err)
		}

		newState.tree = tree
		newState.edgeTiles = edgeTiles
	}
	if newStates[0].tree.N != newStates[1].tree.N {
		return acmeerrors.Internal("tree sizes do not match: %d != %d", newStates[0].tree.N, newStates[1].tree.N)
	}
	newSize := newStates[0].tree.N

	if testingOnlyPauseSequencing != nil {
		testingOnlyPauseSequencing()
	}

	// Upload tiles to staging, where they can be recovered by [LoadLogs] if we
	// crash right after updating the lock database. See also
	// https://github.com/FiloSottile/sunlight/issues/11.
	stagedUploads, err := marshalStagedUploads(tileUploads)
	if err != nil {
		return acmeerrors.Internal("couldn't marshal staged uploads: %w", err)
	}
	stagingPath := stagingPath(newStates[0].tree, newStates[1].tree)
	// Don't upload an empty staging bundle, as it would overwrite the previous
	// one, which has the same path. Note that [LoadLogs] might end up
	// re-uploading the tiles from the previous one, which is harmless.
	if len(tileUploads) > 0 {
		gzipData, err := compress(stagedUploads)
		if err != nil {
			return acmeerrors.Internal("couldn't compress staged uploads: %w", err)
		}
		ls.c.Logger.DebugContext(ctx, "uploading staged tiles", "old_tree_size", oldSize,
			"tree_size", newSize, "path", stagingPath, "size", len(stagedUploads), "gzip_size", len(gzipData))
		ctxStrict, cancel := context.WithTimeout(ctx, strictTimeout)
		defer cancel()
		if err := ls.c.Backend.Upload(ctxStrict, stagingPath, gzipData, optsStaging); err != nil {
			return acmeerrors.Internal("couldn't upload staged tiles: %w", err)
		}
	}

	issuanceCheckpoint, err := signCheckpoint(ls.c.IssuanceOrigin, signers(ls.c.IssuanceSigners), newStates[0].tree)
	if err != nil {
		return acmeerrors.Internal("couldn't sign checkpoint: %w", err)
	}
	evidenceCheckpoint, err := signCheckpoint(ls.c.EvidenceOrigin, signers(ls.c.EvidenceSigners), newStates[1].tree)
	if err != nil {
		return acmeerrors.Internal("couldn't sign checkpoint: %w", err)
	}
	lock, e := ls.c.Lock.Replace(ctx, ls.lockCheckpoint, joinLockCheckpoints(issuanceCheckpoint, evidenceCheckpoint))
	if e != nil {
		// This is a critical error, since we don't know the state of the
		// checkpoints in the database at this point. Bail and let [LoadLogs] get
		// us to a good state after restart.
		return acmeerrors.Internal("%w: couldn't upload checkpoints to database: %w", errFatal, e)
	}

	// At this point the pool is fully serialized: new entries were persisted to
	// object storage (in staging) and the checkpoint was committed to the
	// database. If we were to crash after this, recovery would be clean from
	// database and object storage.
	p.firstLeafIndex = oldTree.N
	ls.issuanceLog = newStates[0]
	ls.evidenceLog = newStates[1]
	ls.lockCheckpoint = lock

	// Use applyStagedUploads instead of going over tileUploads directly, to
	// exercise the same code path as [LoadLogs].
	if err := applyStagedUploads(ctx, ls.c.Backend, stagedUploads); err != nil {
		// This is also fatal, since we can't continue leaving behind missing
		// tiles. The next run of sequence would not upload them again, while
		// [LoadLogs] will retry uploading them from the staging bundle.
		return acmeerrors.Internal("%w: couldn't upload a tile: %w", errFatal, err)
	}

	ctxStrict, cancel := context.WithTimeout(ctx, strictTimeout)
	defer cancel()
	if err := ls.c.Backend.Upload(ctxStrict, "issuance/checkpoint", issuanceCheckpoint, optsCheckpoint); err != nil {
		// Return an error so we don't produce certificates that, although
		// safely serialized, wouldn't be part of a publicly visible tree.
		return acmeerrors.Internal("couldn't upload issuance checkpoint to object storage: %w", err)
	}
	if err := ls.c.Backend.Upload(ctxStrict, "evidence/checkpoint", evidenceCheckpoint, optsCheckpoint); err != nil {
		return acmeerrors.Internal("couldn't upload evidence checkpoint to object storage: %w", err)
	}

	// Once the checkpoint is uploaded to object storage, we can safely delete the
	// staging bundle, if any. No need to fail the sequencing if this fails.
	if len(tileUploads) > 0 {
		if err := ls.c.Backend.Discard(ctx, stagingPath); err != nil {
			ls.c.Logger.ErrorContext(ctx, "staging bundle discard failed",
				"tree_size", newSize, "err", err)
		}
	}

	seqLog.Info("sequenced pool", "tree_size", newSize,
		"tiles", len(tileUploads), "elapsed", time.Since(start))

	return nil
}

var testingOnlyPauseSequencing func()
var testingOnlyPauseAddLeaf func()
var testingOnlyPoolSwapped func()

func signers(s []*torchwood.CosignatureSigner) []note.Signer {
	signers := make([]note.Signer, len(s))
	for i, cs := range s {
		signers[i] = cs
	}
	return signers
}

type uploadAction struct {
	key  string
	data []byte
	opts *UploadOptions
}

func marshalStagedUploads(uploads []*uploadAction) ([]byte, acmeerrors.Error) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, u := range uploads {
		opts, err := json.Marshal(u.opts)
		if err != nil {
			return nil, acmeerrors.Internal("couldn't marshal upload options: %w", err)
		}
		if err := writer.WriteHeader(&tar.Header{
			Name:       u.key,
			Size:       int64(len(u.data)),
			PAXRecords: map[string]string{"MAGNOLIA.opts": string(opts)},
		}); err != nil {
			return nil, acmeerrors.Internal("error writing tar header: %w", err)
		}
		if _, err := writer.Write(u.data); err != nil {
			return nil, acmeerrors.Internal("error writing tar data: %w", err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, acmeerrors.Internal("error closing tar writer: %w", err)
	}
	return buffer.Bytes(), nil
}

func applyStagedUploads(ctx context.Context, backend Backend, stagedUploads []byte) error {
	g, gctx := errgroup.WithContext(ctx)
	reader := tar.NewReader(bytes.NewReader(stagedUploads))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return acmeerrors.Internal("error reading tar header: %w", err)
		}
		key := header.Name
		optsBytes, ok := header.PAXRecords["MAGNOLIA.opts"]
		if !ok {
			return acmeerrors.Internal("missing MAGNOLIA.opts in tar header")
		}
		opts := &UploadOptions{}
		if err := json.Unmarshal([]byte(optsBytes), opts); err != nil {
			return acmeerrors.Internal("couldn't unmarshal upload options: %w", err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			return acmeerrors.Internal("error reading tar data: %w", err)
		}
		g.Go(func() error {
			return backend.Upload(gctx, key, data, opts)
		})
	}
	return g.Wait()
}

// stagingPath returns the path of the staging bundle for the tiles produced by
// a sequencing that reaches tree1 and tree2.
//
// The path only depends on the new trees, because that's all [LoadLogs] knows
// when restoring, but the bundle contents also depend on the size the trees
// were extended from. This means the bundle is not immutable. However, any
// bundle at a path is good enough to recover from: the tree size only grows,
// and since they land at the same final tree hashes, every later bundle is a
// subset of the previous bundles.
func stagingPath(tree1, tree2 tlog.Tree) string {
	// We don't segment the path like in [torchwood.TilePath], because old
	// staging bundles are deleted from the local backend (where it would be
	// important not to make a directory listing too long).
	return fmt.Sprintf("staging/%d-%s-%s", tree1.N, hex.EncodeToString(tree1.Hash[:]), hex.EncodeToString(tree2.Hash[:]))
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

// edgeTilesHashReader returns hashes from l.edgeTiles.
func (l *tlogState) edgeTilesHashReader() tlog.HashReaderFunc {
	return func(indexes []int64) ([]tlog.Hash, error) {
		list := make([]tlog.Hash, 0, len(indexes))
		for _, id := range indexes {
			t := l.edgeTiles[tlog.TileForIndex(torchwood.TileHeight, id).L]
			h, err := tlog.HashFromTile(t.Tile, t.B, id)
			if err != nil {
				return nil, fmt.Errorf("index %d not in edge tiles: %w", id, err)
			}
			list = append(list, h)
		}
		return list, nil
	}
}

func compress(data []byte) ([]byte, error) {
	b := &bytes.Buffer{}
	w := gzip.NewWriter(b)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

const maxCompressRatio = 100

func fetchAndDecompress(ctx context.Context, backend Backend, key string) ([]byte, error) {
	data, err := backend.Fetch(ctx, key)
	if err != nil {
		return nil, err
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	maxSize := int64(len(data)) * maxCompressRatio
	b, err := io.ReadAll(io.LimitReader(r, maxSize))
	if err != nil {
		return nil, err
	}
	if len(b) == int(maxSize) {
		return nil, acmeerrors.Internal("decompressed data hit maximum size of %d bytes", maxSize)
	}
	return b, nil
}
