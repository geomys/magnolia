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

type Logs struct {
	Logger  *slog.Logger
	Backend Backend
	Lock    LockBackend

	IssuanceOrigin  string
	IssuanceSigners []note.Signer
	EvidenceOrigin  string
	EvidenceSigners []note.Signer

	// issuanceLog and evidenceLog are owned by sequencePool.
	issuanceLog tlogState
	evidenceLog tlogState

	// poolGate is acquired by addLeafToPool before poolMu, while the sequencer
	// takes poolMu directly, so that sequencing doesn't have to queue behind
	// multiple addLeafToPool calls under load. It's a one-slot channel so that
	// it can be selected with a context and a timeout.
	poolGate chan struct{}
	// poolMu is held for the entire duration of addLeafToPool, and by
	// RunSequencer while rotating currentPool. This guarantees that
	// addLeafToPool will never add to a pool that already started sequencing.
	poolMu      sync.Mutex
	currentPool *pool
}

type tlogState struct {
	tree           treeWithTimestamp
	lockCheckpoint LockedCheckpoint
	// edgeTiles is a map from level to the right-most tile of that level.
	edgeTiles map[int]tileWithBytes
}

type treeWithTimestamp struct {
	tlog.Tree
	Time int64
}

func hashTreeHead(n int64, r tlog.HashReader, t int64) (treeWithTimestamp, error) {
	rootHash, err := tlog.TreeHash(n, r)
	if err != nil {
		return treeWithTimestamp{}, acmeerrors.Internal("couldn't compute tree hash: %w", err)
	}
	return treeWithTimestamp{N: n, Hash: rootHash, Time: t}, nil
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

type pool struct {
	pendingLeaves []PendingLogEntry

	// done is closed when the pool has been sequenced and
	// the results below are ready.
	done chan struct{}

	err error
	// firstLeafIndex is the 0-based index of pendingLeaves[0] in the tree, and
	// every following entry is sequenced contiguously.
	firstLeafIndex int64
}

type PendingLogEntry struct {
	IssuanceLeaf []byte
	EvidenceLeaf []byte
}

func newPool() *pool { return &pool{done: make(chan struct{})} }

func (ls *Logs) RunSequencer(ctx context.Context, period time.Duration) (err error) {
	// If the sequencer stops, return errors for all pending and future leaves.
	defer func() {
		ls.poolMu.Lock()
		defer ls.poolMu.Unlock()
		ls.currentPool.err = err
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

func (ls *Logs) sequencePool(ctx context.Context, p *pool) (err error) {
	if ls.issuanceLog.tree.N != ls.evidenceLog.tree.N {
		return fmt.Errorf("%w: issuance and evidence log tree sizes do not match: %d != %d", errFatal, ls.issuanceLog.tree.N, ls.evidenceLog.tree.N)
	}
	if ls.issuanceLog.tree.Time != ls.evidenceLog.tree.Time {
		return fmt.Errorf("%w: issuance and evidence log tree times do not match: %d != %d", errFatal, ls.issuanceLog.tree.Time, ls.evidenceLog.tree.Time)
	}
	oldTree := ls.issuanceLog.tree
	oldSize := oldTree.N
	start := time.Now()
	seqLog := ls.Logger.With("old_tree_size", oldSize,
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

	timestamp := time.Now().UnixMilli()
	if timestamp <= oldTree.Time {
		return fmt.Errorf("%w: time did not progress! %d -> %d", errFatal, oldTree.Time, timestamp)
	}

	var tileUploads []*uploadAction
	var newStates [2]tlogState // 0: issuanceLog, 1: evidenceLog
	pendingLeaf := [2]func(p PendingLogEntry) []byte{
		func(p PendingLogEntry) []byte { return p.IssuanceLeaf },
		func(p PendingLogEntry) []byte { return p.EvidenceLeaf },
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
			dataTile, err = torchwood.AppendTileEntry(dataTile, leaf)
			if err != nil {
				return acmeerrors.Internal("couldn't append leaf to data tile: %w", err)
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
				ls.Logger.DebugContext(ctx, "staging full data tile", "tree_size", n,
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
			ls.Logger.DebugContext(ctx, "staging partial data tile", "tree_size", n,
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
			ls.Logger.DebugContext(ctx, "staging tree tile", "old_tree_size", oldSize,
				"tree_size", n, "tile", tile, "size", len(data))
			tileUploads = append(tileUploads, &uploadAction{
				pathPrefix + torchwood.TilePath(tile), data, optsHashTile})
		}

		tree, err := hashTreeHead(n, hashReader, timestamp)
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

	// Upload tiles to staging, where they can be recovered by LoadLog if we
	// crash right after updating the lock database. See also
	// https://github.com/FiloSottile/sunlight/issues/11.
	stagedUploads, err := marshalStagedUploads(tileUploads)
	if err != nil {
		return acmeerrors.Internal("couldn't marshal staged uploads: %w", err)
	}
	stagingPath := stagingPath(newStates[0].tree.Tree, newStates[1].tree.Tree)
	// Don't upload an empty staging bundle, as it would have the same path of
	// the previous one, but different (empty) content. Note that LoadLog might
	// end up re-uploading the tiles from the previous one, which is harmless.
	if len(tileUploads) > 0 {
		gzipData, err := compress(stagedUploads)
		if err != nil {
			return acmeerrors.Internal("couldn't compress staged uploads: %w", err)
		}
		ls.Logger.DebugContext(ctx, "uploading staged tiles", "old_tree_size", oldSize,
			"tree_size", newSize, "path", stagingPath, "size", len(stagedUploads), "gzip_size", len(gzipData))
		ctxStrict, cancel := context.WithTimeout(ctx, strictTimeout)
		defer cancel()
		if err := ls.Backend.Upload(ctxStrict, stagingPath, gzipData, optsStaging); err != nil {
			return acmeerrors.Internal("couldn't upload staged tiles: %w", err)
		}
	}

	issuanceCheckpoint, err := signCheckpoint(ls.IssuanceOrigin, ls.IssuanceSigners, newStates[0].tree)
	if err != nil {
		return acmeerrors.Internal("couldn't sign checkpoint: %w", err)
	}
	evidenceCheckpoint, err := signCheckpoint(ls.EvidenceOrigin, ls.EvidenceSigners, newStates[1].tree)
	if err != nil {
		return acmeerrors.Internal("couldn't sign checkpoint: %w", err)
	}
	// TODO: make these two Replace operations atomic.
	newStates[0].lockCheckpoint, err = ls.Lock.Replace(ctx, ls.issuanceLog.lockCheckpoint, issuanceCheckpoint)
	if err != nil {
		// This is a critical error, since we don't know the state of the
		// checkpoint in the database at this point. Bail and let LoadLog get us
		// to a good state after restart.
		return fmt.Errorf("%w: couldn't upload issuance checkpoint to database: %w", errFatal, err)
	}
	newStates[1].lockCheckpoint, err = ls.Lock.Replace(ctx, ls.evidenceLog.lockCheckpoint, evidenceCheckpoint)
	if err != nil {
		// Same as above.
		return fmt.Errorf("%w: couldn't upload evidence checkpoint to database: %w", errFatal, err)
	}

	// At this point the pool is fully serialized: new entries were persisted to
	// object storage (in staging) and the checkpoint was committed to the
	// database. If we were to crash after this, recovery would be clean from
	// database and object storage.
	p.firstLeafIndex = oldTree.N
	ls.issuanceLog = newStates[0]
	ls.evidenceLog = newStates[1]

	// Use applyStagedUploads instead of going over tileUploads directly, to
	// exercise the same code path as LoadLog.
	if err := applyStagedUploads(ctx, ls.Backend, stagedUploads); err != nil {
		// This is also fatal, since we can't continue leaving behind missing
		// tiles. The next run of sequence would not upload them again, while
		// LoadLog will retry uploading them from the staging bundle.
		return fmt.Errorf("%w: couldn't upload a tile: %w", errFatal, err)
	}

	ctxStrict, cancel := context.WithTimeout(ctx, strictTimeout)
	defer cancel()
	if err := ls.Backend.Upload(ctxStrict, "issuance/checkpoint", issuanceCheckpoint, optsCheckpoint); err != nil {
		// Return an error so we don't produce certificates that, although
		// safely serialized, wouldn't be part of a publicly visible tree.
		return acmeerrors.Internal("couldn't upload issuance checkpoint to object storage: %w", err)
	}
	if err := ls.Backend.Upload(ctxStrict, "evidence/checkpoint", evidenceCheckpoint, optsCheckpoint); err != nil {
		return acmeerrors.Internal("couldn't upload evidence checkpoint to object storage: %w", err)
	}

	// Once the checkpoint is uploaded to object storage, we can safely delete the
	// staging bundle, if any. No need to fail the sequencing if this fails.
	if len(tileUploads) > 0 {
		if err := ls.Backend.Discard(ctx, stagingPath); err != nil {
			ls.Logger.ErrorContext(ctx, "staging bundle discard failed",
				"tree_size", newSize, "err", err)
		}
	}

	seqLog.Info("sequenced pool", "tree_size", newSize,
		"tiles", len(tileUploads), "timestamp", timestamp,
		"elapsed", time.Since(start))

	return nil
}

var testingOnlyPauseSequencing func()
var testingOnlyPauseAddLeafToPool func()
var testingOnlyPoolSwapped func()

type uploadAction struct {
	key  string
	data []byte
	opts *UploadOptions
}

func marshalStagedUploads(uploads []*uploadAction) ([]byte, error) {
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

func stagingPath(tree1, tree2 tlog.Tree) string {
	// We don't segment the path like in [torchwood.TilePath], because old
	// staging bundles are deleted from the local backend (where it would be
	// important not to make a directory listing too long).
	return fmt.Sprintf("staging/%d-%s-%s", tree1.N, hex.EncodeToString(tree1.Hash[:]), hex.EncodeToString(tree2.Hash[:]))
}

// signCheckpoint signs the tree and returns a c2sp.org/checkpoint.
func signCheckpoint(origin string, signers []note.Signer, tree treeWithTimestamp) (checkpoint []byte, err error) {
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
