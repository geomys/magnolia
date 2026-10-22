package lockstep_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"filippo.io/torchwood"
	"geomys.org/magnolia/internal/acmeerrors"
	"geomys.org/magnolia/internal/lockstep"
	"golang.org/x/mod/sumdb/tlog"
)

var longFlag = flag.Bool("long", false, "run especially slow tests")

func TestSequenceOneLeaf(t *testing.T) {
	tl := NewEmptyTestLogs(t)

	n := int64(tileWidth + 2)
	if *longFlag {
		n *= tileWidth
	}
	if testing.Short() {
		n = 3
	} else {
		tl.Quiet()
	}
	for i := int64(0); i < n; i++ {
		wait := addEntry(t, tl)
		fatalIfErr(t, tl.Logs.Sequence(t.Context()))
		if e, err := wait(context.Background()); err != nil {
			t.Fatal(err)
		} else if e.Index != i {
			t.Errorf("got leaf index %d, expected %d", e.Index, i)
		}

		if !*longFlag {
			tl.CheckLog(i + 1)
		}
	}
	tl.CheckLog(n)
}

func TestSequenceLargeLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestSequenceLargeLog in -short mode")
	}

	// Sequencing is subject to wall clock timeouts, which a slow or emulated
	// machine can exceed, silently dropping a pool. Run in a synctest bubble,
	// where the clock only advances while everything is blocked, so the
	// timeouts can't fire in the middle of a sequencing.
	synctest.Test(t, func(t *testing.T) {
		tl := NewEmptyTestLogs(t)
		tl.Quiet()
		for i := 0; i < 5; i++ {
			addEntry(t, tl)
		}
		fatalIfErr(t, tl.Logs.Sequence(t.Context()))
		tl.CheckLog(5)

		for i := 0; i < 500; i++ {
			for k := 0; k < 3000; k++ {
				tl.Logs.AddLeaf(context.Background(), testEntry(uint64(i*3000+k)))
			}
			fatalIfErr(t, tl.Logs.Sequence(t.Context()))
		}
		tl.CheckLog(5 + 500*3000)
	})
}

func TestSequenceEmptyPool(t *testing.T) {
	sequenceTwice := func(tl *TestLogs, size int64) {
		t.Helper()
		fatalIfErr(t, tl.Logs.Sequence(t.Context()))
		tl.CheckLog(size)
		fatalIfErr(t, tl.Logs.Sequence(t.Context()))
		if published := tl.CheckLog(size); published != [2]int64{size, size} {
			t.Errorf("published sizes %v, expected %d", published, size)
		}
	}
	addEntries := func(tl *TestLogs, n int) {
		for i := 0; i < n; i++ {
			addEntry(t, tl)
		}
	}

	tl := NewEmptyTestLogs(t)
	sequenceTwice(tl, 0)
	addEntries(tl, 5)
	sequenceTwice(tl, 5)
	addEntries(tl, tileWidth-5-1)
	sequenceTwice(tl, tileWidth-1)
	addEntries(tl, 1)
	sequenceTwice(tl, tileWidth)
	addEntries(tl, 1)
	sequenceTwice(tl, tileWidth+1)
}

func TestSequenceUploadCount(t *testing.T) {
	tl := NewEmptyTestLogs(t)
	for i := 0; i < tileWidth+1; i++ {
		addEntry(t, tl)
	}
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))

	var old uint64
	uploads := func() uint64 {
		new := tl.Config.Backend.(*MemoryBackend).uploads.Load()
		n := new - old
		old = new
		return n
	}
	uploads()

	// Empty rounds should cause only two uploads: the two checkpoints.
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	if n := uploads(); n != 2 {
		t.Errorf("got %d uploads, expected 2", n)
	}

	// One entry in steady state (not at tile boundary) should cause seven
	// uploads: the staging bundle, the two checkpoints, and for each log the
	// tiles at levels 0 and -1.
	addEntry(t, tl)
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	if n := uploads(); n != 7 {
		t.Errorf("got %d uploads, expected 7", n)
	}

	// A tile width worth of entries should cause thirteen uploads: the staging
	// bundle, the two checkpoints, and for each log two level -1 tiles, two
	// level 0 tiles, and one level 1 tile.
	for i := 0; i < tileWidth; i++ {
		addEntry(t, tl)
	}
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	if n := uploads(); n != 13 {
		t.Errorf("got %d uploads, expected 13", n)
	}
}

// stagingPath returns the path of the staging bundle for the current lock
// checkpoints.
func stagingPath(t *testing.T, tl *TestLogs) string {
	t.Helper()
	ic, ec := tl.lockCheckpoints()
	return fmt.Sprintf("staging/%d-%s-%s", ic.N,
		hex.EncodeToString(ic.Hash[:]), hex.EncodeToString(ec.Hash[:]))
}

func TestSequenceUploadPaths(t *testing.T) {
	tl := NewEmptyTestLogs(t)

	for i := uint64(0); i < tileWidth+5; i++ {
		addEntryWithSeed(t, tl, i)
	}
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	staging1 := stagingPath(t, tl)
	for i := uint64(0); i < tileWidth+10; i++ {
		addEntryWithSeed(t, tl, 1000+i)
	}
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	staging2 := stagingPath(t, tl)
	tl.CheckLog(2*tileWidth + 15)

	m := tl.Config.Backend.(*MemoryBackend).m
	keys := slices.Sorted(maps.Keys(m))

	expected := []string{staging1, staging2}
	for _, prefix := range []string{"issuance/", "evidence/"} {
		for _, suffix := range []string{
			"checkpoint",
			"tile/0/000",
			"tile/0/001",
			"tile/0/001.p/5",
			"tile/0/002.p/15",
			"tile/1/000.p/1",
			"tile/1/000.p/2",
			"tile/entries/000",
			"tile/entries/001",
			"tile/entries/001.p/5",
			"tile/entries/002.p/15",
		} {
			expected = append(expected, prefix+suffix)
		}
	}
	slices.Sort(expected)
	if !slices.Equal(keys, expected) {
		t.Errorf("got %#v, expected %#v", keys, expected)
	}

	for _, key := range keys {
		expectedImmutable := !strings.HasSuffix(key, "/checkpoint") && !strings.HasPrefix(key, "staging/")
		expectedDeleted := strings.HasPrefix(key, "staging/")
		if tl.Config.Backend.(*MemoryBackend).del[key] != expectedDeleted {
			t.Errorf("got deleted %v, expected %v for key %q", tl.Config.Backend.(*MemoryBackend).del[key], expectedDeleted, key)
		}
		if tl.Config.Backend.(*MemoryBackend).imm[key] != expectedImmutable {
			t.Errorf("got immutable %v, expected %v for key %q", tl.Config.Backend.(*MemoryBackend).imm[key], expectedImmutable, key)
		}
	}
}

func TestPoolFull(t *testing.T) {
	tl := NewEmptyTestLogs(t)
	tl.Config.PoolSize = 10
	tl = ReloadLogs(t, tl)

	for range 10 {
		addEntry(t, tl)
	}
	for range 10 {
		wait := addEntryExpectFailure(t, tl)
		if _, err := wait(t.Context()); !errors.Is(err, lockstep.ErrPoolFull) {
			t.Errorf("got error %v, expected ErrPoolFull", err)
		} else if e, ok := errors.AsType[acmeerrors.Error](err); !ok || e.Status() != 503 {
			t.Errorf("got error %v, expected a 503 problem", err)
		}
	}
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(10)

	// The next pool accepts entries again.
	for range 10 {
		addEntry(t, tl)
	}
	addEntryExpectFailure(t, tl)
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(20)
}

func TestCanceledSubmissions(t *testing.T) {
	tl := NewEmptyTestLogs(t)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	// A canceled submission is dropped without making it into the pool.
	wait := tl.Logs.AddLeaf(canceled, testEntry(0))
	if _, err := wait(context.Background()); !errors.Is(err, context.Canceled) {
		t.Errorf("got error %v, expected context.Canceled", err)
	}
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(0)

	// A sequenced entry is not served to a client that went away, but the
	// entry is in the log regardless.
	wait = tl.Logs.AddLeaf(context.Background(), testEntry(0))
	if _, err := wait(canceled); !errors.Is(err, context.Canceled) {
		t.Errorf("got error %v, expected context.Canceled", err)
	}
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	if _, err := wait(canceled); !errors.Is(err, context.Canceled) {
		t.Errorf("got error %v, expected context.Canceled", err)
	}
	if e, err := wait(context.Background()); err != nil {
		t.Errorf("got error %v, expected sequenced entry", err)
	} else if e.Index != 0 {
		t.Errorf("got index %d, expected 0", e.Index)
	}
	tl.CheckLog(1)
}

func TestLeafValidation(t *testing.T) {
	tl := NewEmptyTestLogs(t)

	big := bytes.Repeat([]byte("A"), 65536)
	ok := bytes.Repeat([]byte("B"), 65535)
	for _, e := range []*lockstep.PendingLogEntry{
		{IssuanceLeaf: nil, EvidenceLeaf: ok},
		{IssuanceLeaf: ok, EvidenceLeaf: nil},
		{IssuanceLeaf: nil, EvidenceLeaf: nil},
		{IssuanceLeaf: big, EvidenceLeaf: ok},
		{IssuanceLeaf: ok, EvidenceLeaf: big},
	} {
		wait := tl.Logs.AddLeaf(t.Context(), e)
		if _, err := wait(t.Context()); err == nil {
			t.Errorf("entry with leaves of size %d and %d was accepted", len(e.IssuanceLeaf), len(e.EvidenceLeaf))
		}
	}
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(0)

	// The maximum size is accepted.
	e := &lockstep.PendingLogEntry{IssuanceLeaf: ok, EvidenceLeaf: ok}
	wait := waitFuncWrapper(t, tl, e, true, tl.Logs.AddLeaf(t.Context(), e))
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	wait(t.Context())
	tl.CheckLog(1)
	tl = ReloadLogs(t, tl)
	addEntry(t, tl)
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(2)
}

// TestMaxSizeDataTile verifies that a full data tile of maximum size leaves,
// which compresses extremely well, can be loaded.
func TestMaxSizeDataTile(t *testing.T) {
	tl := NewEmptyTestLogs(t)
	tl.Quiet()
	for i := range tileWidth {
		leaf := bytes.Repeat([]byte{byte(i)}, 65535)
		e := &lockstep.PendingLogEntry{IssuanceLeaf: leaf, EvidenceLeaf: leaf}
		waitFuncWrapper(t, tl, e, true, tl.Logs.AddLeaf(t.Context(), e))
	}
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(tileWidth)
	tl = ReloadLogs(t, tl)
	addEntry(t, tl)
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(tileWidth + 1)
}

// TestConcurrentSubmissions verifies that entries submitted concurrently while
// the sequencer is running are all assigned distinct, contiguous indexes, and
// that each is published at that index in both logs.
func TestConcurrentSubmissions(t *testing.T) {
	tl := NewEmptyTestLogs(t)
	tl.Quiet()
	tl.StartSequencer()

	const submitters = 500
	indexes := make(chan int64, submitters)
	var wg sync.WaitGroup
	for i := range submitters {
		wg.Go(func() {
			wait := addEntryWithSeed(t, tl, uint64(i))
			e, err := wait(t.Context())
			if err != nil {
				t.Error(err)
				return
			}
			indexes <- e.Index
		})
	}
	wg.Wait()
	close(indexes)

	var got []int64
	for idx := range indexes {
		got = append(got, idx)
	}
	slices.Sort(got)
	for i, idx := range got {
		if idx != int64(i) {
			t.Fatalf("got indexes %v, expected 0 to %d", got, submitters-1)
		}
	}
	if published := tl.CheckLog(submitters); published != [2]int64{submitters, submitters} {
		t.Errorf("published sizes %v, expected %d", published, submitters)
	}
}

// TestSequencerNotStarved verifies that the sequencer takes priority over
// submissions for the pool lock: even with a long queue of submissions, each
// spending time in the AddLeaf critical section, a sequencing round rotates the
// pools after waiting for at most the one submission inside the critical
// section.
func TestSequencerNotStarved(t *testing.T) {
	tl := NewEmptyTestLogs(t)

	// Park every submission inside the pool lock critical section until the
	// test releases it. The hold must exceed the sync.Mutex starvation
	// threshold (1ms): within a shorter critical section, submissions can keep
	// barging in front of the waiting sequencer.
	pauses := make(chan chan struct{})
	lockstep.SetAddLeafPause(func() {
		time.Sleep(2 * time.Millisecond)
		release := make(chan struct{})
		pauses <- release
		<-release
	})
	t.Cleanup(func() { lockstep.SetAddLeafPause(nil) })

	swapped := make(chan struct{}, 1)
	lockstep.SetPoolSwapCallback(func() {
		select {
		case swapped <- struct{}{}:
		default:
		}
	})
	t.Cleanup(func() { lockstep.SetPoolSwapCallback(nil) })

	const submitters = 100
	var wg sync.WaitGroup
	for i := range submitters {
		wg.Go(func() {
			tl.Logs.AddLeaf(context.Background(), testEntry(uint64(i)))
		})
	}

	// One submission is now parked inside the critical section; give the
	// others time to queue up for the pool lock behind it.
	holder := <-pauses
	time.Sleep(100 * time.Millisecond)

	seqDone := make(chan error, 1)
	go func() { seqDone <- tl.Logs.Sequence(context.Background()) }()
	close(holder)

	// The sequencer must rotate the pools after waiting for at most the
	// submission holding the lock, not for the whole queue. A couple of
	// submissions can win the race with the sequencer, but the rest must
	// still be queued when the rotation happens.
	releasedBeforeSwap := 0
	for waiting := true; waiting; {
		select {
		case release := <-pauses:
			releasedBeforeSwap++
			close(release)
		case <-swapped:
			waiting = false
		}
	}
	if releasedBeforeSwap > 5 {
		t.Errorf("sequencer waited for %d submissions, expected at most a few", releasedBeforeSwap)
	}

	// Release the rest of the queue and wait for the round to complete.
	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()
	for draining := true; draining; {
		select {
		case release := <-pauses:
			close(release)
		case <-allDone:
			draining = false
		}
	}
	fatalIfErr(t, <-seqDone)
}

// TestPoolGateCancel verifies that a submission waiting for the pool lock
// keeps waiting until the lock is released, unless its context is canceled.
func TestPoolGateCancel(t *testing.T) {
	tl := NewEmptyTestLogs(t)

	pauses := make(chan chan struct{})
	lockstep.SetAddLeafPause(func() {
		release := make(chan struct{})
		pauses <- release
		<-release
	})
	t.Cleanup(func() { lockstep.SetAddLeafPause(nil) })

	go tl.Logs.AddLeaf(context.Background(), testEntry(0))
	holder := <-pauses

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan lockstep.WaitEntryFunc, 1)
	go func() {
		done <- tl.Logs.AddLeaf(ctx, testEntry(1))
	}()
	select {
	case <-done:
		t.Fatal("submission returned instead of waiting for the pool lock")
	case <-time.After(200 * time.Millisecond):
	}
	cancel()
	wait := <-done
	if _, err := wait(context.Background()); !errors.Is(err, context.Canceled) {
		t.Errorf("got error %v, expected context.Canceled", err)
	}

	close(holder)
	lockstep.SetAddLeafPause(nil)
	addEntry(t, tl)
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(2)
}

// TestSubmissionDuringSequencing verifies that entries submitted while a pool
// is being sequenced go to the next pool, and are sequenced right after it.
func TestSubmissionDuringSequencing(t *testing.T) {
	tl := NewEmptyTestLogs(t)
	wait0 := addEntry(t, tl)

	swapped := make(chan struct{}, 1)
	lockstep.SetPoolSwapCallback(func() {
		select {
		case swapped <- struct{}{}:
		default:
		}
	})
	t.Cleanup(func() { lockstep.SetPoolSwapCallback(nil) })
	lockstep.PauseSequencer()

	seqDone := make(chan error, 1)
	go func() { seqDone <- tl.Logs.Sequence(context.Background()) }()
	<-swapped
	wait1 := addEntry(t, tl)
	select {
	case <-seqDone:
		t.Fatal("sequencing completed while paused")
	default:
	}
	lockstep.ResumeSequencer()
	fatalIfErr(t, <-seqDone)

	if e, err := wait0(t.Context()); err != nil {
		t.Fatal(err)
	} else if e.Index != 0 {
		t.Errorf("got index %d, expected 0", e.Index)
	}
	tl.CheckLog(1)
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	if e, err := wait1(t.Context()); err != nil {
		t.Fatal(err)
	} else if e.Index != 1 {
		t.Errorf("got index %d, expected 1", e.Index)
	}
	tl.CheckLog(2)
}

func TestReloadLog(t *testing.T) {
	tl := NewEmptyTestLogs(t)
	n := int64(tileWidth + 2)
	if testing.Short() {
		n = 3
	} else {
		tl.Quiet()
	}
	for i := int64(0); i < n; i++ {
		addEntry(t, tl)

		fatalIfErr(t, tl.Logs.Sequence(t.Context()))
		tl.CheckLog(i + 1)

		tl = ReloadLogs(t, tl)
		fatalIfErr(t, tl.Logs.Sequence(t.Context()))
		tl.CheckLog(i + 1)
	}
}

func TestReloadWrongConfig(t *testing.T) {
	tl := NewEmptyTestLogs(t)
	addEntry(t, tl)
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(1)

	tests := []struct {
		name   string
		mutate func(c *testConfig)
	}{
		{"IssuanceOrigin", func(c *testConfig) { c.IssuanceOrigin = "wrong" }},
		{"EvidenceOrigin", func(c *testConfig) { c.EvidenceOrigin = "wrong" }},
		{"SwappedOrigins", func(c *testConfig) {
			c.IssuanceOrigin, c.EvidenceOrigin = c.EvidenceOrigin, c.IssuanceOrigin
		}},
		{"IssuanceKey", func(c *testConfig) {
			c.IssuanceSigners = []*torchwood.CosignatureSigner{newTestSigner(t, c.IssuanceOrigin)}
		}},
		{"EvidenceKey", func(c *testConfig) {
			c.EvidenceSigners = []*torchwood.CosignatureSigner{newTestSigner(t, c.EvidenceOrigin)}
		}},
		{"SwappedKeys", func(c *testConfig) {
			c.IssuanceSigners, c.EvidenceSigners = c.EvidenceSigners, c.IssuanceSigners
		}},
		{"SwappedLogs", func(c *testConfig) {
			c.IssuanceOrigin, c.EvidenceOrigin = c.EvidenceOrigin, c.IssuanceOrigin
			c.IssuanceSigners, c.EvidenceSigners = c.EvidenceSigners, c.IssuanceSigners
		}},
		{"ExtraIssuanceKey", func(c *testConfig) {
			c.IssuanceSigners = append(slices.Clone(c.IssuanceSigners), newTestSigner(t, c.IssuanceOrigin))
		}},
		{"ExtraEvidenceKey", func(c *testConfig) {
			c.EvidenceSigners = append(slices.Clone(c.EvidenceSigners), newTestSigner(t, c.EvidenceOrigin))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tl.Config
			tt.mutate(&c)
			if _, err := lockstep.LoadLogs(context.Background(), c.build()); err == nil {
				t.Error("expected loading to fail")
			} else {
				t.Logf("LoadLogs: %v", err)
			}
		})
	}

	// The unmodified configuration still loads.
	tl = ReloadLogs(t, tl)
	addEntry(t, tl)
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(2)
}

// TestLoadInconsistentState verifies that LoadLogs refuses to start from
// persisted state where the two logs are not in lockstep, or where object
// storage disagrees with the lock database.
func TestLoadInconsistentState(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name      string
		corrupt   func(t *testing.T, tl *TestLogs)
		wantError string
	}{
		{
			name: "LockSizesDiffer",
			corrupt: func(t *testing.T, tl *TestLogs) {
				ic, ec := tl.lockCheckpoints()
				ic.N, ic.Hash = ic.N+1, tlog.RecordHash([]byte("x"))
				setLock(t, tl, lockstep.JoinLockCheckpoints(
					signCheckpoint(t, ic.Origin, tl.Config.IssuanceSigners, ic.Tree),
					signCheckpoint(t, ec.Origin, tl.Config.EvidenceSigners, ec.Tree)))
			},
			wantError: "different sizes",
		},
		{
			name: "LockMissingEvidence",
			corrupt: func(t *testing.T, tl *TestLogs) {
				ic, _ := tl.lockCheckpoints()
				setLock(t, tl, signCheckpoint(t, ic.Origin, tl.Config.IssuanceSigners, ic.Tree))
			},
			wantError: "missing second checkpoint",
		},
		{
			name: "LockSwapped",
			corrupt: func(t *testing.T, tl *TestLogs) {
				ic, ec := tl.lockCheckpoints()
				setLock(t, tl, lockstep.JoinLockCheckpoints(
					signCheckpoint(t, ec.Origin, tl.Config.EvidenceSigners, ec.Tree),
					signCheckpoint(t, ic.Origin, tl.Config.IssuanceSigners, ic.Tree)))
			},
			wantError: "issuance checkpoint",
		},
		{
			name: "IssuanceStorageNewer",
			corrupt: func(t *testing.T, tl *TestLogs) {
				ic, _ := tl.lockCheckpoints()
				ic.N, ic.Hash = ic.N+1, tlog.RecordHash([]byte("x"))
				fatalIfErr(t, tl.Config.Backend.Upload(ctx, "issuance/checkpoint",
					signCheckpoint(t, ic.Origin, tl.Config.IssuanceSigners, ic.Tree), nil))
			},
			wantError: "issuance checkpoint in object storage is newer",
		},
		{
			name: "EvidenceStorageNewer",
			corrupt: func(t *testing.T, tl *TestLogs) {
				_, ec := tl.lockCheckpoints()
				ec.N, ec.Hash = ec.N+1, tlog.RecordHash([]byte("x"))
				fatalIfErr(t, tl.Config.Backend.Upload(ctx, "evidence/checkpoint",
					signCheckpoint(t, ec.Origin, tl.Config.EvidenceSigners, ec.Tree), nil))
			},
			wantError: "evidence checkpoint in object storage is newer",
		},
		{
			name: "IssuanceStorageHashMismatch",
			corrupt: func(t *testing.T, tl *TestLogs) {
				ic, _ := tl.lockCheckpoints()
				ic.Hash = tlog.RecordHash([]byte("x"))
				fatalIfErr(t, tl.Config.Backend.Upload(ctx, "issuance/checkpoint",
					signCheckpoint(t, ic.Origin, tl.Config.IssuanceSigners, ic.Tree), nil))
			},
			wantError: "issuance checkpoint hash mismatch",
		},
		{
			name: "EvidenceStorageHashMismatch",
			corrupt: func(t *testing.T, tl *TestLogs) {
				_, ec := tl.lockCheckpoints()
				ec.Hash = tlog.RecordHash([]byte("x"))
				fatalIfErr(t, tl.Config.Backend.Upload(ctx, "evidence/checkpoint",
					signCheckpoint(t, ec.Origin, tl.Config.EvidenceSigners, ec.Tree), nil))
			},
			wantError: "evidence checkpoint hash mismatch",
		},
		{
			name: "EvidenceStorageMissing",
			corrupt: func(t *testing.T, tl *TestLogs) {
				delete(tl.Config.Backend.(*MemoryBackend).m, "evidence/checkpoint")
			},
			wantError: "couldn't fetch evidence checkpoint",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tl := NewEmptyTestLogs(t)
			for range 3 {
				addEntry(t, tl)
			}
			fatalIfErr(t, tl.Logs.Sequence(ctx))
			tl.CheckLog(3)

			tt.corrupt(t, tl)
			_, err := lockstep.LoadLogs(ctx, tl.Config.build())
			if err == nil {
				t.Fatal("expected loading to fail")
			}
			t.Logf("LoadLogs: %v", err)
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("got error %q, expected it to contain %q", err, tt.wantError)
			}
		})
	}
}

func setLock(t *testing.T, tl *TestLogs, b []byte) {
	t.Helper()
	setLockRow(t, tl.Config.DBPath, b)
}

func TestCreateLogs(t *testing.T) {
	ctx := context.Background()
	tl := NewEmptyTestLogs(t)
	if err := lockstep.CreateLogs(ctx, tl.Config.build()); !errors.Is(err, lockstep.ErrLogExists) {
		t.Errorf("got error %v, expected ErrLogExists", err)
	}

	// A checkpoint left in object storage from a previous life is refused.
	for _, side := range tl.sides() {
		t.Run(side.name, func(t *testing.T) {
			c := newTestConfig(t)
			tree, err := tlog.TreeHash(0, nil)
			fatalIfErr(t, err)
			fatalIfErr(t, c.Backend.Upload(ctx, side.prefix+"checkpoint",
				signCheckpoint(t, side.origin, side.signers, tlog.Tree{N: 0, Hash: tree}), nil))
			if err := lockstep.CreateLogs(ctx, c.build()); err == nil {
				t.Error("expected creation to fail")
			} else {
				t.Logf("CreateLogs: %v", err)
			}
		})
	}

	t.Run("Validate", func(t *testing.T) {
		for _, tt := range []struct {
			name   string
			mutate func(c *testConfig)
		}{
			{"SameOrigin", func(c *testConfig) { c.EvidenceOrigin = c.IssuanceOrigin }},
			{"EmptyOrigin", func(c *testConfig) { c.IssuanceOrigin = "" }},
			{"NoIssuanceSigners", func(c *testConfig) { c.IssuanceSigners = nil }},
			{"NoEvidenceSigners", func(c *testConfig) { c.EvidenceSigners = nil }},
		} {
			c := newTestConfig(t)
			tt.mutate(&c)
			if err := lockstep.CreateLogs(ctx, c.build()); err == nil {
				t.Errorf("%s: expected creation to fail", tt.name)
			}
			if _, err := lockstep.LoadLogs(ctx, c.build()); err == nil {
				t.Errorf("%s: expected loading to fail", tt.name)
			}
		}
	})
}

func TestStagingCollision(t *testing.T) {
	tl := NewEmptyTestLogs(t)
	addEntry(t, tl)
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))

	// First, upload a staging bundle but fail sequencing.

	addEntryExpectFailureWithSeed(t, tl, 'A')
	addEntryExpectFailureWithSeed(t, tl, 'B')

	tl.Config.Faults.UpdateCallback = failUpdate(false)
	sequenceExpectFailure(t, tl)
	tl.CheckLog(1)

	tl.Config.Faults.UpdateCallback = nil
	tl = ReloadLogs(t, tl)
	tl.CheckLog(1)

	// Then, cause the exact same staging bundle to be uploaded.

	addEntryWithSeed(t, tl, 'A')
	addEntryWithSeed(t, tl, 'B')
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(3)

	// Again, but now due to a staging bundle upload error.

	addEntryExpectFailureWithSeed(t, tl, 'C')
	addEntryExpectFailureWithSeed(t, tl, 'D')

	tl.Config.Backend.(*MemoryBackend).UploadCallback = failUpload("staging/", true)
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(3)

	tl.Config.Backend.(*MemoryBackend).UploadCallback = nil

	addEntryWithSeed(t, tl, 'C')
	addEntryWithSeed(t, tl, 'D')
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(5)

	// Again, but reload the logs after the failed upload.

	addEntryExpectFailureWithSeed(t, tl, 'E')
	addEntryExpectFailureWithSeed(t, tl, 'F')

	tl.Config.Backend.(*MemoryBackend).UploadCallback = failUpload("staging/", true)
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(5)

	tl.Config.Backend.(*MemoryBackend).UploadCallback = nil
	tl = ReloadLogs(t, tl)
	tl.CheckLog(5)

	addEntryWithSeed(t, tl, 'E')
	addEntryWithSeed(t, tl, 'F')
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(7)

	// If the logs don't progress, the staging path is the same, and no empty
	// bundle must overwrite the previous one.

	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(7)

	tl = ReloadLogs(t, tl)
	tl.CheckLog(7)
}

// TestStagingCollisionDifferentSplit verifies that sequencing survives reaching
// the same tree through different sequencing paths. Unlike in a CT log, the
// leaves carry no timestamp, so "[A, B, C]; [D, E]" and "[A, B]; [C, D, E]"
// produce identical trees and identical staging paths, but different staging
// bundles when the split falls differently across a tile boundary.
func TestStagingCollisionDifferentSplit(t *testing.T) {
	tl := NewEmptyTestLogs(t)
	tl.Quiet()
	addEntryWithSeed(t, tl, 'A')
	addEntryWithSeed(t, tl, 'B')
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(2)

	// Upload a staging bundle for a tree of size 2 + 300, spanning a tile
	// boundary, but fail sequencing.
	for i := uint64(1); i <= 300; i++ {
		addEntryExpectFailureWithSeed(t, tl, i)
	}
	tl.Config.Faults.UpdateCallback = failUpdate(false)
	sequenceExpectFailure(t, tl)
	tl.CheckLog(2)
	tl.Config.Faults.UpdateCallback = nil
	tl = ReloadLogs(t, tl)
	tl.CheckLog(2)

	// Reach the same tree in two steps, the second of which starts after the
	// tile boundary and so stages fewer tiles than the failed attempt.
	for i := uint64(1); i <= 256; i++ {
		addEntryWithSeed(t, tl, i)
	}
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(2 + 256)
	for i := uint64(257); i <= 300; i++ {
		addEntryWithSeed(t, tl, i)
	}
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(2 + 300)

	tl = ReloadLogs(t, tl)
	addEntry(t, tl)
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(2 + 301)
}

func sequenceExpectFailure(t *testing.T, tl *TestLogs) {
	t.Helper()
	if err := tl.Logs.Sequence(t.Context()); err == nil {
		t.Error("expected error, got nil")
	} else if !errors.Is(err, lockstep.ErrFatal) {
		t.Errorf("got error %v, expected a fatal error", err)
	}
}

func TestFatalError(t *testing.T) {
	tl := NewEmptyTestLogs(t)
	addEntry(t, tl)
	addEntry(t, tl)
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))

	tl.Config.Faults.UpdateCallback = failUpdate(false)
	addEntryExpectFailure(t, tl)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := tl.Logs.RunSequencer(ctx, 1*time.Millisecond); !errors.Is(err, lockstep.ErrFatal) {
		t.Errorf("got error %v, expected fatal error", err)
	}
	tl.CheckLog(2)

	// Once the sequencer stopped, submissions are rejected.
	wait := addEntryExpectFailure(t, tl)
	if _, err := wait(t.Context()); err == nil || !strings.Contains(err.Error(), "sequencer stopped") {
		t.Errorf("got error %v, expected sequencer stopped", err)
	}

	tl.Config.Faults.UpdateCallback = nil

	tl = ReloadLogs(t, tl)
	addEntry(t, tl)
	fatalIfErr(t, tl.Logs.Sequence(t.Context()))
	tl.CheckLog(3)
}

// TestBadSignerOutput verifies that checkpoints returned by the signer are
// checked before they are published.
func TestBadSignerOutput(t *testing.T) {
	tests := []struct {
		name   string
		result func(t *testing.T, tl *TestLogs, ic, ec []byte) ([]byte, []byte)
	}{
		{"Swapped", func(t *testing.T, tl *TestLogs, ic, ec []byte) ([]byte, []byte) {
			return ec, ic
		}},
		{"OldIssuance", func(t *testing.T, tl *TestLogs, ic, ec []byte) ([]byte, []byte) {
			b, err := tl.Config.Backend.Fetch(t.Context(), "issuance/checkpoint")
			fatalIfErr(t, err)
			return b, ec
		}},
		{"WrongEvidenceKey", func(t *testing.T, tl *TestLogs, ic, ec []byte) ([]byte, []byte) {
			c := openCheckpoint(t, tl.Config.EvidenceOrigin, tl.Config.EvidenceSigners, ec)
			return ic, signCheckpoint(t, c.Origin,
				[]*torchwood.CosignatureSigner{newTestSigner(t, c.Origin)}, c.Tree)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tl := NewEmptyTestLogs(t)
			addEntry(t, tl)
			fatalIfErr(t, tl.Logs.Sequence(t.Context()))
			tl.CheckLog(1)

			tl.Config.Faults.UpdateResult = func(ic, ec []byte) ([]byte, []byte) {
				return tt.result(t, tl, ic, ec)
			}
			addEntryExpectFailure(t, tl)
			sequenceExpectFailure(t, tl)
			published := tl.CheckLog(2)
			if published != [2]int64{1, 1} {
				t.Errorf("published sizes %v, expected 1", published)
			}

			// The signer did apply the update, so reloading recovers it.
			tl.Config.Faults.UpdateResult = nil
			tl = ReloadLogs(t, tl)
			tl.CheckLog(2)
			addEntry(t, tl)
			fatalIfErr(t, tl.Logs.Sequence(t.Context()))
			tl.CheckLog(3)
		})
	}
}

// TestNonFatalError verifies that a non-fatal sequencing error is reported to
// the entries in the failed pool, but doesn't stop the sequencer.
func TestNonFatalError(t *testing.T) {
	tl := NewEmptyTestLogs(t)
	tl.StartSequencer()

	tl.Config.Backend.(*MemoryBackend).UploadCallback = failUpload("staging/", false)
	wait := addEntryExpectFailure(t, tl)
	if _, err := wait(t.Context()); err == nil {
		t.Error("expected error, got nil")
	} else if e, ok := errors.AsType[acmeerrors.Error](err); !ok || e.Status() != 500 {
		t.Errorf("got error %v, expected a 500 problem", err)
	}
	tl.CheckLog(0)

	tl.Config.Backend.(*MemoryBackend).UploadCallback = nil
	wait = addEntry(t, tl)
	if e, err := wait(t.Context()); err != nil {
		t.Fatal(err)
	} else if e.Index != 0 {
		t.Errorf("got index %d, expected 0", e.Index)
	}
	tl.CheckLog(1)
}

// TestSequencerStopped verifies that when the sequencer exits, entries pending
// in the pool and later submissions get an error rather than hanging.
func TestSequencerStopped(t *testing.T) {
	tl := NewEmptyTestLogs(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tl.Logs.RunSequencer(ctx, time.Hour) }()

	pending := addEntryExpectFailure(t, tl)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("got error %v, expected context.Canceled", err)
	}

	if _, err := pending(context.Background()); err == nil || !strings.Contains(err.Error(), "sequencer stopped") {
		t.Errorf("got error %v, expected sequencer stopped", err)
	}
	later := addEntryExpectFailure(t, tl)
	if _, err := later(context.Background()); err == nil || !strings.Contains(err.Error(), "sequencer stopped") {
		t.Errorf("got error %v, expected sequencer stopped", err)
	}
	tl.CheckLog(0)
}

func TestSequenceErrors(t *testing.T) {
	type test struct {
		name           string
		breakSeq       func(*TestLogs)
		unbreakSeq     func(*TestLogs)
		expectProgress bool
		expectFatal    bool
	}
	breakLock := func(persist bool) func(*TestLogs) {
		return func(tl *TestLogs) {
			tl.Config.Faults.UpdateCallback = failUpdate(persist)
		}
	}
	unbreakLock := func(tl *TestLogs) {
		tl.Config.Faults.UpdateCallback = nil
	}
	breakUpload := func(prefix string, persist bool) func(*TestLogs) {
		return func(tl *TestLogs) {
			tl.Config.Backend.(*MemoryBackend).UploadCallback = failUpload(prefix, persist)
		}
	}
	unbreakUpload := func(tl *TestLogs) {
		tl.Config.Backend.(*MemoryBackend).UploadCallback = nil
	}

	tests := []test{
		{
			// A fatal error while uploading to the lock backend. The upload is
			// retried, and the same tiles are generated and uploaded again.
			name:           "LockUpload",
			breakSeq:       breakLock(false),
			unbreakSeq:     unbreakLock,
			expectProgress: false,
			expectFatal:    true,
		},
		{
			// An error while uploading to the lock backend, where the lock is
			// persisted anyway, such as a response timeout.
			name:           "LockUploadPersisted",
			breakSeq:       breakLock(true),
			unbreakSeq:     unbreakLock,
			expectProgress: true,
			expectFatal:    true,
		},
		{
			name:           "StagingUpload",
			breakSeq:       breakUpload("staging/", false),
			unbreakSeq:     unbreakUpload,
			expectProgress: false,
			expectFatal:    false,
		},
		{
			name:           "StagingUploadPersisted",
			breakSeq:       breakUpload("staging/", true),
			unbreakSeq:     unbreakUpload,
			expectProgress: false,
			expectFatal:    false,
		},
	}
	// A failure uploading to either log must hold back both.
	for _, side := range []struct{ name, prefix string }{
		{"Issuance", "issuance/"}, {"Evidence", "evidence/"},
	} {
		for _, persist := range []bool{false, true} {
			suffix := ""
			if persist {
				suffix = "Persisted"
			}
			tests = append(tests,
				test{
					name:           side.name + "CheckpointUpload" + suffix,
					breakSeq:       breakUpload(side.prefix+"checkpoint", persist),
					unbreakSeq:     unbreakUpload,
					expectProgress: true,
					expectFatal:    false,
				},
				test{
					name:           side.name + "DataTileUpload" + suffix,
					breakSeq:       breakUpload(side.prefix+"tile/entries/", persist),
					unbreakSeq:     unbreakUpload,
					expectProgress: true,
					expectFatal:    true,
				},
				test{
					name:           side.name + "Level0TileUpload" + suffix,
					breakSeq:       breakUpload(side.prefix+"tile/0/", persist),
					unbreakSeq:     unbreakUpload,
					expectProgress: true,
					expectFatal:    true,
				},
			)
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tl *TestLogs
			var expectedSize int64
			var broken bool
			breakSeq := func() {
				tt.breakSeq(tl)
				broken = true
			}
			unbreakSeq := func() {
				tt.unbreakSeq(tl)
				broken = false
			}
			sequence := func(added int64) {
				t.Helper()
				err := tl.Logs.Sequence(t.Context())
				if broken && tt.expectFatal {
					if err == nil {
						t.Error("expected error, got nil")
					}
				} else {
					fatalIfErr(t, err)
				}
				if !broken || tt.expectProgress {
					expectedSize += added
				}
				tl.CheckLog(expectedSize)
				if err != nil {
					if broken {
						tt.unbreakSeq(tl)
					}
					tl = ReloadLogs(t, tl)
					if broken {
						tt.breakSeq(tl)
					}
				}
			}

			tl = NewEmptyTestLogs(t)
			for range tileWidth - 2 {
				addEntry(t, tl)
			}
			sequence(tileWidth - 2)

			breakSeq()
			addEntryExpectFailure(t, tl)
			addEntryExpectFailure(t, tl)
			addEntryExpectFailure(t, tl)
			sequence(3)

			// Re-failing the same tile sizes.
			addEntryExpectFailure(t, tl)
			addEntryExpectFailure(t, tl)
			addEntryExpectFailure(t, tl)
			sequence(3)

			unbreakSeq()

			// Succeeding with the same size that failed.
			addEntry(t, tl)
			addEntry(t, tl)
			addEntry(t, tl)
			sequence(3)
			if published := tl.CheckLog(expectedSize); published != [2]int64{expectedSize, expectedSize} {
				t.Errorf("published sizes %v, expected %d", published, expectedSize)
			}

			tl = NewEmptyTestLogs(t)
			expectedSize = 0
			for range tileWidth - 2 {
				addEntry(t, tl)
			}
			sequence(tileWidth - 2)

			breakSeq()
			addEntryExpectFailure(t, tl)
			addEntryExpectFailure(t, tl)
			addEntryExpectFailure(t, tl)
			sequence(3)

			unbreakSeq()

			// Succeeding with a different set of tiles.
			addEntry(t, tl)
			sequence(1)
			if published := tl.CheckLog(expectedSize); published != [2]int64{expectedSize, expectedSize} {
				t.Errorf("published sizes %v, expected %d", published, expectedSize)
			}
		})
	}
}

// TestReloadLaggingCheckpoint verifies recovery from a crash between the two
// checkpoint uploads, which leaves the published logs out of lockstep: the lock
// database has the new size for both, but object storage has it for only one.
func TestReloadLaggingCheckpoint(t *testing.T) {
	for _, side := range []struct {
		name   string
		prefix string
		// published are the expected sizes after the failure, when the logs
		// are at size 2 and 3 entries were added.
		published [2]int64
	}{
		// The issuance checkpoint is uploaded first, so if it fails, neither
		// is published.
		{"Issuance", "issuance/", [2]int64{2, 2}},
		{"Evidence", "evidence/", [2]int64{5, 2}},
	} {
		t.Run(side.name, func(t *testing.T) {
			tl := NewEmptyTestLogs(t)
			addEntry(t, tl)
			addEntry(t, tl)
			fatalIfErr(t, tl.Logs.Sequence(t.Context()))
			tl.CheckLog(2)

			tl.Config.Backend.(*MemoryBackend).UploadCallback = failUpload(side.prefix+"checkpoint", false)
			for range 3 {
				addEntryExpectFailure(t, tl)
			}
			fatalIfErr(t, tl.Logs.Sequence(t.Context()))
			if published := tl.CheckLog(5); published != side.published {
				t.Errorf("published sizes %v, expected %v", published, side.published)
			}

			// Crash and restart. LoadLogs recovers the tiles from the staging
			// bundle, and the next round publishes both checkpoints.
			tl.Config.Backend.(*MemoryBackend).UploadCallback = nil
			tl = ReloadLogs(t, tl)
			if published := tl.CheckLog(5); published != side.published {
				t.Errorf("published sizes %v, expected %v", published, side.published)
			}
			fatalIfErr(t, tl.Logs.Sequence(t.Context()))
			if published := tl.CheckLog(5); published != [2]int64{5, 5} {
				t.Errorf("published sizes %v, expected 5", published)
			}

			// Again, but with an empty round before the restart, which uploads
			// no staging bundle and so leaves the previous one in place.
			tl.Config.Backend.(*MemoryBackend).UploadCallback = failUpload(side.prefix+"checkpoint", false)
			for range 3 {
				addEntryExpectFailure(t, tl)
			}
			fatalIfErr(t, tl.Logs.Sequence(t.Context()))
			fatalIfErr(t, tl.Logs.Sequence(t.Context()))
			tl.CheckLog(8)

			tl.Config.Backend.(*MemoryBackend).UploadCallback = nil
			tl = ReloadLogs(t, tl)
			fatalIfErr(t, tl.Logs.Sequence(t.Context()))
			if published := tl.CheckLog(8); published != [2]int64{8, 8} {
				t.Errorf("published sizes %v, expected 8", published)
			}

			addEntry(t, tl)
			fatalIfErr(t, tl.Logs.Sequence(t.Context()))
			tl.CheckLog(9)
		})
	}
}

// TestLocalBackend runs the logs on the real LocalBackend in a temporary
// directory, across a restart.
func TestLocalBackend(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	logger := slog.New(testLogHandler(t))

	backend, err := lockstep.NewLocalBackend(ctx, filepath.Join(dir, "data"), logger)
	fatalIfErr(t, err)

	config := newTestConfig(t)
	config.Backend = backend
	if _, _, err := config.build().Signer.Checkpoints(ctx); !errors.Is(err, lockstep.ErrLogNotFound) {
		t.Errorf("got error %v, expected ErrLogNotFound", err)
	}
	tl := NewEmptyTestLogsWithConfig(t, config)
	tl.Quiet()

	if err := lockstep.CreateLogs(ctx, tl.Config.build()); !errors.Is(err, lockstep.ErrLogExists) {
		t.Errorf("got error %v, expected ErrLogExists", err)
	}

	for range tileWidth - 1 {
		addEntry(t, tl)
	}
	fatalIfErr(t, tl.Logs.Sequence(ctx))
	tl.CheckLog(tileWidth - 1)
	for range 3 {
		addEntry(t, tl)
	}
	fatalIfErr(t, tl.Logs.Sequence(ctx))
	tl.CheckLog(tileWidth + 2)

	tl = ReloadLogs(t, tl)
	tl.CheckLog(tileWidth + 2)
	addEntry(t, tl)
	fatalIfErr(t, tl.Logs.Sequence(ctx))
	if published := tl.CheckLog(tileWidth + 3); published != [2]int64{tileWidth + 3, tileWidth + 3} {
		t.Errorf("published sizes %v, expected %d", published, tileWidth+3)
	}

	t.Run("Immutable", func(t *testing.T) {
		key := "issuance/" + torchwood.TilePath(tlog.Tile{H: torchwood.TileHeight, L: 0, N: 0, W: tileWidth})
		data, err := backend.Fetch(ctx, key)
		fatalIfErr(t, err)
		// Re-uploading the same contents succeeds, as LoadLogs does when
		// applying a staging bundle.
		fatalIfErr(t, backend.Upload(ctx, key, data, &lockstep.UploadOptions{Immutable: true}))
		other := bytes.Clone(data)
		other[0] ^= 0xff
		if err := backend.Upload(ctx, key, other, &lockstep.UploadOptions{Immutable: true}); err == nil {
			t.Error("expected modifying an immutable file to fail")
		}
		if _, err := backend.Fetch(ctx, "issuance/tile/0/999"); err == nil {
			t.Error("expected fetching a missing file to fail")
		}
	})
}

func BenchmarkSequencer(b *testing.B) {
	tl := NewEmptyTestLogs(b)
	tl.Quiet()
	for i := 0; b.Loop(); i++ {
		const poolSize = 3000
		if i%poolSize == 0 && i != 0 {
			fatalIfErr(b, tl.Logs.Sequence(context.Background()))
		}
		tl.Logs.AddLeaf(context.Background(), testPaddedEntry(uint64(i)))
	}
}
