package lockstep_test

import (
	"context"
	"testing"

	"geomys.org/magnolia/internal/lockstep"
	"golang.org/x/mod/sumdb/tlog"
)

// memoryTree is an in-memory Merkle tree, to produce trees and consistency
// proofs independently of the sequencer.
type memoryTree struct {
	hashes []tlog.Hash
	n      int64
}

func (m *memoryTree) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, x := range indexes {
		out[i] = m.hashes[x]
	}
	return out, nil
}

func (m *memoryTree) append(t testing.TB, record string) {
	t.Helper()
	h, err := tlog.StoredHashes(m.n, []byte(record), m)
	fatalIfErr(t, err)
	m.hashes = append(m.hashes, h...)
	m.n++
}

func (m *memoryTree) tree(t testing.TB) tlog.Tree {
	t.Helper()
	h, err := tlog.TreeHash(m.n, m)
	fatalIfErr(t, err)
	return tlog.Tree{N: m.n, Hash: h}
}

func (m *memoryTree) proof(t testing.TB, n int64) tlog.TreeProof {
	t.Helper()
	if n == 0 {
		return nil
	}
	p, err := tlog.ProveTree(m.n, n, m)
	fatalIfErr(t, err)
	return p
}

func TestSQLiteSigner(t *testing.T) {
	ctx := context.Background()
	c := newTestConfig(t)
	s := c.build().Signer

	if _, _, err := s.Update(ctx, lockstep.CheckpointUpdate{}); err == nil {
		t.Error("expected updating missing logs to fail")
	}
	_, _, err := s.Create(ctx)
	fatalIfErr(t, err)
	if _, _, err := s.Create(ctx); err == nil {
		t.Error("expected creating existing logs to fail")
	}

	issuance, evidence := &memoryTree{}, &memoryTree{}
	update := func(oldSize int64) lockstep.CheckpointUpdate {
		return lockstep.CheckpointUpdate{
			OldSize:     oldSize,
			First:       issuance.tree(t),
			FirstProof:  issuance.proof(t, oldSize),
			Second:      evidence.tree(t),
			SecondProof: evidence.proof(t, oldSize),
		}
	}
	// checkLatest checks the latest checkpoints against the trees as of the
	// last call to latest.
	var latestIssuance, latestEvidence tlog.Tree
	latest := func() {
		latestIssuance, latestEvidence = issuance.tree(t), evidence.tree(t)
	}
	checkLatest := func(size int64) {
		t.Helper()
		ib, eb, err := s.Checkpoints(ctx)
		fatalIfErr(t, err)
		if ic := openCheckpoint(t, c.IssuanceOrigin, c.IssuanceSigners, ib); ic.Tree != latestIssuance || ic.N != size {
			t.Errorf("latest issuance checkpoint is %d %v, expected %d %v", ic.N, ic.Hash, size, latestIssuance.Hash)
		}
		if ec := openCheckpoint(t, c.EvidenceOrigin, c.EvidenceSigners, eb); ec.Tree != latestEvidence || ec.N != size {
			t.Errorf("latest evidence checkpoint is %d %v, expected %d %v", ec.N, ec.Hash, size, latestEvidence.Hash)
		}
	}
	expectFailure := func(name string, u lockstep.CheckpointUpdate) {
		t.Helper()
		if _, _, err := s.Update(ctx, u); err == nil {
			t.Errorf("%s: expected update to fail", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
	latest()
	checkLatest(0)

	for _, r := range []string{"a", "b", "c"} {
		issuance.append(t, "issuance:"+r)
		evidence.append(t, "evidence:"+r)
	}
	expectFailure("WrongOldSize", update(1))
	u := update(0)
	u.FirstProof = tlog.TreeProof{{}}
	expectFailure("ProofFromEmpty", u)
	_, _, err = s.Update(ctx, update(0))
	fatalIfErr(t, err)
	latest()
	checkLatest(3)

	// Same size updates are allowed, but not with a different hash.
	_, _, err = s.Update(ctx, update(3))
	fatalIfErr(t, err)
	checkLatest(3)
	u = update(3)
	u.Second.Hash = tlog.RecordHash([]byte("x"))
	expectFailure("SameSizeDifferentHash", u)

	for _, r := range []string{"d", "e", "f", "g", "h"} {
		issuance.append(t, "issuance:"+r)
		evidence.append(t, "evidence:"+r)
	}
	expectFailure("StaleOldSize", update(2))
	u = update(3)
	u.FirstProof, u.SecondProof = u.SecondProof, u.FirstProof
	expectFailure("SwappedProofs", u)
	u = update(3)
	u.First.Hash = tlog.RecordHash([]byte("x"))
	expectFailure("InconsistentIssuance", u)
	u = update(3)
	u.Second.N--
	expectFailure("SizesDiffer", u)
	checkLatest(3)

	_, _, err = s.Update(ctx, update(3))
	fatalIfErr(t, err)
	latest()
	checkLatest(8)

	issuance.append(t, "issuance:i")
	evidence.append(t, "evidence:i")
	// A second signer on the same database, such as one in another process,
	// sees the updates of the first one.
	s2 := c.build().Signer
	expectFailure("StaleSecondSigner", update(3))
	_, _, err = s2.Update(ctx, update(8))
	fatalIfErr(t, err)
	latest()
	checkLatest(9)
	if _, _, err := s.Update(ctx, update(8)); err == nil {
		t.Error("expected stale update after second signer to fail")
	}
	checkLatest(9)
}
