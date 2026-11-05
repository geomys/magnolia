package lockstep_test

import (
	"context"
	"testing"

	"filippo.io/torchwood"
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

func (m *memoryTree) subtree(t testing.TB, start, end int64) lockstep.Subtree {
	t.Helper()
	h, err := torchwood.SubtreeHash(start, end, m)
	fatalIfErr(t, err)
	p, err := torchwood.ProveSubtree(m.n, start, end, m)
	fatalIfErr(t, err)
	return lockstep.Subtree{Start: start, End: end, Hash: h, Proof: p}
}

// covering returns the subtrees covering the entries [start, m.n).
func (m *memoryTree) covering(t testing.TB, start int64) []lockstep.Subtree {
	t.Helper()
	leftStart, mid, err := torchwood.CoverInterval(start, m.n)
	fatalIfErr(t, err)
	var subtrees []lockstep.Subtree
	if leftStart != mid {
		subtrees = append(subtrees, m.subtree(t, leftStart, mid))
	}
	if mid != m.n {
		subtrees = append(subtrees, m.subtree(t, mid, m.n))
	}
	return subtrees
}

func TestSQLiteSigner(t *testing.T) {
	ctx := context.Background()
	c := newTestConfig(t)
	s := c.build().Signer

	if _, _, _, err := s.Update(ctx, lockstep.CheckpointUpdate{}); err == nil {
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
			OldSize:       oldSize,
			First:         issuance.tree(t),
			FirstProof:    issuance.proof(t, oldSize),
			FirstSubtrees: issuance.covering(t, oldSize),
			Second:        evidence.tree(t),
			SecondProof:   evidence.proof(t, oldSize),
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
		if _, _, _, err := s.Update(ctx, u); err == nil {
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
	// The subtrees covering the new entries of the first tree are checked and
	// cosigned by its signers along with the checkpoints.
	u = update(0)
	if len(u.FirstSubtrees) != 2 || u.FirstSubtrees[0].End != 2 {
		t.Fatalf("unexpected covering subtrees %v", u.FirstSubtrees)
	}
	_, _, sigs, err := s.Update(ctx, u)
	fatalIfErr(t, err)
	latest()
	checkLatest(3)
	if len(sigs) != len(u.FirstSubtrees) {
		t.Fatalf("got %d subtree signatures, want %d", len(sigs), len(u.FirstSubtrees))
	}
	for i, st := range u.FirstSubtrees {
		if len(sigs[i]) != len(c.IssuanceSigners) {
			t.Fatalf("got %d signatures on subtree [%d, %d), want %d", len(sigs[i]), st.Start, st.End, len(c.IssuanceSigners))
		}
		for j, signer := range c.IssuanceSigners {
			if sigs[i][j].Cosigner != signer.Name() || sigs[i][j].KeyHash != signer.KeyHash() {
				t.Errorf("signature on subtree [%d, %d) is from %q %08x, want %q %08x", st.Start, st.End,
					sigs[i][j].Cosigner, sigs[i][j].KeyHash, signer.Name(), signer.KeyHash())
			}
			if !signer.Verifier().VerifySubtreeRaw(c.IssuanceOrigin, st.Start, st.End, st.Hash, sigs[i][j].Signature) {
				t.Errorf("invalid signature on subtree [%d, %d)", st.Start, st.End)
			}
		}
	}
	_, _, sigs, err = s.Update(ctx, update(3))
	fatalIfErr(t, err)
	if len(sigs) != 0 {
		t.Errorf("got %d subtree signatures, want none", len(sigs))
	}

	// Same size updates are allowed, but not with a different hash.
	_, _, _, err = s.Update(ctx, update(3))
	fatalIfErr(t, err)
	checkLatest(3)
	u = update(3)
	u.Second.Hash = tlog.RecordHash([]byte("x"))
	expectFailure("SameSizeDifferentHash", u)
	u = update(3)
	u.FirstSubtrees = []lockstep.Subtree{issuance.subtree(t, 2, 3)}
	expectFailure("SameSizeSubtree", u)

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
	// The update from 3 to 8 is covered by [3, 4) and [4, 8).
	u = update(3)
	u.FirstSubtrees = nil
	expectFailure("MissingSubtrees", u)
	u = update(3)
	u.FirstSubtrees = u.FirstSubtrees[:1]
	expectFailure("MissingSubtree", u)
	u = update(3)
	u.FirstSubtrees = append(u.FirstSubtrees, issuance.subtree(t, 0, 2))
	expectFailure("ExtraSubtree", u)
	u = update(3)
	u.FirstSubtrees[0], u.FirstSubtrees[1] = u.FirstSubtrees[1], u.FirstSubtrees[0]
	expectFailure("SwappedSubtrees", u)
	u = update(3)
	u.FirstSubtrees[0] = issuance.subtree(t, 2, 4)
	expectFailure("NotCoveringSubtree", u)
	u = update(3)
	u.FirstSubtrees[1].Proof = u.FirstSubtrees[1].Proof[1:]
	expectFailure("BadSubtreeProof", u)
	u = update(3)
	u.FirstSubtrees = evidence.covering(t, 3)
	expectFailure("SubtreesFromSecondLog", u)
	checkLatest(3)

	_, _, _, err = s.Update(ctx, update(3))
	fatalIfErr(t, err)
	latest()
	checkLatest(8)

	issuance.append(t, "issuance:i")
	evidence.append(t, "evidence:i")
	// A second signer on the same database, such as one in another process,
	// sees the updates of the first one.
	s2 := c.build().Signer
	expectFailure("StaleSecondSigner", update(3))
	_, _, _, err = s2.Update(ctx, update(8))
	fatalIfErr(t, err)
	latest()
	checkLatest(9)
	if _, _, _, err := s.Update(ctx, update(8)); err == nil {
		t.Error("expected stale update after second signer to fail")
	}
	checkLatest(9)
}
