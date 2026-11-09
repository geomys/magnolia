package lockstep

import (
	"context"
	"testing"
)

var ErrFatal = errFatal

var JoinLockCheckpoints = joinLockCheckpoints
var SplitLockCheckpoints = splitLockCheckpoints

func (ls *Logs) Sequence(ctx context.Context) error {
	return ls.sequence(ctx)
}

func SetAddLeafPause(f func()) {
	testingOnlyPauseAddLeaf = f
}

func SetPoolSwapCallback(f func()) {
	testingOnlyPoolSwapped = f
}

var seqRunning chan struct{}

func PauseSequencer(t testing.TB) {
	seqRunning = make(chan struct{})
	testingOnlyPauseSequencing = func() {
		<-seqRunning
	}
	t.Cleanup(func() { testingOnlyPauseSequencing = nil })
}

func ResumeSequencer() {
	close(seqRunning)
}
