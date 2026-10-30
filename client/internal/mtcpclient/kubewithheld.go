package mtcpclient

import (
	"math/rand/v2"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// A gateway whose map withholds every peer's Kubernetes access, its scope
// table unusable (mtcp-v1 §7.12), asks Core for the whole map again: first
// after withheldResyncFirst, then each wait twice the last up to
// withheldResyncMax, until a usable table comes (K2 §21, e5).
const (
	withheldResyncFirst = 10 * time.Second
	withheldResyncMax   = 5 * time.Minute
)

// withheldResync is the gateway's resync while its table is withheld.
type withheldResync struct {
	timer *time.Timer
	wait  time.Duration
	// pending: a resync was asked and its snapshot has not come. Deltas go
	// on being applied meanwhile, unlike a gap's resync: revocations must
	// not wait (mtcp-v1 §7.12, review e4–e6 H1).
	pending bool
	// sent counts resyncs asked, for tests.
	sent int
}

// withholding reports a gateway's applied map that withholds access.
func (run *sessionRun) withholding() bool {
	state := run.state
	return state.takesKubernetes && state.takesProfiles && state.compiledOnce && state.compiled.withheld
}

// noteWithheld arms a resync while the map withholds access, once; a usable
// table stops it and starts the waits again from the first.
func (run *sessionRun) noteWithheld() {
	held := &run.withheld
	if !run.withholding() {
		if held.timer != nil {
			held.timer.Stop()
			held.timer = nil
		}
		held.wait = 0
		return
	}
	if held.timer != nil {
		return
	}
	if held.wait == 0 {
		held.wait = withheldResyncFirst
	}
	// ±20 %, so gateways given the same table do not ask at once (review
	// e4–e6 M4).
	jitter := time.Duration(rand.Int64N(int64(held.wait)*2/5+1)) - held.wait/5 //nolint:gosec // G404: timing only
	held.timer = time.NewTimer(held.wait + jitter)
}

// withheldTimeout is the armed resync's channel, or nil.
func (run *sessionRun) withheldTimeout() <-chan time.Time {
	if run.withheld.timer == nil {
		return nil
	}
	return run.withheld.timer.C
}

// resyncWithheld asks for the whole map, unless a resync already waits for
// its snapshot; the snapshot arms the next wait if it withholds too.
func (run *sessionRun) resyncWithheld() error {
	held := &run.withheld
	held.timer = nil
	held.wait = min(2*held.wait, withheldResyncMax)
	if run.resyncing || held.pending || !run.withholding() {
		return nil
	}
	held.pending = true
	held.sent++
	view := &mtcpv1.View{Epoch: run.state.epoch, Seq: run.state.seq}
	return run.send(sharedmtcp.MessageMapResync, &mtcpv1.MapResync{View: view})
}

// stopWithheld stops the resync when the session ends.
func (run *sessionRun) stopWithheld() {
	if run.withheld.timer != nil {
		run.withheld.timer.Stop()
		run.withheld.timer = nil
	}
}
