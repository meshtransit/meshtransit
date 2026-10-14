package mtcp

import (
	"sync"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/domain/node"
)

// enforcementPacing stores a session's EnforcementReports at most at the
// enforcement budget's rate (mtcp-v1 §8.4). A report over it is kept,
// replacing any kept before, and stored when the budget allows: the node
// sends evidence only when it changes and with its heartbeat, so the latest
// report is never dropped. One store runs at a time (busy), in the order
// the reports arrived; mu is never held across the store.
type enforcementPacing struct {
	mu      sync.Mutex
	running sync.WaitGroup
	stopped bool
	busy    bool
	budget  rateBudget
	waiting *keptEnforcement
	timer   endpointTimer
}

// keptEnforcement is a report and the node key the session had when it
// arrived.
type keptEnforcement struct {
	report  *mtcpv1.EnforcementReport
	nodeKey node.Key
}

// reportEnforcement stores report now, or keeps it until the budget allows.
func (conversation *conversation) reportEnforcement(report *mtcpv1.EnforcementReport) {
	pacing := &conversation.enforcementPacing
	pacing.mu.Lock()
	if pacing.stopped {
		pacing.mu.Unlock()
		return
	}
	// A newer report replaces a kept one.
	pacing.waiting = &keptEnforcement{report: report, nodeKey: conversation.currentKey()}
	next, ok, refused := conversation.claimEnforcementLocked()
	if refused {
		conversation.application.options.Metrics.limited(limitEnforcement)
	}
	pacing.mu.Unlock()
	if ok {
		conversation.storeEnforcement(next)
	}
}

// flushEnforcement is the timer: it stores the kept report once the budget
// allows.
func (conversation *conversation) flushEnforcement() {
	pacing := &conversation.enforcementPacing
	pacing.mu.Lock()
	next, ok, _ := conversation.claimEnforcementLocked()
	pacing.mu.Unlock()
	if ok {
		conversation.storeEnforcement(next)
	}
}

// claimEnforcementLocked takes the kept report if it may be stored now, or
// arms the timer for when it may; refused reports that the budget, not a
// store in flight, held it back.
func (conversation *conversation) claimEnforcementLocked() (kept *keptEnforcement, ok, refused bool) {
	pacing := &conversation.enforcementPacing
	if pacing.stopped || pacing.busy || pacing.waiting == nil {
		return nil, false, false
	}
	now := conversation.application.now()
	if wait, admitted := pacing.budget.spend(now, 1); !admitted {
		delay := max(wait, time.Millisecond)
		if pacing.timer == nil {
			pacing.timer = conversation.application.enforcementTimer(delay, conversation.flushEnforcement)
		} else {
			pacing.timer.Reset(delay)
		}
		return nil, false, true
	}
	kept = pacing.waiting
	pacing.waiting, pacing.busy = nil, true
	pacing.running.Add(1)
	return kept, true, false
}

// storeEnforcement stores claimed reports until none may be stored now.
func (conversation *conversation) storeEnforcement(kept *keptEnforcement) {
	pacing := &conversation.enforcementPacing
	for {
		conversation.enforcement(conversation.session.ctx, kept.report, kept.nodeKey)
		pacing.mu.Lock()
		pacing.busy = false
		pacing.running.Done()
		next, ok, _ := conversation.claimEnforcementLocked()
		pacing.mu.Unlock()
		if !ok {
			return
		}
		kept = next
	}
}

// stopEnforcementPacing ends the pacing when the session ends, dropping a
// kept report, and waits for a store already running; the store's own
// coordination timeout bounds that wait.
func (conversation *conversation) stopEnforcementPacing() {
	pacing := &conversation.enforcementPacing
	pacing.mu.Lock()
	pacing.stopped = true
	pacing.waiting = nil
	if pacing.timer != nil {
		pacing.timer.Stop()
	}
	pacing.mu.Unlock()
	pacing.running.Wait()
}
