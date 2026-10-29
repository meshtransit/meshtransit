package kubeaudit

import (
	"context"
	"slices"
	"sync"
	"time"

	"meshtransit.net/client/internal/controlplane"
)

const (
	// maximumOutcomes and maximumDenials bound one report (mtcp-v1 §6.10);
	// maximumHeldOutcomes bounds those waiting: past it new ones are
	// dropped and counted.
	maximumOutcomes     = 1024
	maximumDenials      = 256
	maximumHeldOutcomes = 4 * maximumOutcomes
)

// denialKey names one count of refused requests.
type denialKey struct {
	peer, reason string
}

// reports holds outcomes and denials until they are sent; nothing waits on
// them, and what does not fit is counted, never queued without bound.
type reports struct {
	mu       sync.Mutex
	outcomes []controlplane.KubeAuditOutcome
	denials  map[denialKey]*controlplane.KubeAuditDenials
	dropped  uint64
}

func newReports() *reports {
	return &reports{denials: map[denialKey]*controlplane.KubeAuditDenials{}}
}

// finished holds an outcome; status 0 is an operation recorded but never
// forwarded.
func (held *reports) finished(auditID [16]byte, status int, duration time.Duration) {
	held.mu.Lock()
	defer held.mu.Unlock()
	if len(held.outcomes) >= maximumHeldOutcomes {
		held.dropped++
		return
	}
	held.outcomes = append(held.outcomes, controlplane.KubeAuditOutcome{AuditID: auditID, Status: status,
		Duration: duration})
}

// denied counts a refused request of peer for reason. Past maximumDenials
// counts, a new peer's go to the reason's unnamed count.
func (held *reports) denied(peer, reason string, at time.Time) {
	if !slices.Contains(denialReasons, reason) {
		reason = "other" // Core takes no other (review b2 L3)
	}
	held.mu.Lock()
	defer held.mu.Unlock()
	key := denialKey{peer: peer, reason: reason}
	if _, found := held.denials[key]; !found && len(held.denials) >= maximumDenials-len(denialReasons) {
		key.peer = ""
	}
	count, found := held.denials[key]
	if !found {
		count = &controlplane.KubeAuditDenials{Peer: key.peer, Reason: reason, First: at}
		held.denials[key] = count
	}
	count.Count++
	count.Last = at
}

// denialReasons are the reasons a type B count may give: room is kept for
// each reason's unnamed count.
var denialReasons = []string{"unauthenticated", "forbidden", "not_granted", "stale", "limited", "other"}

// takeOutcomes removes up to one report's outcomes.
func (held *reports) takeOutcomes() []controlplane.KubeAuditOutcome {
	held.mu.Lock()
	defer held.mu.Unlock()
	n := min(len(held.outcomes), maximumOutcomes)
	taken := append([]controlplane.KubeAuditOutcome(nil), held.outcomes[:n]...)
	held.outcomes = append(held.outcomes[:0], held.outcomes[n:]...)
	return taken
}

// takeDenials removes every count.
func (held *reports) takeDenials() []controlplane.KubeAuditDenials {
	held.mu.Lock()
	defer held.mu.Unlock()
	taken := make([]controlplane.KubeAuditDenials, 0, len(held.denials))
	for key, count := range held.denials {
		taken = append(taken, *count)
		delete(held.denials, key)
	}
	return taken
}

// drop counts rows a report could not deliver.
func (held *reports) drop(rows int) {
	held.mu.Lock()
	defer held.mu.Unlock()
	held.dropped += uint64(rows) //nolint:gosec // a count of rows
}

// reportLoop sends outcomes every ReportWindow and denials every
// DenialWindow; a report the stream does not take within the window is
// dropped and counted.
func (recorder *Recorder) reportLoop(ctx context.Context) {
	outcomes := time.NewTicker(recorder.options.ReportWindow)
	defer outcomes.Stop()
	denials := time.NewTicker(recorder.options.DenialWindow)
	defer denials.Stop()
	for {
		var report controlplane.KubeAuditReport
		select {
		case <-ctx.Done():
			return
		case <-outcomes.C:
			report.Outcomes = recorder.reports.takeOutcomes()
		case <-denials.C:
			report.Denials = recorder.reports.takeDenials()
		}
		if len(report.Outcomes)+len(report.Denials) == 0 {
			continue
		}
		recorder.mu.Lock()
		// A report spends Core's audit budget as a batch does.
		recorder.messages.refill(messageRate, messageBurst, time.Now())
		recorder.messages.tokens -= messageFloor
		recorder.mu.Unlock()
		timer := time.NewTimer(recorder.options.ReportWindow)
		select {
		case recorder.options.Reports <- report:
		case <-timer.C:
			recorder.reports.drop(len(report.Outcomes) + len(report.Denials))
		case <-ctx.Done():
			timer.Stop()
			return
		}
		timer.Stop()
	}
}

// Measurements are a recorder's counts, for metrics.
type Measurements struct {
	Queued, InFlight int
	Rate             float64
	Paused           bool
	DroppedReports   uint64
}

// Snapshot returns the recorder's counts.
func (recorder *Recorder) Snapshot() Measurements {
	recorder.mu.Lock()
	measured := Measurements{Queued: recorder.queued, InFlight: recorder.inFlight, Rate: recorder.rate,
		Paused: time.Now().Before(recorder.paused)}
	recorder.mu.Unlock()
	recorder.reports.mu.Lock()
	measured.DroppedReports = recorder.reports.dropped
	recorder.reports.mu.Unlock()
	return measured
}
