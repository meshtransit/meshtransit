package mtcp

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
)

// GatewayKeyRecorder records one report of a Kubernetes gateway's stale or
// contested key, as a sealed audit event of its Network (schema 229).
// machine is the node-domain fingerprint of the session's machine key.
type GatewayKeyRecorder interface {
	// keyID is the kid of a token signed by a key the trust lacks, else
	// empty (schema 235).
	Record(ctx context.Context, machine [32]byte, reason kubecluster.KeyEventReason,
		suppressed int, keyID string) (kubecluster.KeyEventOutcome, error)
}

const (
	// gatewayKeyReportHold is how long a key and reason recorded, or
	// limited, is not sent again; the database holds the same window.
	gatewayKeyReportHold = 10 * time.Minute
	// gatewayKeyRetryHold is how long a report that did not reach the
	// database waits before another is sent.
	gatewayKeyRetryHold = 30 * time.Second
	// gatewayKeyReportQueue bounds the reports waiting for the database.
	gatewayKeyReportQueue = 256
	// maxGatewayKeyReports bounds the keys and reasons remembered.
	maxGatewayKeyReports = 1 << 12
	// gatewayKeyRecordTimeout bounds one report's transaction.
	gatewayKeyRecordTimeout = 3 * time.Second
	// gatewayKeyWarnEvery spaces the warnings of one result.
	gatewayKeyWarnEvery = time.Minute
)

type gatewayKeyReportKey struct {
	machine [32]byte
	reason  kubecluster.KeyEventReason
}

type gatewayKeyReportState struct {
	holdUntil  time.Time
	suppressed int
}

type gatewayKeyReport struct {
	key        gatewayKeyReportKey
	suppressed int
	keyID      string
}

// gatewayKeyReporter records gateway key reports off the handshake path
// (K1a1 plan §15.3): report never blocks, one goroutine writes, and a
// bounded memory of keys keeps repeats from reaching the database. Its
// goroutine starts with the first report; stop ends it.
type gatewayKeyReporter struct {
	recorder GatewayKeyRecorder
	metrics  *Metrics
	logger   *slog.Logger
	now      func() time.Time
	queue    chan gatewayKeyReport

	ctx    context.Context
	cancel context.CancelFunc
	// start runs the goroutine once, or, when stop comes first, closes
	// stopped for it: stopped is closed exactly once either way.
	start   sync.Once
	stopped chan struct{}

	mu     sync.Mutex
	halted bool
	seen   map[gatewayKeyReportKey]*gatewayKeyReportState
	warned map[string]time.Time
}

func newGatewayKeyReporter(recorder GatewayKeyRecorder, metrics *Metrics, logger *slog.Logger,
	now func() time.Time, queue int) *gatewayKeyReporter {
	if recorder == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &gatewayKeyReporter{recorder: recorder, metrics: metrics, logger: logger, now: now,
		queue: make(chan gatewayKeyReport, queue), ctx: ctx, cancel: cancel, stopped: make(chan struct{}),
		seen: make(map[gatewayKeyReportKey]*gatewayKeyReportState), warned: make(map[string]time.Time)}
}

// report queues one report of machine for reason unless the same was sent
// within its hold; then it only counts it into the next event.
func (reporter *gatewayKeyReporter) report(machine [32]byte, reason kubecluster.KeyEventReason) {
	reporter.reportToken(machine, reason, "")
}

// reportToken is report for a refused rotation token: keyID names the key
// a token was signed with that the trust lacks, else empty. Reports folded
// into one event keep the kid sent with it.
func (reporter *gatewayKeyReporter) reportToken(machine [32]byte, reason kubecluster.KeyEventReason, keyID string) {
	if reporter == nil || !reason.IsKnown() {
		return
	}
	key := gatewayKeyReportKey{machine: machine, reason: reason}
	now := reporter.now()
	reporter.mu.Lock()
	if reporter.halted {
		reporter.mu.Unlock()
		reporter.metrics.gatewayKeyReported("dropped")
		return
	}
	state := reporter.seen[key]
	if state != nil && now.Before(state.holdUntil) {
		state.suppressed = min(state.suppressed+1, kubecluster.MaximumSuppressedReports)
		reporter.mu.Unlock()
		reporter.metrics.gatewayKeyReported("suppressed")
		return
	}
	if state == nil {
		if len(reporter.seen) >= maxGatewayKeyReports {
			reporter.forgetExpiredLocked(now)
		}
		if len(reporter.seen) >= maxGatewayKeyReports {
			reporter.mu.Unlock()
			reporter.metrics.gatewayKeyReported("dropped")
			return
		}
		state = &gatewayKeyReportState{}
		reporter.seen[key] = state
	}
	pending := gatewayKeyReport{key: key, suppressed: state.suppressed, keyID: keyID}
	state.suppressed, state.holdUntil = 0, now.Add(gatewayKeyReportHold)
	select {
	case reporter.queue <- pending:
	default:
		state.suppressed, state.holdUntil = pending.suppressed+1, now.Add(gatewayKeyRetryHold)
		reporter.mu.Unlock()
		reporter.metrics.gatewayKeyReported("dropped")
		return
	}
	reporter.mu.Unlock()
	reporter.start.Do(func() { go reporter.run() })
	if reporter.ctx.Err() != nil {
		// Stop came between the queue and the start: the report is lost.
		reporter.metrics.gatewayKeyReported("dropped")
	}
}

func (reporter *gatewayKeyReporter) forgetExpiredLocked(now time.Time) {
	for key, state := range reporter.seen {
		if !now.Before(state.holdUntil) {
			delete(reporter.seen, key)
		}
	}
}

// run writes queued reports, one transaction each, until stop.
func (reporter *gatewayKeyReporter) run() {
	defer close(reporter.stopped)
	for {
		select {
		case <-reporter.ctx.Done():
			return
		case pending := <-reporter.queue:
			reporter.record(pending)
		}
	}
}

func (reporter *gatewayKeyReporter) record(pending gatewayKeyReport) {
	ctx, cancel := context.WithTimeout(reporter.ctx, gatewayKeyRecordTimeout)
	outcome, err := reporter.recorder.Record(ctx, pending.key.machine, pending.key.reason, pending.suppressed,
		pending.keyID)
	cancel()
	result := "failed"
	switch {
	case err != nil:
	case outcome == kubecluster.KeyEventRecorded:
		result = "recorded"
	case outcome == kubecluster.KeyEventLimited:
		result = "limited"
	case outcome == kubecluster.KeyEventBusy:
		result = "busy"
	case outcome == kubecluster.KeyEventNotGateway:
		result = "unknown"
	}
	reporter.metrics.gatewayKeyReported(result)
	// Recorded, limited and unknown are final; unknown means the gate and
	// the database disagree, so it is also warned about.
	if result == "recorded" || result == "limited" {
		return
	}
	hold := gatewayKeyRetryHold
	if result == "unknown" {
		hold = gatewayKeyReportHold
	}
	// What did not reach the database is sent again soon, with its count.
	now := reporter.now()
	reporter.mu.Lock()
	if state := reporter.seen[pending.key]; state != nil {
		state.suppressed = min(state.suppressed+pending.suppressed+1, kubecluster.MaximumSuppressedReports)
		state.holdUntil = now.Add(hold)
	}
	warn := result != "busy" && now.Sub(reporter.warned[result]) >= gatewayKeyWarnEvery
	if warn {
		reporter.warned[result] = now
	}
	reporter.mu.Unlock()
	if warn && reporter.ctx.Err() == nil {
		reporter.logger.Warn("mtcp gateway key report not recorded", "result", result,
			"error_code", "gateway_key_audit_"+result)
	}
}

// stop ends the goroutine, cancelling the report it is writing; queued
// reports are dropped (the metrics counted them) and later ones go nowhere.
func (reporter *gatewayKeyReporter) stop() {
	if reporter == nil {
		return
	}
	reporter.mu.Lock()
	reporter.halted = true
	reporter.mu.Unlock()
	reporter.cancel()
	reporter.start.Do(func() { close(reporter.stopped) })
	<-reporter.stopped
}
