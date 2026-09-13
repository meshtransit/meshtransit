package revisionworker

import (
	"sync/atomic"
	"time"
)

// Telemetry owns the revision worker's process-local operational counters and
// gauges. Updates and snapshots are race-safe and never block delivery work.
type Telemetry struct {
	readyBacklog        atomic.Pointer[Backlog]
	backlogSuccessTotal atomic.Uint64
	backlogErrorTotal   atomic.Uint64
	claimSuccessTotal   atomic.Uint64
	claimErrorTotal     atomic.Uint64
	claimedEventsTotal  atomic.Uint64
	deliveredTotal      atomic.Uint64
	deferredTotal       atomic.Uint64
	failedTotal         atomic.Uint64
}

// TelemetrySnapshot is a read-only, point-in-time view for operator adapters.
// Counters may advance while a concurrent snapshot is taken. The two backlog
// gauges always come from the same immutable observation.
type TelemetrySnapshot struct {
	ReadyBacklogEvents  int64
	OldestReadyEventAge time.Duration
	BacklogSuccessTotal uint64
	BacklogErrorTotal   uint64
	ClaimSuccessTotal   uint64
	ClaimErrorTotal     uint64
	ClaimedEventsTotal  uint64
	DeliveredTotal      uint64
	DeferredTotal       uint64
	FailedTotal         uint64
}

// NewTelemetry constructs zeroed process-local worker telemetry.
func NewTelemetry() *Telemetry {
	return &Telemetry{}
}

// Snapshot returns the current operational measurements without blocking the
// dispatch goroutine.
func (telemetry *Telemetry) Snapshot() TelemetrySnapshot {
	if telemetry == nil {
		return TelemetrySnapshot{}
	}
	var readyBacklog Backlog
	if observed := telemetry.readyBacklog.Load(); observed != nil {
		readyBacklog = *observed
	}
	return TelemetrySnapshot{
		ReadyBacklogEvents:  readyBacklog.Events(),
		OldestReadyEventAge: readyBacklog.OldestAge(),
		BacklogSuccessTotal: telemetry.backlogSuccessTotal.Load(),
		BacklogErrorTotal:   telemetry.backlogErrorTotal.Load(),
		ClaimSuccessTotal:   telemetry.claimSuccessTotal.Load(),
		ClaimErrorTotal:     telemetry.claimErrorTotal.Load(),
		ClaimedEventsTotal:  telemetry.claimedEventsTotal.Load(),
		DeliveredTotal:      telemetry.deliveredTotal.Load(),
		DeferredTotal:       telemetry.deferredTotal.Load(),
		FailedTotal:         telemetry.failedTotal.Load(),
	}
}

func (telemetry *Telemetry) recordBacklog(backlog Backlog) {
	telemetry.readyBacklog.Store(&backlog)
	telemetry.backlogSuccessTotal.Add(1)
}

func (telemetry *Telemetry) recordBacklogError() {
	telemetry.backlogErrorTotal.Add(1)
}

func (telemetry *Telemetry) recordClaim(claimed int, err error) {
	if err != nil {
		telemetry.claimErrorTotal.Add(1)
		return
	}
	telemetry.claimSuccessTotal.Add(1)
	for range claimed {
		telemetry.claimedEventsTotal.Add(1)
	}
}

type deliveryOutcome uint8

const (
	deliveryDelivered deliveryOutcome = iota
	deliveryDeferred
	deliveryFailed
)

func (telemetry *Telemetry) recordDelivery(outcome deliveryOutcome) {
	switch outcome {
	case deliveryDelivered:
		telemetry.deliveredTotal.Add(1)
	case deliveryDeferred:
		telemetry.deferredTotal.Add(1)
	case deliveryFailed:
		telemetry.failedTotal.Add(1)
	}
}
