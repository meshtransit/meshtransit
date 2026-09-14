package revisionfeed

import "sync/atomic"

// Telemetry owns race-safe, bounded-cardinality revision-feed signals.
type Telemetry struct {
	connected      atomic.Bool
	watchers       atomic.Int64
	wakeupsTotal   atomic.Uint64
	deliveredTotal atomic.Uint64
	coalescedTotal atomic.Uint64
}

// TelemetrySnapshot is one read-only process-local observation.
type TelemetrySnapshot struct {
	Connected      bool
	ActiveWatchers int64
	WakeupsTotal   uint64
	DeliveredTotal uint64
	CoalescedTotal uint64
}

// NewTelemetry constructs zeroed feed telemetry.
func NewTelemetry() *Telemetry { return &Telemetry{} }

// Snapshot returns current metrics without blocking the receive goroutine.
func (telemetry *Telemetry) Snapshot() TelemetrySnapshot {
	if telemetry == nil {
		return TelemetrySnapshot{}
	}
	return TelemetrySnapshot{
		Connected:      telemetry.connected.Load(),
		ActiveWatchers: telemetry.watchers.Load(),
		WakeupsTotal:   telemetry.wakeupsTotal.Load(),
		DeliveredTotal: telemetry.deliveredTotal.Load(),
		CoalescedTotal: telemetry.coalescedTotal.Load(),
	}
}

func (telemetry *Telemetry) setConnected(connected bool) { telemetry.connected.Store(connected) }
func (telemetry *Telemetry) watcherOpened()              { telemetry.watchers.Add(1) }
func (telemetry *Telemetry) watcherClosed()              { telemetry.watchers.Add(-1) }

func (telemetry *Telemetry) recordWakeup(delivered, coalesced uint64) {
	telemetry.wakeupsTotal.Add(1)
	telemetry.deliveredTotal.Add(delivered)
	telemetry.coalescedTotal.Add(coalesced)
}
