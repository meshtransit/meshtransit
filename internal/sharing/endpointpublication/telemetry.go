package endpointpublication

import "sync/atomic"

type operation uint8

const (
	operationPublication operation = iota
	operationWithdrawal
)

type attemptResult uint8

const (
	resultSucceeded attemptResult = iota
	resultDeferred
)

// Telemetry stores bounded, identifier-free process-local measurements.
type Telemetry struct {
	running               atomic.Bool
	passes                atomic.Uint64
	publicationCandidates atomic.Int64
	withdrawalCandidates  atomic.Int64
	publicationListErrors atomic.Uint64
	withdrawalListErrors  atomic.Uint64
	publicationSucceeded  atomic.Uint64
	publicationDeferred   atomic.Uint64
	withdrawalSucceeded   atomic.Uint64
	withdrawalDeferred    atomic.Uint64
}

// TelemetrySnapshot is one race-safe operator view.
type TelemetrySnapshot struct {
	Running               bool
	Passes                uint64
	PublicationCandidates int64
	WithdrawalCandidates  int64
	PublicationListErrors uint64
	WithdrawalListErrors  uint64
	PublicationSucceeded  uint64
	PublicationDeferred   uint64
	WithdrawalSucceeded   uint64
	WithdrawalDeferred    uint64
}

// NewTelemetry returns zeroed worker measurements.
func NewTelemetry() *Telemetry { return &Telemetry{} }

// Snapshot returns identifier-free current values.
func (telemetry *Telemetry) Snapshot() TelemetrySnapshot {
	if telemetry == nil {
		return TelemetrySnapshot{}
	}
	return TelemetrySnapshot{
		Running: telemetry.running.Load(), Passes: telemetry.passes.Load(),
		PublicationCandidates: telemetry.publicationCandidates.Load(),
		WithdrawalCandidates:  telemetry.withdrawalCandidates.Load(),
		PublicationListErrors: telemetry.publicationListErrors.Load(),
		WithdrawalListErrors:  telemetry.withdrawalListErrors.Load(),
		PublicationSucceeded:  telemetry.publicationSucceeded.Load(),
		PublicationDeferred:   telemetry.publicationDeferred.Load(),
		WithdrawalSucceeded:   telemetry.withdrawalSucceeded.Load(),
		WithdrawalDeferred:    telemetry.withdrawalDeferred.Load(),
	}
}

func (telemetry *Telemetry) setRunning(value bool) { telemetry.running.Store(value) }
func (telemetry *Telemetry) recordPass()           { telemetry.passes.Add(1) }

func (telemetry *Telemetry) observeCandidates(kind operation, count int, err error) {
	if kind == operationPublication {
		if err != nil {
			telemetry.publicationListErrors.Add(1)
			return
		}
		telemetry.publicationCandidates.Store(int64(count))
		return
	}
	if err != nil {
		telemetry.withdrawalListErrors.Add(1)
		return
	}
	telemetry.withdrawalCandidates.Store(int64(count))
}

func (telemetry *Telemetry) recordAttempt(kind operation, result attemptResult) {
	switch {
	case kind == operationPublication && result == resultSucceeded:
		telemetry.publicationSucceeded.Add(1)
	case kind == operationPublication:
		telemetry.publicationDeferred.Add(1)
	case result == resultSucceeded:
		telemetry.withdrawalSucceeded.Add(1)
	default:
		telemetry.withdrawalDeferred.Add(1)
	}
}
