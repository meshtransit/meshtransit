// Package enforcementledger records, over time, whether each Device enforced
// the rules the control plane delivered to it (R1-69 increment B).
//
// The worker reads every active or suspended Device of the installation,
// classifies its enforcement evidence exactly as the distribution read does,
// and records what changed: a new validity interval when the state or either
// digest changes, and a sealed audit event when a Device starts or stops
// enforcing other rules than it was given. Applying, unreported and unknown
// observations record nothing, so the last evidence stands.
package enforcementledger

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/shared/policydigest"
)

const (
	// NetworkPageSize bounds one Network discovery read.
	NetworkPageSize = 200
	// DevicePageSize bounds one Device read.
	DevicePageSize = 500
	// observationBatch matches the delivery record loader's bound.
	observationBatch = distribution.MaximumObservationBatch
	// PruneBatchSize bounds the rows one retention call removes.
	PruneBatchSize = 1000
	// maximumPrunePasses bounds the retention calls of one maintenance round.
	maximumPrunePasses = 20
	// maximumNetworkPages bounds one pass to 20,000 Networks.
	maximumNetworkPages = 100
	// maximumDevicePages bounds one Network to 25,000 Devices per pass.
	maximumDevicePages = 50
)

var (
	// ErrInvalidWorker rejects unsafe dependencies or timing bounds.
	ErrInvalidWorker = errors.New("enforcement ledger worker: invalid configuration")
	// ErrWorkerStarted rejects duplicate lifecycle ownership.
	ErrWorkerStarted = errors.New("enforcement ledger worker: already started")
	// ErrWorkerNotStarted rejects shutdown before startup.
	ErrWorkerNotStarted = errors.New("enforcement ledger worker: not started")
)

// State is recorded enforcement evidence.
type State string

const (
	// StateEnforced means the Device reported the delivered rules.
	StateEnforced State = "enforced"
	// StateMismatch means the Device reported other rules past the grace period.
	StateMismatch State = "mismatch"
)

// Interval is the open evidence of one Device; the zero value means none.
type Interval struct {
	State     State
	Delivered policydigest.Digest
	Enforced  policydigest.Digest
}

// Target is one Device to classify with its open interval.
type Target struct {
	DeviceID node.ID
	Open     Interval
}

// Observation is one classified Device to record.
type Observation struct {
	Scope           network.Scope
	DeviceID        node.ID
	NetworkRevision int64
	Delivered       distribution.FilterSummary
	Enforced        distribution.FilterSummary
	AppliedAt       time.Time
	ReportedAt      time.Time
}

// State returns the recorded state the observation implies.
func (observation Observation) State() State {
	if observation.Delivered.Digest == observation.Enforced.Digest {
		return StateEnforced
	}
	return StateMismatch
}

// Outcome is what one record call did.
type Outcome uint8

const (
	// OutcomeUnchanged found the open interval already current.
	OutcomeUnchanged Outcome = iota
	// OutcomeRecorded opened a new interval without an audit event.
	OutcomeRecorded
	// OutcomeAudited opened a new interval and sealed an audit event.
	OutcomeAudited
	// OutcomeBusy found another worker recording the same Device.
	OutcomeBusy
)

// Directory discovers Networks and their Devices.
type Directory interface {
	ListNetworks(ctx context.Context, installation deployment.ID, after network.ID, limit int) ([]network.Scope, error)
	ListDevices(ctx context.Context, installation deployment.ID, scope network.Scope, after node.ID,
		limit int) ([]Target, error)
}

// Recorder records one observation in one transaction.
type Recorder interface {
	Record(ctx context.Context, installation deployment.ID, observation Observation) (Outcome, error)
}

// Pruner removes rows past retention and returns how many it removed.
type Pruner interface {
	Prune(ctx context.Context, installation deployment.ID, limit int) (int, error)
}

// Options binds one process to an exact installation and finite work.
type Options struct {
	DeploymentID                                  deployment.ID
	PollInterval, PruneInterval, OperationTimeout time.Duration
}

func (options Options) valid() bool {
	return options.DeploymentID.IsValid() &&
		options.PollInterval >= 100*time.Millisecond && options.PollInterval <= 5*time.Minute &&
		options.PruneInterval >= time.Minute && options.PruneInterval <= 24*time.Hour &&
		options.OperationTimeout >= 100*time.Millisecond && options.OperationTimeout <= 30*time.Second
}

// Worker owns one goroutine. Nothing is cached between passes: every pass
// re-reads the open intervals, so a failed record is retried on the next.
type Worker struct {
	options      Options
	directory    Directory
	observations distribution.ObservationLoader
	recorder     Recorder
	pruner       Pruner
	logger       *slog.Logger
	now          func() time.Time

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan error

	running                                                    atomic.Bool
	passes, readErrors, recorded, audited, unchanged, deferred atomic.Uint64
	pruned, pruneErrors                                        atomic.Uint64
}

// Measurements exposes bounded, identifier-free process measurements.
type Measurements struct {
	Running                                                    bool
	Passes, ReadErrors, Recorded, Audited, Unchanged, Deferred uint64
	Pruned, PruneErrors                                        uint64
}

// New constructs a stopped worker without I/O.
func New(options Options, directory Directory, observations distribution.ObservationLoader, recorder Recorder,
	pruner Pruner, logger *slog.Logger) (*Worker, error) {
	if !options.valid() || nilPort(directory) || nilPort(observations) || nilPort(recorder) || nilPort(pruner) ||
		logger == nil {
		return nil, ErrInvalidWorker
	}
	return &Worker{options: options, directory: directory, observations: observations, recorder: recorder,
		pruner: pruner, logger: logger, now: time.Now}, nil
}

func nilPort(port any) bool {
	if port == nil {
		return true
	}
	value := reflect.ValueOf(port)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// Start owns cancellation separately from the caller's startup context.
func (worker *Worker) Start(ctx context.Context) error {
	if worker == nil || ctx == nil {
		return ErrInvalidWorker
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if worker.started {
		return ErrWorkerStarted
	}
	owned, cancel := context.WithCancel(context.WithoutCancel(ctx))
	worker.cancel, worker.done, worker.started = cancel, make(chan error, 1), true
	go func() {
		worker.running.Store(true)
		worker.run(owned)
		worker.running.Store(false)
		worker.done <- nil
		close(worker.done)
	}()
	return nil
}

// Done is the process-owned lifecycle join, available after Start.
func (worker *Worker) Done() <-chan error {
	if worker == nil {
		return nil
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	return worker.done
}

// Shutdown cancels finite work. Done is the join path used by the process owner.
func (worker *Worker) Shutdown(ctx context.Context) error {
	if worker == nil || ctx == nil {
		return ErrInvalidWorker
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if !worker.started {
		return ErrWorkerNotStarted
	}
	worker.cancel()
	return nil
}

// Snapshot returns race-safe measurements without tenant identifiers.
func (worker *Worker) Snapshot() Measurements {
	if worker == nil {
		return Measurements{}
	}
	return Measurements{
		Running: worker.running.Load(), Passes: worker.passes.Load(), ReadErrors: worker.readErrors.Load(),
		Recorded: worker.recorded.Load(), Audited: worker.audited.Load(), Unchanged: worker.unchanged.Load(),
		Deferred: worker.deferred.Load(), Pruned: worker.pruned.Load(), PruneErrors: worker.pruneErrors.Load(),
	}
}

func (worker *Worker) run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	var lastPrune time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if lastPrune.IsZero() || time.Since(lastPrune) >= worker.options.PruneInterval {
				worker.prune(ctx)
				lastPrune = time.Now()
			}
			worker.sweep(ctx)
			if ctx.Err() != nil {
				return
			}
			timer.Reset(worker.options.PollInterval)
		}
	}
}

// sweep classifies every Device once. A failed read skips the rest of that
// Network or of the pass; the next pass starts over.
func (worker *Worker) sweep(ctx context.Context) {
	worker.passes.Add(1)
	var after network.ID
	for range maximumNetworkPages {
		var scopes []network.Scope
		err := worker.bounded(ctx, func(operationCtx context.Context) error {
			var listErr error
			scopes, listErr = worker.directory.ListNetworks(operationCtx, worker.options.DeploymentID, after,
				NetworkPageSize)
			return listErr
		})
		if err != nil || len(scopes) > NetworkPageSize {
			worker.readFailed(ctx, "enforcement_ledger_networks_failed")
			return
		}
		for _, scope := range scopes {
			if ctx.Err() != nil {
				return
			}
			worker.sweepNetwork(ctx, scope)
		}
		if len(scopes) < NetworkPageSize {
			return
		}
		after = scopes[len(scopes)-1].NetworkID()
	}
}

func (worker *Worker) sweepNetwork(ctx context.Context, scope network.Scope) {
	var after node.ID
	for range maximumDevicePages {
		var targets []Target
		err := worker.bounded(ctx, func(operationCtx context.Context) error {
			var listErr error
			targets, listErr = worker.directory.ListDevices(operationCtx, worker.options.DeploymentID, scope, after,
				DevicePageSize)
			return listErr
		})
		if err != nil || len(targets) > DevicePageSize {
			worker.readFailed(ctx, "enforcement_ledger_devices_failed")
			return
		}
		for start := 0; start < len(targets); start += observationBatch {
			if !worker.classify(ctx, scope, targets[start:min(start+observationBatch, len(targets))]) {
				return
			}
		}
		if len(targets) < DevicePageSize {
			return
		}
		after = targets[len(targets)-1].DeviceID
	}
}

// classify loads one batch of observations and records those that changed.
// It reports false when the batch could not be read.
func (worker *Worker) classify(ctx context.Context, scope network.Scope, targets []Target) bool {
	ids := make([]node.ID, len(targets))
	for index, target := range targets {
		ids[index] = target.DeviceID
	}
	var observed []distribution.Observation
	err := worker.bounded(ctx, func(operationCtx context.Context) error {
		var loadErr error
		observed, loadErr = worker.observations.LoadObservations(operationCtx, ids)
		return loadErr
	})
	if err != nil || len(observed) != len(targets) {
		worker.readFailed(ctx, "enforcement_ledger_observations_failed")
		return false
	}
	now := worker.now()
	for index, target := range targets {
		observation, ok := evidenceOf(scope, target.DeviceID, observed[index], now)
		if !ok || target.Open == (Interval{State: observation.State(), Delivered: observation.Delivered.Digest,
			Enforced: observation.Enforced.Digest}) {
			continue
		}
		worker.record(ctx, observation)
	}
	return true
}

// evidenceOf turns a Device's delivery record into recordable evidence:
// only an enforced or mismatched classification counts.
func evidenceOf(scope network.Scope, deviceID node.ID, observed distribution.Observation,
	now time.Time) (Observation, bool) {
	if !observed.IsValid() {
		return Observation{}, false
	}
	switch distribution.ClassifyEnforcement(observed, now) {
	case distribution.EnforcementEnforced, distribution.EnforcementMismatch:
	default:
		return Observation{}, false
	}
	if observed.Enforced.IsZero() || observed.Filter.IsZero() {
		return Observation{}, false
	}
	return Observation{
		Scope: scope, DeviceID: deviceID, NetworkRevision: observed.NetworkRevision,
		Delivered: observed.Filter, Enforced: observed.Enforced,
		AppliedAt: observed.AppliedAt, ReportedAt: observed.ReportedAt,
	}, true
}

func (worker *Worker) record(ctx context.Context, observation Observation) {
	var outcome Outcome
	err := worker.bounded(ctx, func(operationCtx context.Context) error {
		var recordErr error
		outcome, recordErr = worker.recorder.Record(operationCtx, worker.options.DeploymentID, observation)
		return recordErr
	})
	if err != nil {
		worker.deferred.Add(1)
		if ctx.Err() == nil {
			worker.logger.WarnContext(ctx, "enforcement evidence deferred", "error_code", "enforcement_ledger_deferred")
		}
		return
	}
	switch outcome {
	case OutcomeRecorded:
		worker.recorded.Add(1)
	case OutcomeAudited:
		worker.recorded.Add(1)
		worker.audited.Add(1)
	case OutcomeUnchanged:
		worker.unchanged.Add(1)
	case OutcomeBusy:
		worker.deferred.Add(1)
	}
}

func (worker *Worker) bounded(ctx context.Context, operation func(context.Context) error) error {
	operationCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	return errors.Join(operation(operationCtx), operationCtx.Err())
}

func (worker *Worker) readFailed(ctx context.Context, code string) {
	if ctx.Err() != nil {
		return
	}
	worker.readErrors.Add(1)
	worker.logger.WarnContext(ctx, "enforcement ledger read deferred", "error_code", code)
}

func (worker *Worker) prune(ctx context.Context) {
	for range maximumPrunePasses {
		if ctx.Err() != nil {
			return
		}
		var removed int
		err := worker.bounded(ctx, func(operationCtx context.Context) error {
			var pruneErr error
			removed, pruneErr = worker.pruner.Prune(operationCtx, worker.options.DeploymentID, PruneBatchSize)
			return pruneErr
		})
		if err != nil || removed < 0 {
			if ctx.Err() == nil {
				worker.pruneErrors.Add(1)
				worker.logger.WarnContext(ctx, "enforcement ledger retention deferred",
					"error_code", "enforcement_ledger_prune_failed")
			}
			return
		}
		worker.pruned.Add(uint64(removed))
		if removed < PruneBatchSize {
			return
		}
	}
}
