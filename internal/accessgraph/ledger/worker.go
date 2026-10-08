// Package ledger records the effective access edges of each Network over
// time and reads them back at a past instant (R1-68).
//
// After a Network revision the worker records the edge set of that revision:
// edges that appeared open, edges that vanished close, and each recorded
// change is sealed as an audit event with a digest of the whole set. Reads at
// time T return the edges whose validity contains T, with the time each one
// began.
package ledger

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/network"
)

const (
	maximumBatchSize = 64
	// PruneBatchSize bounds the rows one retention call removes.
	PruneBatchSize = 1000
	// maximumPrunePasses bounds the retention calls of one maintenance round.
	maximumPrunePasses = 20
	// maximumRetryDelay caps the backoff of a Network that fails to record.
	maximumRetryDelay = 5 * time.Minute
)

var (
	// ErrInvalidWorker rejects unsafe dependencies or timing bounds.
	ErrInvalidWorker = errors.New("access ledger worker: invalid configuration")
	// ErrWorkerStarted rejects duplicate lifecycle ownership.
	ErrWorkerStarted = errors.New("access ledger worker: already started")
	// ErrWorkerNotStarted rejects shutdown before startup.
	ErrWorkerNotStarted = errors.New("access ledger worker: not started")
)

// Outcome is what one record call did.
type Outcome uint8

const (
	// OutcomeUnchanged advanced the ledger without a change in the edge set,
	// or found it already current.
	OutcomeUnchanged Outcome = iota
	// OutcomeRecorded wrote a sealed snapshot.
	OutcomeRecorded
	// OutcomeBusy found another worker recording the same Network.
	OutcomeBusy
)

// Due discovers Networks whose revision is newer than the ledger.
type Due interface {
	ListDue(ctx context.Context, installation deployment.ID, limit int) ([]network.Scope, error)
}

// Recorder records the current revision of one Network in one transaction.
type Recorder interface {
	Record(ctx context.Context, installation deployment.ID, scope network.Scope) (Outcome, error)
}

// Pruner removes ledger rows past retention and returns how many it removed.
type Pruner interface {
	Prune(ctx context.Context, installation deployment.ID, limit int) (int, error)
}

// Options binds one process to an exact installation and finite sequential work.
type Options struct {
	DeploymentID                                  deployment.ID
	BatchSize                                     int
	PollInterval, PruneInterval, OperationTimeout time.Duration
}

func (options Options) valid() bool {
	return options.DeploymentID.IsValid() && options.BatchSize >= 1 && options.BatchSize <= maximumBatchSize &&
		options.PollInterval >= 100*time.Millisecond && options.PollInterval <= time.Minute &&
		options.PruneInterval >= time.Minute && options.PruneInterval <= 24*time.Hour &&
		options.OperationTimeout >= 100*time.Millisecond && options.OperationTimeout <= 30*time.Second
}

// Worker owns one goroutine. A failed Network is retried on the next pass
// from committed state; nothing is cached between passes.
type Worker struct {
	options  Options
	due      Due
	recorder Recorder
	pruner   Pruner
	logger   *slog.Logger

	// backoff is owned by the worker goroutine.
	backoff map[network.Scope]retryState

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan error

	running                                                atomic.Bool
	passes, discoveryErrors, recorded, unchanged, deferred atomic.Uint64
	pruned, pruneErrors                                    atomic.Uint64
}

type retryState struct {
	failures int
	until    time.Time
}

// Measurements exposes bounded, identifier-free process measurements.
type Measurements struct {
	Running                                                bool
	Passes, DiscoveryErrors, Recorded, Unchanged, Deferred uint64
	Pruned, PruneErrors                                    uint64
}

// New constructs a stopped worker without I/O.
func New(options Options, due Due, recorder Recorder, pruner Pruner, logger *slog.Logger) (*Worker, error) {
	if !options.valid() || nilPort(due) || nilPort(recorder) || nilPort(pruner) || logger == nil {
		return nil, ErrInvalidWorker
	}
	return &Worker{options: options, due: due, recorder: recorder, pruner: pruner, logger: logger,
		backoff: make(map[network.Scope]retryState)}, nil
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
		Running: worker.running.Load(), Passes: worker.passes.Load(), DiscoveryErrors: worker.discoveryErrors.Load(),
		Recorded: worker.recorded.Load(), Unchanged: worker.unchanged.Load(), Deferred: worker.deferred.Load(),
		Pruned: worker.pruned.Load(), PruneErrors: worker.pruneErrors.Load(),
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

// retryDelay backs off a Network whose record keeps failing, so a Network
// that cannot be recorded does not hold the head of every batch.
func (worker *Worker) retryDelay(failures int) time.Duration {
	delay := worker.options.PollInterval
	for range min(failures, 16) {
		delay *= 2
		if delay >= maximumRetryDelay {
			return maximumRetryDelay
		}
	}
	return delay
}

func (worker *Worker) sweep(ctx context.Context) {
	worker.passes.Add(1)
	// Ask for enough Networks to fill a batch past those backing off.
	limit := min(maximumBatchSize, worker.options.BatchSize+len(worker.backoff))
	readCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	scopes, err := worker.due.ListDue(readCtx, worker.options.DeploymentID, limit)
	err = errors.Join(err, readCtx.Err())
	cancel()
	if err != nil || len(scopes) > limit {
		if ctx.Err() == nil {
			worker.discoveryErrors.Add(1)
			worker.logger.WarnContext(ctx, "access ledger discovery deferred", "error_code", "access_ledger_read_failed")
		}
		return
	}
	due := make(map[network.Scope]bool, len(scopes))
	for _, scope := range scopes {
		due[scope] = true
	}
	for scope := range worker.backoff {
		if !due[scope] {
			delete(worker.backoff, scope)
		}
	}
	now := time.Now()
	attempted := 0
	failures := false
	for _, scope := range scopes {
		if ctx.Err() != nil {
			return
		}
		if attempted == worker.options.BatchSize {
			break
		}
		if entry, waiting := worker.backoff[scope]; waiting && now.Before(entry.until) {
			continue
		}
		attempted++
		if !scope.IsValid() {
			failures = true
			worker.deferred.Add(1)
			continue
		}
		operationCtx, stop := context.WithTimeout(ctx, worker.options.OperationTimeout)
		outcome, err := worker.recorder.Record(operationCtx, worker.options.DeploymentID, scope)
		stop()
		if err != nil {
			failures = true
			worker.deferred.Add(1)
			entry := worker.backoff[scope]
			entry.failures++
			entry.until = time.Now().Add(worker.retryDelay(entry.failures))
			worker.backoff[scope] = entry
			continue
		}
		delete(worker.backoff, scope)
		switch outcome {
		case OutcomeRecorded:
			worker.recorded.Add(1)
		case OutcomeUnchanged:
			worker.unchanged.Add(1)
		}
	}
	if failures && ctx.Err() == nil {
		worker.logger.WarnContext(ctx, "access ledger record deferred", "error_code", "access_ledger_deferred")
	}
}

func (worker *Worker) prune(ctx context.Context) {
	for range maximumPrunePasses {
		if ctx.Err() != nil {
			return
		}
		operationCtx, stop := context.WithTimeout(ctx, worker.options.OperationTimeout)
		removed, err := worker.pruner.Prune(operationCtx, worker.options.DeploymentID, PruneBatchSize)
		stop()
		if err != nil || removed < 0 {
			if ctx.Err() == nil {
				worker.pruneErrors.Add(1)
				worker.logger.WarnContext(ctx, "access ledger retention deferred", "error_code", "access_ledger_prune_failed")
			}
			return
		}
		worker.pruned.Add(uint64(removed))
		if removed < PruneBatchSize {
			return
		}
	}
}
