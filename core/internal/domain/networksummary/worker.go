package networksummary

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
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	maximumBatchSize = 64
	// minimumIdleWait is the first wait after a pass that found nothing; the
	// wait doubles up to Options.PollInterval while nothing is due.
	minimumIdleWait = 500 * time.Millisecond
	// minimumSpacing and spacingFactor space recomputes of one Network:
	// at least 2 s, and 20 times what the last count took, so a large
	// Network is not counted again and again while it keeps changing.
	minimumSpacing = 2 * time.Second
	spacingFactor  = 20
	maximumSpacing = 10 * time.Minute
	lagInterval    = 15 * time.Second
	// failureRetry is how long a Network whose count or store failed waits
	// before it is claimed again.
	failureRetry = 30 * time.Second
	// leaseMargin is room for the claim and the stores of one batch.
	leaseMargin = 10 * time.Second
)

var (
	// ErrInvalidWorker rejects unsafe dependencies or timing bounds.
	ErrInvalidWorker = errors.New("network summary worker: invalid configuration")
	// ErrWorkerStarted rejects duplicate lifecycle ownership.
	ErrWorkerStarted = errors.New("network summary worker: already started")
	// ErrWorkerNotStarted rejects shutdown before startup.
	ErrWorkerNotStarted = errors.New("network summary worker: not started")
)

// Lag is how far the summaries are behind the writes.
type Lag struct {
	// Pending Networks wait for a count; Marks are changes not folded into
	// the queue yet (bounded at 100 000).
	Pending, Marks int64
	Oldest         time.Duration
}

// foldLimit bounds the marks one pass folds, in its own short transaction.
const foldLimit = 5000

// Store is the worker's database: claims, counts in one snapshot, and
// stores only newer summaries.
type Store interface {
	// Fold moves up to limit change marks into the queue.
	Fold(ctx context.Context, limit int) (int, error)
	Claim(ctx context.Context, installation deployment.ID, worker publicid.ID, limit int,
		lease time.Duration) ([]network.Scope, error)
	// Compute counts one Network; false when it no longer exists here.
	Compute(ctx context.Context, installation deployment.ID, scope network.Scope) (Summary, bool, error)
	// Save stores the summary if it is newer and releases the claim; false
	// when a newer summary was already stored.
	Save(ctx context.Context, installation deployment.ID, worker publicid.ID, summary Summary,
		took, spacing time.Duration) (bool, error)
	// Release gives a claim back; the Network is claimed again after retry.
	Release(ctx context.Context, installation deployment.ID, worker publicid.ID, scope network.Scope,
		retry time.Duration) error
	Lag(ctx context.Context, installation deployment.ID) (Lag, error)
}

// Options binds one process to one installation and finite work.
type Options struct {
	DeploymentID deployment.ID
	BatchSize    int
	// PollInterval is the longest wait between passes while nothing is due.
	PollInterval, OperationTimeout, Lease time.Duration
}

func (options Options) valid() bool {
	return options.DeploymentID.IsValid() && options.BatchSize >= 1 && options.BatchSize <= maximumBatchSize &&
		options.PollInterval >= minimumIdleWait && options.PollInterval <= time.Minute &&
		options.OperationTimeout >= 100*time.Millisecond && options.OperationTimeout <= 30*time.Second &&
		options.Lease >= 5*time.Second && options.Lease <= 5*time.Minute &&
		// A batch is counted one Network at a time: the lease must outlast
		// it, or another worker claims the rest and counts them twice.
		options.Lease >= time.Duration(options.BatchSize)*options.OperationTimeout+leaseMargin
}

// Worker owns one goroutine. Nothing is cached between passes: a failed
// Network is released and claimed again from committed state.
type Worker struct {
	options Options
	store   Store
	logger  *slog.Logger
	id      publicid.ID
	clock   func() time.Time

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan error

	running                                      atomic.Bool
	passes, claimed, stored, stale, gone, failed atomic.Uint64
	computeNanoseconds                           atomic.Int64
	pending, marks                               atomic.Int64
	lagMilliseconds                              atomic.Int64
}

// Measurements are bounded, identifier-free process measurements.
type Measurements struct {
	Running                                      bool
	Passes, Claimed, Stored, Stale, Gone, Failed uint64
	// Pending and Lag come from the queue, read every 15 s.
	Pending, Marks int64
	Lag            time.Duration
	// Computing is the total time spent counting.
	Computing time.Duration
}

// New constructs a stopped worker without I/O.
func New(options Options, store Store, logger *slog.Logger) (*Worker, error) {
	if !options.valid() || nilPort(store) || logger == nil {
		return nil, ErrInvalidWorker
	}
	id, err := publicid.New()
	if err != nil {
		return nil, errors.Join(ErrInvalidWorker, err)
	}
	return &Worker{options: options, store: store, logger: logger, id: id, clock: time.Now}, nil
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

// Shutdown cancels finite work. Done is the join path.
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
		Running: worker.running.Load(), Passes: worker.passes.Load(), Claimed: worker.claimed.Load(),
		Stored: worker.stored.Load(), Stale: worker.stale.Load(), Gone: worker.gone.Load(),
		Failed: worker.failed.Load(), Pending: worker.pending.Load(), Marks: worker.marks.Load(),
		Lag:       time.Duration(worker.lagMilliseconds.Load()) * time.Millisecond,
		Computing: time.Duration(worker.computeNanoseconds.Load()),
	}
}

func (worker *Worker) run(ctx context.Context) {
	wait := minimumIdleWait
	var lagReadAt time.Time
	for ctx.Err() == nil {
		if worker.clock().Sub(lagReadAt) >= lagInterval {
			worker.readLag(ctx)
			lagReadAt = worker.clock()
		}
		claimed := worker.pass(ctx)
		// A full batch means more may be due: go again at once. Any work
		// means changes are coming in: look again soon.
		if claimed >= worker.options.BatchSize {
			wait = minimumIdleWait
			continue
		}
		if claimed > 0 {
			wait = minimumIdleWait
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if claimed == 0 {
			wait = min(wait*2, worker.options.PollInterval)
		}
	}
}

// pass claims and counts one batch; it returns how many it claimed.
func (worker *Worker) pass(ctx context.Context) int {
	worker.passes.Add(1)
	// The fold has its own transaction and failure: a slow fold never
	// fails a claim, and the next pass folds again.
	foldCtx, foldCancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	if _, err := worker.store.Fold(foldCtx, foldLimit); err != nil && ctx.Err() == nil {
		worker.logger.WarnContext(ctx, "network summary fold failed", "error_code", "network_summary_fold_failed")
	}
	foldCancel()
	claimCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	scopes, err := worker.store.Claim(claimCtx, worker.options.DeploymentID, worker.id, worker.options.BatchSize,
		worker.options.Lease)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			worker.failed.Add(1)
			worker.logger.WarnContext(ctx, "network summary claim failed", "error_code", "network_summary_claim_failed")
		}
		return 0
	}
	worker.claimed.Add(uint64(len(scopes)))
	for index, scope := range scopes {
		if ctx.Err() != nil {
			// Shutting down: give the rest back for another worker now.
			for _, left := range scopes[index:] {
				worker.release(ctx, left, 0)
			}
			return len(scopes)
		}
		worker.summarize(ctx, scope)
	}
	return len(scopes)
}

func (worker *Worker) summarize(ctx context.Context, scope network.Scope) {
	operation, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	started := worker.clock()
	summary, found, err := worker.store.Compute(operation, worker.options.DeploymentID, scope)
	took := worker.clock().Sub(started)
	worker.computeNanoseconds.Add(int64(took))
	if err == nil && found {
		err = summary.Validate()
	}
	if ctx.Err() != nil {
		// Stopping, not failing: give it back for another worker now.
		worker.release(ctx, scope, 0)
		return
	}
	if err != nil || !found {
		if err != nil {
			worker.failed.Add(1)
			worker.logger.WarnContext(ctx, "network summary count failed", "error_code", "network_summary_compute_failed")
		} else {
			worker.gone.Add(1)
		}
		retry := failureRetry
		if !found && err == nil {
			retry = 0
		}
		worker.release(ctx, scope, retry)
		return
	}
	newer, err := worker.store.Save(operation, worker.options.DeploymentID, worker.id, summary, took, Spacing(took))
	switch {
	case err != nil && ctx.Err() != nil:
		worker.release(ctx, scope, 0)
	case err != nil:
		worker.failed.Add(1)
		worker.logger.WarnContext(ctx, "network summary store failed", "error_code", "network_summary_store_failed")
		worker.release(ctx, scope, failureRetry)
	case newer:
		worker.stored.Add(1)
	default:
		worker.stale.Add(1)
	}
}

// release gives a claim back, past a cancelled pass too, within its own
// bounded time; a failed release only waits out the lease.
func (worker *Worker) release(ctx context.Context, scope network.Scope, retry time.Duration) {
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), worker.options.OperationTimeout)
	defer cancel()
	_ = worker.store.Release(releaseCtx, worker.options.DeploymentID, worker.id, scope, retry)
}

func (worker *Worker) readLag(ctx context.Context) {
	lagCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	lag, err := worker.store.Lag(lagCtx, worker.options.DeploymentID)
	if err != nil {
		return
	}
	worker.pending.Store(lag.Pending)
	worker.marks.Store(lag.Marks)
	worker.lagMilliseconds.Store(lag.Oldest.Milliseconds())
}

// Spacing is how long a Network waits before it is counted again after a
// count that took took.
func Spacing(took time.Duration) time.Duration {
	return min(max(minimumSpacing, spacingFactor*took), maximumSpacing)
}
