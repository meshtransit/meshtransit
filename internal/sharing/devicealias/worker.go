package devicealias

import (
	"context"
	"errors"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrInvalidWorker rejects unsafe dependencies, pages or timing bounds.
	ErrInvalidWorker = errors.New("device alias worker: invalid configuration or work")
	// ErrWorkerStarted rejects duplicate lifecycle ownership.
	ErrWorkerStarted = errors.New("device alias worker: already started")
	// ErrWorkerNotStarted rejects shutdown before startup.
	ErrWorkerNotStarted = errors.New("device alias worker: not started")
)

// Options binds one process to an exact installation and finite sequential work.
type Options struct {
	DeploymentID                   deployment.ID
	BatchSize                      int
	PollInterval, OperationTimeout time.Duration
}

// Worker owns one goroutine, one finite page and no authority cache. Failed
// candidates advance the cursor so later pairs cannot starve. A fresh sweep
// discovers committed state again, including after an uncertain write outcome.
type Worker struct {
	options                                    Options
	work                                       Work
	changes                                    Changes
	logger                                     *slog.Logger
	mu                                         sync.Mutex
	started                                    bool
	cancel                                     context.CancelFunc
	done                                       chan error
	running                                    atomic.Bool
	passes, discoveryErrors, changed, deferred atomic.Uint64
}

// Measurements exposes bounded, identifier-free process measurements.
type Measurements struct {
	Running                                    bool
	Passes, DiscoveryErrors, Changed, Deferred uint64
}

// New constructs a stopped worker without I/O.
func New(options Options, work Work, changes Changes, logger *slog.Logger) (*Worker, error) {
	if !options.DeploymentID.IsValid() || options.BatchSize < 1 || options.BatchSize > 128 || options.PollInterval < 100*time.Millisecond || options.PollInterval > time.Minute || options.OperationTimeout < 100*time.Millisecond || options.OperationTimeout > 15*time.Second || nilPort(work) || nilPort(changes) || logger == nil {
		return nil, ErrInvalidWorker
	}
	return &Worker{options: options, work: work, changes: changes, logger: logger}, nil
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
	return Measurements{Running: worker.running.Load(), Passes: worker.passes.Load(), DiscoveryErrors: worker.discoveryErrors.Load(), Changed: worker.changed.Load(), Deferred: worker.deferred.Load()}
}

func (worker *Worker) run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	after := Cursor{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			after = worker.reconcile(ctx, after)
			if ctx.Err() != nil {
				return
			}
			timer.Reset(worker.options.PollInterval)
		}
	}
}

func (worker *Worker) reconcile(ctx context.Context, after Cursor) Cursor {
	worker.passes.Add(1)
	readCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	page, err := worker.work.List(readCtx, worker.options.DeploymentID, after, worker.options.BatchSize)
	err = errors.Join(err, readCtx.Err())
	cancel()
	if err != nil || !page.IsValid(worker.options.DeploymentID, after, worker.options.BatchSize) {
		if ctx.Err() == nil {
			worker.discoveryErrors.Add(1)
			worker.logger.WarnContext(ctx, "Device alias discovery deferred", "error_code", "device_alias_work_read_failed")
		}
		return after
	}
	// No read transaction survives discovery. Each action opens its own guarded
	// write and rechecks all live authority; the page is never a cached grant.
	failures := false
	for _, intent := range page.Items {
		if ctx.Err() != nil {
			return after
		}
		operationCtx, stop := context.WithTimeout(ctx, worker.options.OperationTimeout)
		changed, err := worker.changes.Change(operationCtx, intent)
		stop()
		if err != nil {
			worker.deferred.Add(1)
			failures = true
			continue
		}
		if changed {
			worker.changed.Add(1)
		}
	}
	if failures && ctx.Err() == nil {
		worker.logger.WarnContext(ctx, "Device alias changes deferred", "error_code", "device_alias_change_deferred")
	}
	if page.Done {
		return Cursor{}
	}
	return page.Next
}
