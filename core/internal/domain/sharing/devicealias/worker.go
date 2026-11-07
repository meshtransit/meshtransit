package devicealias

import (
	"context"
	"errors"
	"log/slog"
	"meshtransit.net/core/internal/domain/deployment"
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
	// IdleInterval, set exactly with Hints, is the longest wait between two
	// sweeps that found no work while the hints are listening.
	IdleInterval time.Duration
	// Hints wake the worker when alias work may have appeared, so idle sweeps
	// can space out; nil keeps a sweep every PollInterval.
	Hints Hints
}

// Hints report that alias work may have appeared: a client claimed aliases
// or a Network revision advanced. A wakeup carries no data. Listening is
// false while wakeups may be missed; the worker then sweeps every
// PollInterval.
type Hints interface {
	Wakeups() <-chan struct{}
	Listening() bool
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
	if !options.DeploymentID.IsValid() || options.BatchSize < 1 || options.BatchSize > 128 || options.PollInterval < 100*time.Millisecond || options.PollInterval > time.Minute || options.OperationTimeout < 100*time.Millisecond || options.OperationTimeout > 15*time.Second || nilPort(work) || nilPort(changes) || logger == nil || !validHints(options) {
		return nil, ErrInvalidWorker
	}
	return &Worker{options: options, work: work, changes: changes, logger: logger}, nil
}

// validHints requires an idle interval exactly with hints, between the poll
// interval and a minute.
func validHints(options Options) bool {
	if options.Hints == nil {
		return options.IdleInterval == 0
	}
	return !nilPort(options.Hints) && options.IdleInterval >= options.PollInterval && options.IdleInterval <= time.Minute
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
	var wakeups <-chan struct{}
	if worker.options.Hints != nil {
		wakeups = worker.options.Hints.Wakeups()
	}
	after := Cursor{}
	// wait is the pause after a sweep that found no work; sweepWorked says
	// whether the sweep in progress found work (or failed to read).
	wait, sweepWorked := worker.options.PollInterval, false
	due := time.Now()
	var lastPass time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-wakeups:
			// Work may have appeared: sweep again soon, but no sooner than a
			// poll interval after the last pass, and start the back-off over.
			// Mid-sweep, the cursor may have passed it already, so the next
			// sweep follows at the poll interval too.
			wait = worker.options.PollInterval
			if after != (Cursor{}) {
				sweepWorked = true
			}
			if earliest := lastPass.Add(worker.options.PollInterval); earliest.Before(due) {
				due = earliest
				resetTimer(timer, time.Until(due))
			}
			continue
		case <-timer.C:
		}
		lastPass = time.Now()
		next, swept, worked := worker.pass(ctx, after)
		if ctx.Err() != nil {
			return
		}
		after, sweepWorked = next, sweepWorked || worked
		delay := worker.options.PollInterval
		if swept {
			wait = worker.idleWait(wait, sweepWorked)
			delay, sweepWorked = wait, false
		}
		due = time.Now().Add(delay)
		resetTimer(timer, delay)
	}
}

// idleWait is the pause after a finished sweep: the poll interval after work
// or without listening hints, else double the last pause up to IdleInterval.
// Pages of one sweep always follow each other at the poll interval.
func (worker *Worker) idleWait(last time.Duration, worked bool) time.Duration {
	hints := worker.options.Hints
	if worked || hints == nil || !hints.Listening() {
		return worker.options.PollInterval
	}
	return min(2*last, worker.options.IdleInterval)
}

func resetTimer(timer *time.Timer, wait time.Duration) {
	timer.Stop()
	timer.Reset(max(wait, 0))
}

// pass reads and runs one page. swept reports that the page ended a sweep;
// worked that it had work, or failed to read (so the next sweep stays fast).
func (worker *Worker) pass(ctx context.Context, after Cursor) (next Cursor, swept, worked bool) {
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
		return after, false, true
	}
	// No read transaction survives discovery. Each action opens its own guarded
	// write and rechecks all live authority; the page is never a cached grant.
	failures := false
	for _, intent := range page.Items {
		if ctx.Err() != nil {
			return after, false, true
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
	worked = len(page.Items) > 0
	if page.Done {
		return Cursor{}, true, worked
	}
	return page.Next, false, worked
}
