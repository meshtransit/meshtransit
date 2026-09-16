// Package authexpiry owns bounded, opt-in browser-login expiry polling.
// It cannot admit login, issue Sessions or publish Network authority.
package authexpiry

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

var (
	// ErrInvalidWorker indicates missing assignment/dependencies or unsafe limits.
	ErrInvalidWorker = errors.New("invalid browser expiry worker")
	// ErrWorkerStarted indicates that an owned Worker cannot start twice.
	ErrWorkerStarted = errors.New("browser expiry worker already started")
	// ErrWorkerNotStarted indicates shutdown before successful Start.
	ErrWorkerNotStarted = errors.New("browser expiry worker not started")
	// ErrCleanupFailed stops polling after unresolved bounded resource cleanup.
	ErrCleanupFailed = errors.New("browser expiry worker cleanup failed")
)

// Options fixes one trusted process assignment and finite sequential work limits.
type Options struct {
	DeploymentID              deployment.ID
	BatchSize                 int
	PollInterval, PassTimeout time.Duration
}

// Sweeper owns a bounded pass and joins independent cleanup before returning.
// It rereads durable candidates with fresh evidence IDs; it must honor context.
type Sweeper interface {
	Sweep(context.Context, deployment.ID) (oidcauth.ExpiryPass, error)
}

// Outcome is a closed operator category, never a dependency error or scope label.
type Outcome uint8

const (
	// Unknown is the invalid zero category.
	Unknown Outcome = iota
	// Empty means successful selection with no due qualifying row, not coverage.
	Empty
	// Confirmed counts released engine receipts, not every possible durable Commit.
	Confirmed
	// Unavailable indicates a failed pass with no automatic attempt replay.
	Unavailable
	// Deadline indicates a bounded pass or unit timeout.
	Deadline
	// CommitUnknown ends an uncertain pass; a later selection is separate cleanup.
	CommitUnknown
	// CleanupFailed stops the worker after unresolved resource ownership.
	CleanupFailed
	// Canceled indicates owned shutdown cancellation after joined work.
	Canceled
	// Invalid indicates malformed aggregate counts; no counts are released.
	Invalid
)

// Observation contains no identifiers, secrets, binding hashes or free text.
type Observation struct {
	Outcome           Outcome
	Pass              oidcauth.ExpiryPass
	Elapsed           time.Duration
	BatchLimitReached bool
}

// Observer receives synchronous bounded no-data callbacks outside lifecycle locks.
// Implementations must be concurrency-safe, nonblocking and perform no I/O.
type Observer interface {
	WorkerRunning(bool)
	PassOpened()
	PassClosed(Observation)
}

// Dependencies excludes provider, browser, Session, Redis and retry capabilities.
type Dependencies struct {
	Sweeper  Sweeper
	Observer Observer
	Logger   *slog.Logger
}

// Worker owns exactly one sequential polling goroutine and its Done join path.
// Configuration is immutable; lifecycle locks never cover I/O or callbacks.
type Worker struct {
	options      Options
	dependencies Dependencies
	mu           sync.Mutex
	started      bool
	cancel       context.CancelFunc
	done         chan error
}

// New validates explicit ownership without starting work or registering metrics.
func New(options Options, dependencies Dependencies) (*Worker, error) {
	worker := &Worker{options: options, dependencies: dependencies}
	if !worker.valid() {
		return nil, ErrInvalidWorker
	}
	return worker, nil
}

func (worker *Worker) valid() bool {
	if worker == nil {
		return false
	}
	options := worker.options
	validBatch := options.BatchSize >= 1 && options.BatchSize <= 128
	validPoll := options.PollInterval >= 100*time.Millisecond && options.PollInterval <= time.Minute
	validPass := options.PassTimeout > 0 && options.PassTimeout <= 30*time.Second
	validPorts := !nilDependency(worker.dependencies.Sweeper) && !nilDependency(worker.dependencies.Observer) &&
		worker.dependencies.Logger != nil
	return options.DeploymentID.IsValid() && validBatch && validPoll && validPass && validPorts
}

func nilDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// Start starts once; the process owner must signal Shutdown and join Done.
// The application startup context is not a request or the worker's lifetime.
func (worker *Worker) Start(ctx context.Context) error {
	if ctx == nil || !worker.valid() {
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
	// One terminal result fits even before the process owner begins joining.
	done := make(chan error, 1)
	worker.cancel, worker.done, worker.started = cancel, done, true
	go func() {
		worker.dependencies.Observer.WorkerRunning(true)
		err := worker.run(owned)
		cancel()
		worker.dependencies.Observer.WorkerRunning(false)
		done <- err
		close(done)
	}()
	return nil
}

// Done is nil before Start and closes only after the complete pass has joined.
func (worker *Worker) Done() <-chan error {
	if worker == nil {
		return nil
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	return worker.done
}

// Shutdown always signals cancellation, even if the supplied drain budget expired.
// It starts no cleanup goroutine; Done is the process owner's bounded join path.
func (worker *Worker) Shutdown(ctx context.Context) error {
	if ctx == nil || !worker.valid() {
		return ErrInvalidWorker
	}
	worker.mu.Lock()
	if !worker.started {
		worker.mu.Unlock()
		return ErrWorkerNotStarted
	}
	cancel := worker.cancel
	worker.mu.Unlock()
	cancel()
	return nil
}

func (worker *Worker) run(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			if ctx.Err() != nil {
				return nil
			}
			if worker.sweep(ctx) == CleanupFailed {
				return ErrCleanupFailed
			}
			if ctx.Err() != nil {
				return nil
			}
			timer.Reset(worker.options.PollInterval)
		}
	}
}

func (worker *Worker) sweep(parent context.Context) Outcome {
	ctx, cancel := context.WithTimeout(parent, worker.options.PassTimeout)
	defer cancel()
	started := time.Now()
	worker.dependencies.Observer.PassOpened()
	pass, err := worker.dependencies.Sweeper.Sweep(ctx, worker.options.DeploymentID)
	validCounts := pass.Attempted >= 0 && pass.Attempted <= worker.options.BatchSize &&
		pass.Confirmed >= 0 && pass.Confirmed <= pass.Attempted
	complete := err != nil || pass.Attempted == pass.Confirmed
	outcome := passOutcome(parent, ctx, passEvaluation{pass: pass, err: err, valid: validCounts && complete})
	if !validCounts || !complete {
		pass = oidcauth.ExpiryPass{}
	}
	worker.dependencies.Observer.PassClosed(Observation{
		Outcome: outcome, Pass: pass, Elapsed: time.Since(started),
		BatchLimitReached: pass.Attempted == worker.options.BatchSize,
	})
	// Ordinary failures are handled here. Fatal cleanup is returned to the owner
	// for one runtime log, not logged and propagated at this boundary.
	switch outcome {
	case Unavailable, Deadline, CommitUnknown, Invalid:
		worker.dependencies.Logger.WarnContext(
			parent,
			"browser expiry pass failed",
			"error_code",
			failureClass(outcome),
		)
	}
	return outcome
}

type passEvaluation struct {
	pass  oidcauth.ExpiryPass
	err   error
	valid bool
}

func passOutcome(parent, ctx context.Context, evaluation passEvaluation) Outcome {
	err := evaluation.err
	switch {
	case errors.Is(err, oidcauth.ErrExpiryCleanupFailed):
		return CleanupFailed
	case errors.Is(err, oidcauth.ErrCommitOutcomeUnknown):
		return CommitUnknown
	case parent.Err() != nil:
		return Canceled
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return Deadline
	case !evaluation.valid:
		return Invalid
	case err != nil:
		return Unavailable
	case evaluation.pass.Attempted == 0:
		return Empty
	default:
		return Confirmed
	}
}

func failureClass(outcome Outcome) string {
	switch outcome {
	case CommitUnknown:
		return "browser_expiry_commit_unknown"
	case CleanupFailed:
		return "browser_expiry_cleanup_failed"
	case Deadline:
		return "browser_expiry_deadline"
	case Invalid:
		return "browser_expiry_invalid_pass"
	default:
		return "browser_expiry_unavailable"
	}
}
