package deletion

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
)

// Step is what one phase-2 step did.
type Step struct {
	// Changed: a deletion moved (Devices revoked, or it completed).
	Changed bool
	// Completed: the deletion finished in this step.
	Completed bool
	Revoked   int
	// Failed counts deletions whose step failed and was rolled back; the
	// others still ran.
	Failed int
}

// Lag is the worker's backlog.
type Lag struct {
	Pending int64
	// Oldest is how long the oldest unfinished deletion has waited.
	Oldest time.Duration
}

// WorkerStore runs one step in one transaction with its evidence.
type WorkerStore interface {
	Step(ctx context.Context, installation deployment.ID, batch int) (Step, error)
	Lag(ctx context.Context, installation deployment.ID) (Lag, error)
}

// WorkerOptions bound the worker.
type WorkerOptions struct {
	// Name names the work in logs; empty is "network deletion". The same
	// loop runs the removal of Devices signed out past their hold.
	Name             string
	DeploymentID     deployment.ID
	BatchSize        int
	PollInterval     time.Duration
	OperationTimeout time.Duration
}

// WorkerSnapshot is what the worker reports for metrics.
type WorkerSnapshot struct {
	Running                   bool
	Steps, Revoked, Completed uint64
	Failures                  uint64
	Pending                   int64
	Lag                       time.Duration
}

// Worker revokes deleted Networks' Devices in batches until each deletion
// completes. Steps run back to back while there is work and every poll
// interval otherwise; a failed step waits for the next poll.
type Worker struct {
	store   WorkerStore
	options WorkerOptions
	logger  *slog.Logger

	mu       sync.Mutex
	snapshot WorkerSnapshot
	started  bool
	cancel   context.CancelFunc
	done     chan error
}

// NewWorker validates its options.
func NewWorker(options WorkerOptions, store WorkerStore, logger *slog.Logger) (*Worker, error) {
	if store == nil || logger == nil || !options.DeploymentID.IsValid() || options.BatchSize < 1 ||
		options.BatchSize > 2000 || options.PollInterval < 500*time.Millisecond ||
		options.OperationTimeout < 100*time.Millisecond || options.OperationTimeout > time.Minute {
		return nil, ErrInvalid
	}
	if options.Name == "" {
		options.Name = "network deletion"
	}
	return &Worker{store: store, options: options, logger: logger}, nil
}

// Start runs the worker until Shutdown.
func (worker *Worker) Start(ctx context.Context) error {
	if worker == nil || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if worker.started {
		return ErrInvalid
	}
	owned, cancel := context.WithCancel(context.WithoutCancel(ctx))
	worker.cancel, worker.done, worker.started = cancel, make(chan error, 1), true
	worker.snapshot.Running = true
	go func() {
		worker.run(owned)
		worker.mu.Lock()
		worker.snapshot.Running = false
		worker.mu.Unlock()
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

// Shutdown cancels the loop; Done is the join path.
func (worker *Worker) Shutdown(ctx context.Context) error {
	if worker == nil || ctx == nil {
		return ErrInvalid
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if !worker.started {
		return ErrInvalid
	}
	worker.cancel()
	return nil
}

// Snapshot reads the counters.
func (worker *Worker) Snapshot() WorkerSnapshot {
	worker.mu.Lock()
	defer worker.mu.Unlock()
	return worker.snapshot
}

func (worker *Worker) run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	var lagReadAt time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		next := worker.options.PollInterval
		if worker.pass(ctx) {
			// More may be waiting: step again at once.
			next = 0
		}
		// The backlog is read once a poll interval, busy or not.
		if time.Since(lagReadAt) >= worker.options.PollInterval {
			worker.readLag(ctx)
			lagReadAt = time.Now()
		}
		timer.Reset(next)
	}
}

// pass runs one step and reports whether it changed anything.
func (worker *Worker) pass(ctx context.Context) bool {
	stepCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	step, err := worker.store.Step(stepCtx, worker.options.DeploymentID, worker.options.BatchSize)
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if err != nil {
		if ctx.Err() == nil {
			worker.snapshot.Failures++
			worker.logger.WarnContext(ctx, worker.options.Name+" step failed", slog.String("error", err.Error()))
		}
		return false
	}
	if step.Failed > 0 {
		worker.snapshot.Failures += uint64(step.Failed)
		worker.logger.WarnContext(ctx, worker.options.Name+" steps failed", slog.Int("items", step.Failed))
	}
	if !step.Changed {
		return false
	}
	worker.snapshot.Steps++
	if step.Revoked > 0 {
		worker.snapshot.Revoked += uint64(step.Revoked)
	}
	if step.Completed {
		worker.snapshot.Completed++
		worker.logger.InfoContext(ctx, worker.options.Name+" completed")
	}
	return true
}

func (worker *Worker) readLag(ctx context.Context) {
	lagCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	lag, err := worker.store.Lag(lagCtx, worker.options.DeploymentID)
	if err != nil {
		if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
			worker.logger.WarnContext(ctx, worker.options.Name+" lag read failed", slog.String("error", err.Error()))
		}
		return
	}
	worker.mu.Lock()
	worker.snapshot.Pending, worker.snapshot.Lag = lag.Pending, lag.Oldest
	worker.mu.Unlock()
}
