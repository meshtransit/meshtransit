package revisionworker

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

const (
	minLease            = time.Second
	maxLease            = 5 * time.Minute
	minPollInterval     = 100 * time.Millisecond
	maxPollInterval     = time.Minute
	minRetryDelay       = 100 * time.Millisecond
	maxRetryDelay       = 24 * time.Hour
	minOperationTimeout = 100 * time.Millisecond
	maxOperationTimeout = 30 * time.Second
	maxBatchSize        = 256
	operationsPerClaim  = 3

	errorClassLoadRevision  = "load_revision_failed"
	errorClassPublishWakeup = "publish_wakeup_failed"
)

var (
	// ErrInvalidDispatcher indicates missing dependencies or unsafe bounds.
	ErrInvalidDispatcher = errors.New("invalid network revision dispatcher")
	// ErrDispatcherStarted indicates that a Dispatcher may only start once.
	ErrDispatcherStarted = errors.New("network revision dispatcher already started")
	// ErrDispatcherNotStarted indicates shutdown before a successful start.
	ErrDispatcherNotStarted = errors.New("network revision dispatcher not started")
	// ErrInvalidClaimBatch indicates an adapter contract violation.
	ErrInvalidClaimBatch = errors.New("invalid network revision claim batch")
)

// Options bounds one process's durable Network-revision delivery work.
type Options struct {
	WorkerID         string
	BatchSize        int
	Lease            time.Duration
	PollInterval     time.Duration
	RetryDelay       time.Duration
	OperationTimeout time.Duration
}

// Dispatcher owns one polling goroutine. It processes a bounded batch
// sequentially so concurrency can never exceed the configured database and
// Redis budgets.
type Dispatcher struct {
	options   Options
	outbox    Outbox
	publisher Publisher
	logger    *slog.Logger

	mu       sync.Mutex
	started  bool
	stopping bool
	cancel   context.CancelFunc
	done     chan error
}

// New constructs a stopped Dispatcher from explicit application boundaries.
func New(
	options Options,
	outbox Outbox,
	publisher Publisher,
	logger *slog.Logger,
) (*Dispatcher, error) {
	if !validOptions(options) || isNilDependency(outbox) ||
		isNilDependency(publisher) || logger == nil {
		return nil, ErrInvalidDispatcher
	}
	return &Dispatcher{
		options:   options,
		outbox:    outbox,
		publisher: publisher,
		logger:    logger,
	}, nil
}

// Start starts exactly one owned polling goroutine. Done is its join path.
func (dispatcher *Dispatcher) Start(ctx context.Context) error {
	if ctx == nil || dispatcher == nil {
		return ErrInvalidDispatcher
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if dispatcher.started || dispatcher.stopping {
		return ErrDispatcherStarted
	}

	workerCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan error, 1)
	dispatcher.cancel = cancel
	dispatcher.done = done
	dispatcher.started = true
	go func() {
		done <- dispatcher.run(workerCtx)
		close(done)
	}()
	return nil
}

// Done returns the join channel after a successful Start call.
func (dispatcher *Dispatcher) Done() <-chan error {
	if dispatcher == nil {
		return nil
	}
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	return dispatcher.done
}

// Shutdown cancels in-flight I/O. Done is the corresponding join path.
func (dispatcher *Dispatcher) Shutdown(ctx context.Context) error {
	if ctx == nil || dispatcher == nil {
		return ErrInvalidDispatcher
	}

	dispatcher.mu.Lock()
	if !dispatcher.started {
		dispatcher.mu.Unlock()
		return ErrDispatcherNotStarted
	}
	dispatcher.stopping = true
	cancel := dispatcher.cancel
	dispatcher.mu.Unlock()
	cancel()
	return nil
}

func (dispatcher *Dispatcher) run(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			if err := dispatcher.dispatchOnce(ctx); err != nil && ctx.Err() == nil {
				dispatcher.logger.WarnContext(
					ctx,
					"network revision dispatch cycle failed",
					"error_code", "network_revision_dispatch_failure",
					"error", err,
				)
			}
			if ctx.Err() != nil {
				return nil
			}
			timer.Reset(dispatcher.options.PollInterval)
		}
	}
}
