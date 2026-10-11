// Package unrouted closes outbox events that no consumer reads. Only events
// scoped to a Network (revision wakeups) have a dispatcher today; identity,
// session, deployment and Workspace events are written for audit lineage
// and future integrations, and would otherwise stay pending forever, so the
// backlog only grows and hides real delivery stalls.
//
// The retirer marks them terminal with error class no_consumer, keeping
// every row. When a consumer for such events ships, it must claim them
// before this retirer does (or this retirer must skip their classes).
package unrouted

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrInvalidRetirer rejects unsafe dependencies or timing bounds.
	ErrInvalidRetirer = errors.New("unrouted outbox retirer: invalid configuration")
	// ErrRetirerStarted rejects duplicate lifecycle ownership.
	ErrRetirerStarted = errors.New("unrouted outbox retirer: already started")
	// ErrRetirerNotStarted rejects shutdown before startup.
	ErrRetirerNotStarted = errors.New("unrouted outbox retirer: not started")
)

// Store closes up to limit pending events that have no Network scope and
// reports how many it closed.
type Store interface {
	RetireUnroutedEvents(ctx context.Context, workerID string, limit int) (int, error)
}

// Options bounds one retirer.
type Options struct {
	WorkerID         string
	BatchSize        int
	Interval         time.Duration
	OperationTimeout time.Duration
}

// DefaultOptions closes up to 256 events a minute; a full batch runs again
// at once, so a backlog drains without waiting for the next tick.
func DefaultOptions(workerID string) Options {
	return Options{WorkerID: workerID, BatchSize: 256, Interval: time.Minute, OperationTimeout: 30 * time.Second}
}

func (options Options) valid() bool {
	return options.WorkerID != "" && len(options.WorkerID) <= 128 &&
		options.BatchSize >= 1 && options.BatchSize <= 256 &&
		options.Interval >= time.Second && options.Interval <= time.Hour &&
		options.OperationTimeout >= time.Second && options.OperationTimeout <= 5*time.Minute
}

// maxBatchesPerPass bounds the catch-up loop inside one pass.
const maxBatchesPerPass = 64

// Retirer owns one goroutine. A failed pass is logged and retried at the
// next interval.
type Retirer struct {
	options Options
	store   Store
	logger  *slog.Logger

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan error

	running                 atomic.Bool
	passes, retired, failed atomic.Uint64
}

// Measurements exposes bounded process measurements.
type Measurements struct {
	Running                 bool
	Passes, Retired, Failed uint64
}

// New constructs a stopped retirer without I/O.
func New(options Options, store Store, logger *slog.Logger) (*Retirer, error) {
	if !options.valid() || store == nil || logger == nil {
		return nil, ErrInvalidRetirer
	}
	if value := reflect.ValueOf(store); value.Kind() == reflect.Pointer && value.IsNil() {
		return nil, ErrInvalidRetirer
	}
	return &Retirer{options: options, store: store, logger: logger}, nil
}

// Start owns cancellation separately from the caller's startup context.
func (retirer *Retirer) Start(ctx context.Context) error {
	if retirer == nil || ctx == nil {
		return ErrInvalidRetirer
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	retirer.mu.Lock()
	defer retirer.mu.Unlock()
	if retirer.started {
		return ErrRetirerStarted
	}
	owned, cancel := context.WithCancel(context.WithoutCancel(ctx))
	retirer.cancel, retirer.done, retirer.started = cancel, make(chan error, 1), true
	go func() {
		retirer.running.Store(true)
		retirer.run(owned)
		retirer.running.Store(false)
		retirer.done <- nil
		close(retirer.done)
	}()
	return nil
}

// Done is the process-owned lifecycle join, available after Start.
func (retirer *Retirer) Done() <-chan error {
	if retirer == nil {
		return nil
	}
	retirer.mu.Lock()
	defer retirer.mu.Unlock()
	return retirer.done
}

// Shutdown cancels the loop. Done is the join path used by the process owner.
func (retirer *Retirer) Shutdown(ctx context.Context) error {
	if retirer == nil || ctx == nil {
		return ErrInvalidRetirer
	}
	retirer.mu.Lock()
	defer retirer.mu.Unlock()
	if !retirer.started {
		return ErrRetirerNotStarted
	}
	retirer.cancel()
	return nil
}

// Snapshot returns race-safe measurements.
func (retirer *Retirer) Snapshot() Measurements {
	if retirer == nil {
		return Measurements{}
	}
	return Measurements{Running: retirer.running.Load(), Passes: retirer.passes.Load(),
		Retired: retirer.retired.Load(), Failed: retirer.failed.Load()}
}

func (retirer *Retirer) run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			retirer.pass(ctx)
			if ctx.Err() != nil {
				return
			}
			timer.Reset(retirer.options.Interval)
		}
	}
}

func (retirer *Retirer) pass(ctx context.Context) {
	retirer.passes.Add(1)
	total := 0
	for range maxBatchesPerPass {
		operationCtx, cancel := context.WithTimeout(ctx, retirer.options.OperationTimeout)
		retired, err := retirer.store.RetireUnroutedEvents(operationCtx, retirer.options.WorkerID, retirer.options.BatchSize)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				retirer.failed.Add(1)
				retirer.logger.WarnContext(ctx, "Unrouted outbox events not retired",
					"error_code", "outbox_unrouted_retire_failed")
			}
			break
		}
		if retired > 0 {
			retirer.retired.Add(uint64(retired))
			total += retired
		}
		if retired < retirer.options.BatchSize || ctx.Err() != nil {
			break
		}
	}
	if total > 0 {
		retirer.logger.InfoContext(ctx, "Unrouted outbox events retired", "count", total)
	}
}
