// Package partitions keeps monthly audit partitions created ahead of time.
// Events land in the partition of the month they occur in; if that partition
// does not exist they fall into the DEFAULT partition, after which the month
// can no longer be attached. The maintainer keeps a rolling window ahead.
package partitions

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
	// ErrInvalidMaintainer rejects unsafe dependencies or timing bounds.
	ErrInvalidMaintainer = errors.New("audit partition maintainer: invalid configuration")
	// ErrMaintainerStarted rejects duplicate lifecycle ownership.
	ErrMaintainerStarted = errors.New("audit partition maintainer: already started")
	// ErrMaintainerNotStarted rejects shutdown before startup.
	ErrMaintainerNotStarted = errors.New("audit partition maintainer: not started")
)

// Store creates any missing monthly partition up to monthsAhead months from
// the current month and reports how many it created.
type Store interface {
	EnsurePartitions(ctx context.Context, monthsAhead int) (int, error)
}

// Options bounds one maintainer.
type Options struct {
	MonthsAhead      int
	Interval         time.Duration
	OperationTimeout time.Duration
}

// DefaultOptions keeps a year ahead and checks four times a day.
func DefaultOptions() Options {
	return Options{MonthsAhead: 12, Interval: 6 * time.Hour, OperationTimeout: 30 * time.Second}
}

func (options Options) valid() bool {
	return options.MonthsAhead >= 1 && options.MonthsAhead <= 36 &&
		options.Interval >= time.Minute && options.Interval <= 24*time.Hour &&
		options.OperationTimeout >= time.Second && options.OperationTimeout <= 5*time.Minute
}

// Maintainer owns one goroutine. A failed pass is logged and retried at the
// next interval; the window ahead leaves months of slack before any event
// could reach the DEFAULT partition.
type Maintainer struct {
	options Options
	store   Store
	logger  *slog.Logger

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan error

	running                 atomic.Bool
	passes, created, failed atomic.Uint64
}

// Measurements exposes bounded process measurements.
type Measurements struct {
	Running                 bool
	Passes, Created, Failed uint64
}

// New constructs a stopped maintainer without I/O.
func New(options Options, store Store, logger *slog.Logger) (*Maintainer, error) {
	if !options.valid() || store == nil || logger == nil {
		return nil, ErrInvalidMaintainer
	}
	if value := reflect.ValueOf(store); value.Kind() == reflect.Pointer && value.IsNil() {
		return nil, ErrInvalidMaintainer
	}
	return &Maintainer{options: options, store: store, logger: logger}, nil
}

// Start owns cancellation separately from the caller's startup context.
func (maintainer *Maintainer) Start(ctx context.Context) error {
	if maintainer == nil || ctx == nil {
		return ErrInvalidMaintainer
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	maintainer.mu.Lock()
	defer maintainer.mu.Unlock()
	if maintainer.started {
		return ErrMaintainerStarted
	}
	owned, cancel := context.WithCancel(context.WithoutCancel(ctx))
	maintainer.cancel, maintainer.done, maintainer.started = cancel, make(chan error, 1), true
	go func() {
		maintainer.running.Store(true)
		maintainer.run(owned)
		maintainer.running.Store(false)
		maintainer.done <- nil
		close(maintainer.done)
	}()
	return nil
}

// Done is the process-owned lifecycle join, available after Start.
func (maintainer *Maintainer) Done() <-chan error {
	if maintainer == nil {
		return nil
	}
	maintainer.mu.Lock()
	defer maintainer.mu.Unlock()
	return maintainer.done
}

// Shutdown cancels the loop. Done is the join path used by the process owner.
func (maintainer *Maintainer) Shutdown(ctx context.Context) error {
	if maintainer == nil || ctx == nil {
		return ErrInvalidMaintainer
	}
	maintainer.mu.Lock()
	defer maintainer.mu.Unlock()
	if !maintainer.started {
		return ErrMaintainerNotStarted
	}
	maintainer.cancel()
	return nil
}

// Snapshot returns race-safe measurements.
func (maintainer *Maintainer) Snapshot() Measurements {
	if maintainer == nil {
		return Measurements{}
	}
	return Measurements{Running: maintainer.running.Load(), Passes: maintainer.passes.Load(),
		Created: maintainer.created.Load(), Failed: maintainer.failed.Load()}
}

func (maintainer *Maintainer) run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			maintainer.pass(ctx)
			if ctx.Err() != nil {
				return
			}
			timer.Reset(maintainer.options.Interval)
		}
	}
}

func (maintainer *Maintainer) pass(ctx context.Context) {
	maintainer.passes.Add(1)
	operationCtx, cancel := context.WithTimeout(ctx, maintainer.options.OperationTimeout)
	created, err := maintainer.store.EnsurePartitions(operationCtx, maintainer.options.MonthsAhead)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			maintainer.failed.Add(1)
			maintainer.logger.WarnContext(ctx, "Audit partition maintenance deferred",
				"error_code", "audit_partition_maintenance_failed")
		}
		return
	}
	if created > 0 {
		maintainer.created.Add(uint64(created))
		maintainer.logger.InfoContext(ctx, "Audit partitions created", "count", created)
	}
}
