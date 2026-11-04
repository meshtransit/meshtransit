// Package retention removes what Core no longer needs to keep (schema 274,
// docs/database-store-separation.md §6): Activity past its months, finished
// outbox events past their days and expired idempotency records. Each kind
// is removed in bounded batches through a definer function that records
// itself; a pass that cannot take a lock in time is retried at the next.
package retention

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
	// ErrInvalidMaintainer rejects unsafe dependencies or bounds.
	ErrInvalidMaintainer = errors.New("retention maintainer: invalid configuration")
	// ErrMaintainerStarted rejects duplicate lifecycle ownership.
	ErrMaintainerStarted = errors.New("retention maintainer: already started")
	// ErrMaintainerNotStarted rejects shutdown before startup.
	ErrMaintainerNotStarted = errors.New("retention maintainer: not started")
	// ErrBusy reports a lock not taken in time: the next pass tries again.
	ErrBusy = errors.New("retention: lock not taken in time")
	// ErrNotReady reports a database that cannot run retention yet: an older
	// schema, or operator step 274 not applied (the functions are refused).
	ErrNotReady = errors.New("retention: database not ready")
)

// Policy is how long each kind is kept.
type Policy struct {
	// AuditKeepMonths whole months of Activity are kept with this one: the
	// month that ended AuditKeepMonths+1 months ago goes.
	AuditKeepMonths int
	// OutboxDeliveredDays and OutboxTerminalDays after it finished, an
	// outbox event and its delivery attempts go.
	OutboxDeliveredDays int
	OutboxTerminalDays  int
	// IdempotencyGrace after it expired, an idempotency record goes.
	IdempotencyGrace time.Duration
}

// DefaultPolicy is the owner's (2026-11-04): Activity twelve months,
// delivered events a week, failed ones a month, idempotency a day past expiry.
func DefaultPolicy() Policy {
	return Policy{AuditKeepMonths: 12, OutboxDeliveredDays: 7, OutboxTerminalDays: 30,
		IdempotencyGrace: 24 * time.Hour}
}

func (policy Policy) valid() bool {
	return policy.AuditKeepMonths >= 1 && policy.AuditKeepMonths <= 120 &&
		policy.OutboxDeliveredDays >= 1 && policy.OutboxDeliveredDays <= 365 &&
		policy.OutboxTerminalDays >= policy.OutboxDeliveredDays && policy.OutboxTerminalDays <= 365 &&
		policy.IdempotencyGrace >= time.Hour && policy.IdempotencyGrace <= 30*24*time.Hour
}

// OutboxRemoved is what one outbox batch removed.
type OutboxRemoved struct{ Events, Attempts int }

// AuditRemoved is what one batch of Activity rows removed.
type AuditRemoved struct{ Defaults, Identities, Mutations int }

// Store removes one bounded batch of each kind and says how much went.
type Store interface {
	PruneIdempotency(ctx context.Context, grace time.Duration, limit int) (int, error)
	PruneOutbox(ctx context.Context, deliveredDays, terminalDays, limit int) (OutboxRemoved, error)
	// DropAuditPartitions drops the whole Activity months past keepMonths
	// in its own transaction and names them.
	DropAuditPartitions(ctx context.Context, keepMonths int) ([]string, error)
	PruneAudit(ctx context.Context, keepMonths, limit int) (AuditRemoved, error)
}

// Options bounds one maintainer: the policy, the rows per batch, the
// batches per kind in one pass, the pause between passes and the time one
// batch may take.
type Options struct {
	Policy           Policy
	BatchSize        int
	MaxBatches       int
	Interval         time.Duration
	OperationTimeout time.Duration
}

// DefaultOptions removes up to 20,000 rows of each kind an hour, a
// thousand at a time, so no batch holds locks for long.
func DefaultOptions() Options {
	return Options{Policy: DefaultPolicy(), BatchSize: 1000, MaxBatches: 20, Interval: time.Hour,
		OperationTimeout: 30 * time.Second}
}

func (options Options) valid() bool {
	return options.Policy.valid() &&
		options.BatchSize >= 1 && options.BatchSize <= 5000 &&
		options.MaxBatches >= 1 && options.MaxBatches <= 1000 &&
		options.Interval >= time.Minute && options.Interval <= 24*time.Hour &&
		options.OperationTimeout >= time.Second && options.OperationTimeout <= 5*time.Minute
}

// Measurements are the totals since the process started.
type Measurements struct {
	Running                                 bool
	Passes, Failed                          uint64
	IdempotencyRecords                      uint64
	OutboxEvents, OutboxAttempts            uint64
	AuditPartitions, AuditEvents, AuditRows uint64
	LastWholePass                           time.Time
}

// Maintainer owns one goroutine running a pass at start and every Interval.
type Maintainer struct {
	options Options
	store   Store
	logger  *slog.Logger
	now     func() time.Time

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan error

	running                            atomic.Bool
	passes, failed                     atomic.Uint64
	idempotency, events, attempts      atomic.Uint64
	partitions, auditEvents, auditRows atomic.Uint64
	lastWhole                          atomic.Int64
}

// New constructs a stopped maintainer without I/O.
func New(options Options, store Store, logger *slog.Logger) (*Maintainer, error) {
	if !options.valid() || store == nil || logger == nil {
		return nil, ErrInvalidMaintainer
	}
	if value := reflect.ValueOf(store); value.Kind() == reflect.Pointer && value.IsNil() {
		return nil, ErrInvalidMaintainer
	}
	return &Maintainer{options: options, store: store, logger: logger, now: time.Now}, nil
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
	measurements := Measurements{
		Running: maintainer.running.Load(), Passes: maintainer.passes.Load(), Failed: maintainer.failed.Load(),
		IdempotencyRecords: maintainer.idempotency.Load(),
		OutboxEvents:       maintainer.events.Load(), OutboxAttempts: maintainer.attempts.Load(),
		AuditPartitions: maintainer.partitions.Load(), AuditEvents: maintainer.auditEvents.Load(),
		AuditRows: maintainer.auditRows.Load(),
	}
	if last := maintainer.lastWhole.Load(); last > 0 {
		measurements.LastWholePass = time.Unix(last, 0)
	}
	return measurements
}

func (maintainer *Maintainer) run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			maintainer.Pass(ctx)
			if ctx.Err() != nil {
				return
			}
			timer.Reset(maintainer.options.Interval)
		}
	}
}

// Pass removes what is due, idempotency first so the outbox events it held
// can go in the same pass. A kind that fails stops the pass; the next one
// starts again. Exported for tests and an operator's one-off run.
func (maintainer *Maintainer) Pass(ctx context.Context) {
	maintainer.passes.Add(1)
	for _, step := range []struct {
		kind string
		run  func(context.Context) error
	}{
		{"idempotency", maintainer.idempotencyStep}, {"outbox", maintainer.outboxStep},
		{"audit", maintainer.auditStep},
	} {
		if err := step.run(ctx); err != nil {
			if ctx.Err() == nil {
				maintainer.failed.Add(1)
				// Only the class of the error is logged: its text may quote a row.
				maintainer.logger.WarnContext(ctx, "Retention pass deferred", "error_code", "retention_pass_failed",
					"kind", step.kind, "cause", cause(err))
			}
			return
		}
	}
	maintainer.lastWhole.Store(maintainer.now().Unix())
}

// batches runs one kind's batch until it removes less than a full batch, the
// pass's batches run out, or the context ends.
func (maintainer *Maintainer) batches(ctx context.Context, batch func(context.Context) (bool, error)) error {
	for range maintainer.options.MaxBatches {
		if err := ctx.Err(); err != nil {
			return err
		}
		operation, cancel := context.WithTimeout(ctx, maintainer.options.OperationTimeout)
		full, err := batch(operation)
		cancel()
		if err != nil || !full {
			return err
		}
	}
	return nil
}

func (maintainer *Maintainer) idempotencyStep(ctx context.Context) error {
	limit := maintainer.options.BatchSize
	return maintainer.batches(ctx, func(operation context.Context) (bool, error) {
		removed, err := maintainer.store.PruneIdempotency(operation, maintainer.options.Policy.IdempotencyGrace, limit)
		if err != nil {
			return false, err
		}
		maintainer.idempotency.Add(uint64(max(removed, 0)))
		return removed >= limit, nil
	})
}

func (maintainer *Maintainer) outboxStep(ctx context.Context) error {
	policy, limit := maintainer.options.Policy, maintainer.options.BatchSize
	return maintainer.batches(ctx, func(operation context.Context) (bool, error) {
		removed, err := maintainer.store.PruneOutbox(operation, policy.OutboxDeliveredDays,
			policy.OutboxTerminalDays, limit)
		if err != nil {
			return false, err
		}
		maintainer.events.Add(uint64(max(removed.Events, 0)))
		maintainer.attempts.Add(uint64(max(removed.Attempts, 0)))
		return removed.Events >= limit, nil
	})
}

// cause names an error's class for the log.
func cause(err error) string {
	switch {
	case errors.Is(err, ErrBusy):
		return "busy"
	case errors.Is(err, ErrNotReady):
		return "not_ready"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "other"
	}
}

// auditStep drops the whole months first, in a transaction of their own,
// then removes what they leave behind in batches.
func (maintainer *Maintainer) auditStep(ctx context.Context) error {
	keep, limit := maintainer.options.Policy.AuditKeepMonths, maintainer.options.BatchSize
	operation, cancel := context.WithTimeout(ctx, maintainer.options.OperationTimeout)
	dropped, err := maintainer.store.DropAuditPartitions(operation, keep)
	cancel()
	if err != nil {
		return err
	}
	if len(dropped) > 0 {
		maintainer.partitions.Add(uint64(len(dropped)))
		maintainer.logger.InfoContext(ctx, "Activity months removed past retention", "partitions", dropped)
	}
	return maintainer.batches(ctx, func(operation context.Context) (bool, error) {
		removed, err := maintainer.store.PruneAudit(operation, keep, limit)
		if err != nil {
			return false, err
		}
		maintainer.auditEvents.Add(uint64(max(removed.Defaults, 0)))
		maintainer.auditRows.Add(uint64(max(removed.Identities, 0) + max(removed.Mutations, 0)))
		return removed.Defaults >= limit || removed.Identities >= limit || removed.Mutations >= limit, nil
	})
}
