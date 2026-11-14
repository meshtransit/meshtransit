package renewal

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/deployment/entitlement"
)

var (
	// ErrInvalidRenewer rejects unsafe dependencies or timing bounds.
	ErrInvalidRenewer = errors.New("entitlement renewer: invalid configuration")
	// ErrRenewerStarted rejects duplicate lifecycle ownership.
	ErrRenewerStarted = errors.New("entitlement renewer: already started")
	// ErrRenewerNotStarted rejects shutdown before startup.
	ErrRenewerNotStarted = errors.New("entitlement renewer: not started")
)

// Outcome is what one renewal attempt did.
type Outcome string

const (
	// OutcomeRenewed recorded the next generation.
	OutcomeRenewed Outcome = "renewed"
	// OutcomeNotDue found the current generation with more than a third of
	// its life left.
	OutcomeNotDue Outcome = "not_due"
	// OutcomeBusy found another replica renewing.
	OutcomeBusy Outcome = "busy"
	// OutcomeNoEntitlement found no recorded generation to renew.
	OutcomeNoEntitlement Outcome = "no_entitlement"
)

// NextFunc decides, inside the store's transaction, on the current
// generation: the next one to record and true, or false when none is due.
type NextFunc func(current Current) (entitlement.Entitlement, bool, error)

// Store runs one renewal attempt in one transaction: it serializes
// replicas, reads the current generation while holding the Deployment, and
// records what next returns. A replica that cannot serialize returns
// OutcomeBusy at once.
type Store interface {
	RenewDeploymentEntitlement(ctx context.Context, deploymentID deployment.ID, next NextFunc) (Outcome, error)
}

// Options bounds one renewer. Time comes from the database (Current).
type Options struct {
	DeploymentID     deployment.ID
	Interval         time.Duration
	OperationTimeout time.Duration
}

// DefaultOptions tries each hour, from the start.
func DefaultOptions(deploymentID deployment.ID) Options {
	return Options{DeploymentID: deploymentID, Interval: time.Hour, OperationTimeout: 30 * time.Second}
}

func (options Options) valid() bool {
	return options.DeploymentID.IsValid() &&
		options.Interval >= time.Second && options.Interval <= 24*time.Hour &&
		options.OperationTimeout >= time.Second && options.OperationTimeout <= 5*time.Minute
}

// Renewer owns one goroutine. A failed attempt is logged and retried at the
// next interval: a generation becomes due a third of its life (four months)
// before it expires, so hours of failures cost nothing.
type Renewer struct {
	options Options
	store   Store
	signer  *Signer
	logger  *slog.Logger

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan error

	attempts, renewed, failed atomic.Uint64
}

// Measurements exposes bounded process measurements.
type Measurements struct {
	Attempts, Renewed, Failed uint64
}

// New constructs a stopped renewer without I/O.
func New(options Options, store Store, signer *Signer, logger *slog.Logger) (*Renewer, error) {
	if !options.valid() || store == nil || signer == nil || logger == nil ||
		signer.deploymentID != options.DeploymentID {
		return nil, ErrInvalidRenewer
	}
	if value := reflect.ValueOf(store); value.Kind() == reflect.Pointer && value.IsNil() {
		return nil, ErrInvalidRenewer
	}
	return &Renewer{options: options, store: store, signer: signer, logger: logger}, nil
}

// Start owns cancellation separately from the caller's startup context.
func (renewer *Renewer) Start(ctx context.Context) error {
	if renewer == nil || ctx == nil {
		return ErrInvalidRenewer
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	renewer.mu.Lock()
	defer renewer.mu.Unlock()
	if renewer.started {
		return ErrRenewerStarted
	}
	owned, cancel := context.WithCancel(context.WithoutCancel(ctx))
	renewer.cancel, renewer.done, renewer.started = cancel, make(chan error, 1), true
	go func() {
		renewer.run(owned)
		// The loop is the only signer user: the key goes with it.
		renewer.signer.forget()
		renewer.done <- nil
		close(renewer.done)
	}()
	return nil
}

// Done is the process-owned lifecycle join, available after Start.
func (renewer *Renewer) Done() <-chan error {
	if renewer == nil {
		return nil
	}
	renewer.mu.Lock()
	defer renewer.mu.Unlock()
	return renewer.done
}

// Shutdown cancels the loop. Done is the join path used by the process owner.
func (renewer *Renewer) Shutdown(ctx context.Context) error {
	if renewer == nil || ctx == nil {
		return ErrInvalidRenewer
	}
	renewer.mu.Lock()
	defer renewer.mu.Unlock()
	if !renewer.started {
		return ErrRenewerNotStarted
	}
	renewer.cancel()
	return nil
}

// Snapshot returns race-safe measurements.
func (renewer *Renewer) Snapshot() Measurements {
	if renewer == nil {
		return Measurements{}
	}
	return Measurements{Attempts: renewer.attempts.Load(), Renewed: renewer.renewed.Load(),
		Failed: renewer.failed.Load()}
}

func (renewer *Renewer) run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			renewer.Attempt(ctx)
			if ctx.Err() != nil {
				return
			}
			timer.Reset(renewer.options.Interval)
		}
	}
}

// Attempt runs one bounded renewal attempt and logs its outcome.
func (renewer *Renewer) Attempt(ctx context.Context) Outcome {
	renewer.attempts.Add(1)
	attemptCtx, cancel := context.WithTimeout(ctx, renewer.options.OperationTimeout)
	defer cancel()
	var renewed entitlement.Entitlement
	outcome, err := renewer.store.RenewDeploymentEntitlement(attemptCtx, renewer.options.DeploymentID,
		func(current Current) (entitlement.Entitlement, bool, error) {
			if current.DatabaseNow.IsZero() {
				return entitlement.Entitlement{}, false, ErrNotRenewable
			}
			if !Due(current, current.DatabaseNow) {
				return entitlement.Entitlement{}, false, nil
			}
			next, err := renewer.signer.Next(current, current.DatabaseNow)
			renewed = next
			return next, err == nil, err
		})
	switch {
	case err != nil:
		renewer.failed.Add(1)
		renewer.logger.ErrorContext(ctx, "deployment entitlement renewal failed",
			"error_code", "entitlement_renewal_failure", "signer_key_id", renewer.signer.KeyID(), "error", err)
		return ""
	case outcome == OutcomeRenewed:
		renewer.renewed.Add(1)
		renewer.logger.InfoContext(ctx, "deployment entitlement renewed",
			"entitlement_id", renewed.ID.String(), "generation", renewed.Generation,
			"expires_at", renewed.ExpiresAt.Format(time.RFC3339), "signer_key_id", renewed.KeyID)
	case outcome == OutcomeNoEntitlement:
		renewer.logger.WarnContext(ctx, "deployment entitlement renewal found no entitlement",
			"error_code", "entitlement_renewal_no_entitlement")
	default:
		renewer.logger.DebugContext(ctx, "deployment entitlement renewal", "outcome", string(outcome))
	}
	return outcome
}
