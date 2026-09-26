package oidcauth

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"time"

	"github.com/meshtransit/meshtransit/internal/publicid"
)

var (
	// ErrInvalidFailure rejects missing confirmed evidence or unsafe setup.
	ErrInvalidFailure = errors.New("oidc auth: invalid browser failure")
	// ErrFailureFailed conceals dependency details and releases no terminal receipt.
	ErrFailureFailed = errors.New("oidc auth: browser failure unavailable")
	// ErrFailureCleanupFailed retains failure of bounded joined cleanup.
	ErrFailureCleanupFailed = errors.New("oidc auth: browser failure cleanup failed")
)

// FailureCommand fixes original confirmed consumption and fresh evidence IDs.
// It cannot select success, supply a provider error, or create session authority.
type FailureCommand struct {
	claimed Claimed
	ids     MutationIDs
}

// NewFailureCommand accepts only confirmed consuming evidence and disjoint IDs.
func NewFailureCommand(receipt ClaimResult, ids MutationIDs) (FailureCommand, error) {
	command := FailureCommand{claimed: receipt.claimed, ids: ids}
	if !receipt.IsValid() || !command.IsValid() {
		return FailureCommand{}, ErrInvalidFailure
	}
	return command, nil
}

// IsValid checks immutable evidence shape, not a current consumption lease.
func (command FailureCommand) IsValid() bool {
	if !command.claimed.IsValid() || !command.ids.IsValid() {
		return false
	}
	id := publicid.ID(command.claimed.TransactionID())
	disjointChange := id != command.ids.ChangeID()
	disjointEvents := id != command.ids.AuditEventID() && id != command.ids.OutboxEventID()
	return disjointChange && disjointEvents
}

// Claimed returns the original version-two transition evidence.
func (command FailureCommand) Claimed() Claimed { return command.claimed }

// Snapshot returns original immutable creation evidence, never a verifier.
func (command FailureCommand) Snapshot() PendingSnapshot { return command.claimed.snapshot }

// MutationIDs returns only this terminal transition's fresh identities.
func (command FailureCommand) MutationIDs() MutationIDs { return command.ids }

// String redacts secret-derived binding evidence.
func (FailureCommand) String() string { return "[REDACTED]" }

// GoString redacts detailed formatting.
func (FailureCommand) GoString() string { return "oidcauth.FailureCommand([REDACTED])" }

// LogValue redacts structured formatting.
func (FailureCommand) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Terminated describes a version-three failed/expired transition, not Commit.
type Terminated struct {
	claimed      Claimed
	at           time.Time
	state, class string
}

// NewTerminated checks fixed state/class and microsecond-canonical live DB time.
// Separate durable fields are intentional here: validation must not infer any
// missing state/class/version from a timestamp or grant-like result reference.
func NewTerminated(
	claimed Claimed,
	version int64,
	state, class string,
	at time.Time,
) (Terminated, error) {
	result := Terminated{claimed: claimed, at: at.UTC(), state: state, class: class}
	if version != 3 || !result.IsValid() {
		return Terminated{}, ErrInvalidFailure
	}
	return result, nil
}

// IsValid checks the exclusive deadline classification and original claim binding.
func (result Terminated) IsValid() bool {
	canonicalTime := !result.at.IsZero() && result.at.Nanosecond()%1000 == 0
	orderedTime := !result.at.Before(result.claimed.ConsumedAt())
	if !canonicalTime || !orderedTime || !result.claimed.IsValid() {
		return false
	}
	if result.at.Before(result.claimed.snapshot.ExpiresAt()) {
		return result.state == "failed" && result.class == "authentication_failed"
	}
	return result.state == "expired" && result.class == "deadline_expired"
}

// Claimed returns the unchanged original consumption evidence.
func (result Terminated) Claimed() Claimed { return result.claimed }

// State returns failed or expired, never success.
func (result Terminated) State() string { return result.state }

// FailureClass returns a closed non-provider diagnostic category.
func (result Terminated) FailureClass() string { return result.class }

// TerminatedAt returns the database timestamp after auth/audit lock acquisition.
func (result Terminated) TerminatedAt() time.Time { return result.at }

// Version returns three for valid evidence, zero otherwise.
func (result Terminated) Version() int64 {
	if !result.IsValid() {
		return 0
	}
	return 3
}

// BeforeSemanticHash returns consuming/version-two lifecycle evidence.
func (result Terminated) BeforeSemanticHash() [32]byte {
	if !result.IsValid() {
		return [32]byte{}
	}
	return result.claimed.AfterSemanticHash()
}

// AfterSemanticHash binds original consumption, terminal version/time/state.
func (result Terminated) AfterSemanticHash() [32]byte {
	if !result.IsValid() {
		return [32]byte{}
	}
	material := []byte("meshtransit/oidc-auth/browser-failure-lifecycle/v1\x00")
	before := result.BeforeSemanticHash()
	material = append(material, before[:]...)
	material = binary.BigEndian.AppendUint64(material, 3)
	material = binary.AppendVarint(material, result.at.UnixMicro())
	state := byte(1)
	if result.state == "expired" {
		state = 2
	}
	return sha256.Sum256(append(material, state))
}

// String redacts terminal binding evidence.
func (Terminated) String() string { return "[REDACTED]" }

// GoString redacts detailed formatting.
func (Terminated) GoString() string { return "oidcauth.Terminated([REDACTED])" }

// LogValue redacts structured formatting.
func (Terminated) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// FailureTransactions opens one owned short write unit, not current route admission.
type FailureTransactions interface {
	BeginFailure(context.Context, Route) (FailureTransaction, error)
}

// FailureTransaction atomically erases proof and appends terminal audit/outbox.
// Overlapping methods must reject without queueing or concurrent database I/O.
type FailureTransaction interface {
	Fail(context.Context, FailureCommand) (Terminated, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// FailureOptions bounds complete work and independently joined cleanup.
type FailureOptions struct{ RequestTimeout, RollbackTimeout time.Duration }

// FailureDependencies excludes provider I/O, secret recovery and session issuance.
type FailureDependencies struct {
	Transactions FailureTransactions
	IDs          ClaimIDGenerator
	Clock        StartClock
}

// FailureService owns one no-grant terminal attempt per confirmed claim receipt.
type FailureService struct {
	options      FailureOptions
	dependencies FailureDependencies
}

// NewFailureService validates finite budgets and required dependencies.
func NewFailureService(options FailureOptions, dependencies FailureDependencies) (*FailureService, error) {
	missingDependencies := dependencies.Transactions == nil || dependencies.IDs == nil || dependencies.Clock == nil
	if missingDependencies || !validFailureOptions(options) {
		return nil, ErrInvalidFailure
	}
	return &FailureService{options: options, dependencies: dependencies}, nil
}
func validFailureOptions(options FailureOptions) bool {
	return validClaimOptions(ClaimOptions(options))
}

// FailBrowser burns one failure attempt and any unused exchange before effects.
// Expired claims may be erased; unknown Commit is never resolved or retried.
func (service *FailureService) FailBrowser(
	ctx context.Context,
	receipt ClaimResult,
) (result FailureResult, resultErr error) {
	if ctx == nil || service == nil {
		return result, ErrInvalidFailure
	}
	missingDependencies := service.dependencies.Transactions == nil || service.dependencies.IDs == nil || service.dependencies.Clock == nil
	if missingDependencies || !validFailureOptions(service.options) || !receipt.IsValid() {
		return result, ErrInvalidFailure
	}
	ctx, cancel := context.WithTimeout(ctx, service.options.RequestTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return result, errors.Join(ErrFailureFailed, ctx.Err())
	}
	if !receipt.failureAttempt.CompareAndSwap(false, true) {
		return result, ErrInvalidFailure
	}
	receipt.exchangeAttempt.Store(true)
	ids, err := service.dependencies.IDs.NewClaimIDs()
	if err != nil {
		return result, ErrFailureFailed
	}
	command, err := NewFailureCommand(receipt, ids)
	if err != nil || ctx.Err() != nil {
		return result, errors.Join(ErrFailureFailed, ctx.Err())
	}
	unit, beginErr := service.dependencies.Transactions.BeginFailure(ctx, command.Snapshot().Route())
	committed := false
	if unit != nil {
		defer func() {
			if committed {
				return
			}
			cleanup, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), service.options.RollbackTimeout)
			defer cleanupCancel()
			if errors.Join(unit.Rollback(cleanup), cleanup.Err()) != nil {
				result, resultErr = FailureResult{}, errors.Join(resultErr, ErrFailureCleanupFailed)
			}
		}()
	}
	if beginErr != nil || unit == nil || ctx.Err() != nil {
		return result, errors.Join(ErrFailureFailed, ctx.Err())
	}
	terminal, err := unit.Fail(ctx, command)
	if err != nil || !terminal.IsValid() {
		return result, errors.Join(ErrFailureFailed, ctx.Err())
	}
	sameBinding := terminal.claimed.TransactionID() == command.claimed.TransactionID() &&
		terminal.claimed.snapshot.SemanticHash() == command.claimed.snapshot.SemanticHash()
	sameClaimTime := terminal.claimed.ConsumedAt().Equal(command.claimed.ConsumedAt())
	if !sameBinding || !sameClaimTime {
		return result, errors.Join(ErrFailureFailed, ctx.Err())
	}
	if !authorityTimeReached(service.dependencies.Clock.Now(), terminal.at) || ctx.Err() != nil {
		return result, errors.Join(ErrFailureFailed, ctx.Err())
	}
	if err := unit.Commit(ctx); err != nil {
		if errors.Is(err, ErrCommitOutcomeUnknown) {
			return result, errors.Join(ErrFailureFailed, ErrCommitOutcomeUnknown, ctx.Err())
		}
		return result, errors.Join(ErrFailureFailed, ctx.Err())
	}
	committed = true
	if ctx.Err() != nil || !authorityTimeReached(service.dependencies.Clock.Now(), terminal.at) {
		return result, errors.Join(ErrFailureFailed, ctx.Err())
	}
	return FailureResult{terminal: terminal}, nil
}

// FailureResult is confirmed no-grant terminal evidence; no handle or identity API.
type FailureResult struct{ terminal Terminated }

// IsValid reports that confirmed terminal evidence was released.
func (result FailureResult) IsValid() bool { return result.terminal.IsValid() }

// Terminated returns immutable transition evidence, not session authority.
func (result FailureResult) Terminated() Terminated { return result.terminal }

// String redacts confirmed terminal evidence.
func (FailureResult) String() string { return "[REDACTED]" }

// GoString redacts detailed formatting.
func (FailureResult) GoString() string { return "oidcauth.FailureResult([REDACTED])" }

// LogValue redacts structured formatting.
func (FailureResult) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
