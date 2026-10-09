package oidcauth

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

var (
	// ErrInvalidClaim rejects unverified commands, malformed evidence, or unsafe setup.
	ErrInvalidClaim = errors.New("oidc auth: invalid browser claim")
	// ErrClaimFailed conceals private dependency details and releases no receipt.
	ErrClaimFailed = errors.New("oidc auth: browser claim failed")
	// ErrClaimCleanupFailed retains failure of bounded joined resource cleanup.
	ErrClaimCleanupFailed = errors.New("oidc auth: browser claim cleanup failed")
)

// ClaimCommand binds opaque verified possession to fresh transition evidence IDs.
// It contains no plaintext PKCE; a snapshot alone cannot construct this command.
type ClaimCommand struct {
	snapshot PendingSnapshot
	ids      MutationIDs
}

// NewClaimCommand checks possession shape and disjoint UUIDv7 evidence identities.
func NewClaimCommand(verified VerifiedBrowser, ids MutationIDs) (ClaimCommand, error) {
	command := ClaimCommand{snapshot: verified.snapshot, ids: ids}
	if !verified.IsValid() || !command.IsValid() {
		return ClaimCommand{}, ErrInvalidClaim
	}
	return command, nil
}

// IsValid checks immutable evidence, not a live database consumption lease.
func (command ClaimCommand) IsValid() bool {
	id := publicid.ID(command.snapshot.TransactionID())
	return command.snapshot.IsValid() && command.ids.IsValid() && id != command.ids.ChangeID() && id != command.ids.AuditEventID() && id != command.ids.OutboxEventID()
}

// Snapshot returns original creation evidence for the locked compare-and-transition.
func (command ClaimCommand) Snapshot() PendingSnapshot { return command.snapshot }

// MutationIDs returns only the fresh transition's evidence identities.
func (command ClaimCommand) MutationIDs() MutationIDs { return command.ids }

// String redacts the command's secret-derived evidence.
func (ClaimCommand) String() string { return "[REDACTED]" }

// GoString redacts detailed command formatting.
func (ClaimCommand) GoString() string { return "oidcauth.ClaimCommand([REDACTED])" }

// LogValue redacts structured command formatting.
func (ClaimCommand) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Claimed describes a consuming/version-two transition, not confirmed Commit.
// The original creation binding hash remains immutable in the database.
type Claimed struct {
	snapshot   PendingSnapshot
	consumedAt time.Time
}

// NewClaimed rejects noncanonical or nonlive durable transition timestamps.
func NewClaimed(snapshot PendingSnapshot, version int64, consumedAt time.Time) (Claimed, error) {
	claimed := Claimed{snapshot: snapshot, consumedAt: consumedAt.UTC()}
	if version != 2 || !claimed.IsValid() {
		return Claimed{}, ErrInvalidClaim
	}
	return claimed, nil
}

// IsValid checks transition evidence shape, not durable Commit confirmation.
func (claimed Claimed) IsValid() bool {
	return claimed.snapshot.IsValid() && !claimed.consumedAt.IsZero() && claimed.consumedAt.Nanosecond()%1000 == 0 && livePendingSnapshot(claimed.snapshot, claimed.consumedAt)
}

// TransactionID returns the original identity; claiming creates no new transaction.
func (claimed Claimed) TransactionID() TransactionID { return claimed.snapshot.TransactionID() }

// Version returns two for valid claim evidence, zero for invalid evidence.
func (claimed Claimed) Version() int64 {
	if !claimed.IsValid() {
		return 0
	}
	return 2
}

// ConsumedAt returns the live database clock timestamp after authority/auth locks.
func (claimed Claimed) ConsumedAt() time.Time { return claimed.consumedAt }

// BeforeSemanticHash binds original creation evidence to pending/version one.
func (claimed Claimed) BeforeSemanticHash() [32]byte {
	if !claimed.IsValid() {
		return [32]byte{}
	}
	return hashClaimLifecycle(claimed.snapshot.SemanticHash(), 1, time.Time{})
}

// AfterSemanticHash binds original creation evidence to consuming/version two/time.
func (claimed Claimed) AfterSemanticHash() [32]byte {
	if !claimed.IsValid() {
		return [32]byte{}
	}
	return hashClaimLifecycle(claimed.snapshot.SemanticHash(), 2, claimed.consumedAt)
}

// String redacts claim evidence.
func (Claimed) String() string { return "[REDACTED]" }

// GoString redacts detailed claim evidence.
func (Claimed) GoString() string { return "oidcauth.Claimed([REDACTED])" }

// LogValue redacts structured claim evidence.
func (Claimed) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func hashClaimLifecycle(binding [32]byte, version uint64, consumedAt time.Time) [32]byte {
	material := []byte("meshtransit/oidc-auth/browser-claim-lifecycle/v1\x00")
	material = append(material, binding[:]...)
	material = binary.BigEndian.AppendUint64(material, version)
	var consumedMicros int64
	if !consumedAt.IsZero() {
		consumedMicros = consumedAt.UnixMicro()
	}
	material = binary.AppendVarint(material, consumedMicros)
	return sha256.Sum256(material)
}

// ClaimTransactions opens one owned short read-write unit; no replay resolver.
type ClaimTransactions interface {
	// BeginClaim fixes the exact route and returns any owned unit even on setup error.
	BeginClaim(context.Context, Route) (ClaimTransaction, error)
}

// ClaimTransaction atomically transitions pending and appends audit/outbox.
// Methods must reject overlapping calls without queuing or concurrent database I/O.
type ClaimTransaction interface {
	// Claim locks current authority/auth and verifies original version/hash/live expiry.
	Claim(context.Context, ClaimCommand) (Claimed, error)
	// Commit confirms the single attempted transition; unknown completion is not replayable.
	Commit(context.Context) error
	// Rollback joins owned cleanup; it cannot resolve an uncertain Commit outcome.
	Rollback(context.Context) error
}

// ClaimIDGenerator prepares fresh transition evidence before Begin, never a new auth ID.
type ClaimIDGenerator interface{ NewClaimIDs() (MutationIDs, error) }

// SystemClaimIDs uses OS-backed UUIDv7 generation for exactly three evidence IDs.
type SystemClaimIDs struct{}

// NewClaimIDs generates fresh change/audit/outbox identities without database I/O.
func (SystemClaimIDs) NewClaimIDs() (MutationIDs, error) {
	var values [3]publicid.ID
	for index := range values {
		value, err := publicid.New()
		if err != nil {
			return MutationIDs{}, err
		}
		values[index] = value
	}
	return NewMutationIDs(MutationIDParams{ChangeID: values[0], AuditEventID: values[1], OutboxEventID: values[2]})
}

// ClaimOptions bounds the entire claim and independently joined cleanup.
type ClaimOptions struct{ RequestTimeout, RollbackTimeout time.Duration }

// ClaimDependencies names effects; no provider, cipher, token, session, or resolver.
type ClaimDependencies struct {
	Transactions ClaimTransactions
	IDs          ClaimIDGenerator
	Clock        StartClock
}

// ClaimService consumes verified browser evidence without performing token exchange.
type ClaimService struct {
	options      ClaimOptions
	dependencies ClaimDependencies
}

// NewClaimService rejects invalid construction before any effects.
func NewClaimService(options ClaimOptions, dependencies ClaimDependencies) (*ClaimService, error) {
	if !validClaimOptions(options) || dependencies.Transactions == nil || dependencies.IDs == nil || dependencies.Clock == nil {
		return nil, ErrInvalidClaim
	}
	return &ClaimService{options: options, dependencies: dependencies}, nil
}
func validClaimOptions(options ClaimOptions) bool {
	return options.RequestTimeout > 0 && options.RequestTimeout <= 30*time.Second && options.RollbackTimeout > 0 && options.RollbackTimeout <= 5*time.Second
}

// ClaimBrowser returns an opaque receipt only after confirmed Commit and fresh
// release checks. Unknown completion fails closed without resolution/retry.
func (service *ClaimService) ClaimBrowser(ctx context.Context, verified VerifiedBrowser) (result ClaimResult, resultErr error) {
	if ctx == nil || service == nil || !validClaimOptions(service.options) || service.dependencies.Transactions == nil || service.dependencies.IDs == nil || service.dependencies.Clock == nil || !verified.IsValid() {
		return ClaimResult{}, ErrInvalidClaim
	}
	ctx, cancel := context.WithTimeout(ctx, service.options.RequestTimeout)
	defer cancel()
	if ctx.Err() != nil || !livePendingSnapshotAtLocalClock(verified.snapshot, service.dependencies.Clock.Now()) {
		return result, errors.Join(ErrClaimFailed, ctx.Err())
	}
	ids, err := service.dependencies.IDs.NewClaimIDs()
	if err != nil {
		return result, ErrClaimFailed
	}
	command, err := NewClaimCommand(verified, ids)
	if err != nil || ctx.Err() != nil {
		return result, errors.Join(ErrClaimFailed, ctx.Err())
	}
	unit, beginErr := service.dependencies.Transactions.BeginClaim(ctx, command.Snapshot().Route())
	committed := false
	if unit != nil {
		defer func() {
			if committed {
				return
			}
			cleanup, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), service.options.RollbackTimeout)
			defer cleanupCancel()
			if err := errors.Join(unit.Rollback(cleanup), cleanup.Err()); err != nil {
				result, resultErr = ClaimResult{}, errors.Join(resultErr, ErrClaimCleanupFailed)
			}
		}()
	}
	if beginErr != nil || unit == nil || ctx.Err() != nil {
		return result, errors.Join(ErrClaimFailed, ctx.Err())
	}
	claimed, err := unit.Claim(ctx, command)
	if err != nil {
		return result, errors.Join(ErrClaimFailed, ctx.Err())
	}
	now := service.dependencies.Clock.Now()
	if !claimed.IsValid() || claimed.TransactionID() != verified.snapshot.TransactionID() || claimed.snapshot.SemanticHash() != verified.snapshot.SemanticHash() || ctx.Err() != nil || !authorityTimeReached(now, claimed.ConsumedAt()) || !livePendingSnapshotAtLocalClock(verified.snapshot, now) {
		return result, errors.Join(ErrClaimFailed, ctx.Err())
	}
	if err := unit.Commit(ctx); err != nil {
		if errors.Is(err, ErrCommitOutcomeUnknown) {
			return result, errors.Join(ErrClaimFailed, ErrCommitOutcomeUnknown, ctx.Err())
		}
		return result, errors.Join(ErrClaimFailed, ctx.Err())
	}
	committed = true
	now = service.dependencies.Clock.Now()
	if !authorityTimeReached(now, claimed.ConsumedAt()) || !livePendingSnapshotAtLocalClock(verified.snapshot, now) || ctx.Err() != nil {
		return result, errors.Join(ErrClaimFailed, ctx.Err())
	}
	return ClaimResult{claimed: claimed, exchangeAttempt: &atomic.Bool{}, failureAttempt: &atomic.Bool{}}, nil
}

// ClaimResult is confirmed consumption evidence with private exchange/failure attempts.
// Copies share non-queuing gates; a restart cannot recreate either capability.
// It releases no plaintext verifier, provider credential, identity, or session.
type ClaimResult struct {
	claimed         Claimed
	exchangeAttempt *atomic.Bool
	failureAttempt  *atomic.Bool
}

// IsValid checks whether the service released confirmed consuming evidence.
func (result ClaimResult) IsValid() bool {
	return result.claimed.IsValid() && result.exchangeAttempt != nil && result.failureAttempt != nil
}

// Claimed returns safe immutable transition evidence, not exchange material.
func (result ClaimResult) Claimed() Claimed { return result.claimed }

// String redacts the confirmed receipt.
func (ClaimResult) String() string { return "[REDACTED]" }

// GoString redacts detailed confirmed receipt formatting.
func (ClaimResult) GoString() string { return "oidcauth.ClaimResult([REDACTED])" }

// LogValue redacts structured confirmed receipt formatting.
func (ClaimResult) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
