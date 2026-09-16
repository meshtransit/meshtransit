package oidcauth

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"reflect"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

var (
	// ErrInvalidExpiry rejects invalid no-grant lifecycle evidence or bounds.
	ErrInvalidExpiry = errors.New("oidc auth: invalid browser expiry")
	// ErrExpiryFailed conceals private dependencies and releases no receipt.
	ErrExpiryFailed = errors.New("oidc auth: browser expiry failed")
	// ErrExpiryCleanupFailed retains failure of bounded joined rollback.
	ErrExpiryCleanupFailed = errors.New("oidc auth: browser expiry cleanup failed")
)

// ExpirySnapshotParams contains original durable metadata, never a browser proof.
// Only trusted Deployment-assigned worker code may supply this adapter boundary.
type ExpirySnapshotParams struct {
	DeploymentID                     deployment.ID
	TransactionID                    TransactionID
	State                            string
	Version                          int64
	CreatedAt, ExpiresAt, ConsumedAt time.Time
	SemanticHash                     [32]byte
}

// String redacts original secret-derived creation metadata.
func (ExpirySnapshotParams) String() string { return "[REDACTED]" }

// GoString redacts detailed formatting.
func (ExpirySnapshotParams) GoString() string { return "oidcauth.ExpirySnapshotParams([REDACTED])" }

// LogValue redacts structured formatting.
func (ExpirySnapshotParams) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// ExpirySnapshot is no-grant pending1/consuming2 lifecycle evidence, not a claim.
type ExpirySnapshot struct{ params ExpirySnapshotParams }

// NewExpirySnapshot validates canonical original metadata without routing admission.
func NewExpirySnapshot(params ExpirySnapshotParams) (ExpirySnapshot, error) {
	params.CreatedAt, params.ExpiresAt = params.CreatedAt.UTC(), params.ExpiresAt.UTC()
	if !params.ConsumedAt.IsZero() {
		params.ConsumedAt = params.ConsumedAt.UTC()
	}
	snapshot := ExpirySnapshot{params: params}
	if !snapshot.IsValid() {
		return ExpirySnapshot{}, ErrInvalidExpiry
	}
	return snapshot, nil
}

// IsValid excludes terminal/legacy evidence and never admits a Session.
func (snapshot ExpirySnapshot) IsValid() bool {
	p := snapshot.params
	if !publicid.ID(p.DeploymentID).IsValid() || !publicid.ID(p.TransactionID).IsValid() ||
		p.SemanticHash == [32]byte{} || !expiryTime(p.CreatedAt) || !expiryTime(p.ExpiresAt) ||
		!p.ExpiresAt.After(p.CreatedAt) {
		return false
	}
	if p.State == "pending" && p.Version == 1 {
		return p.ConsumedAt.IsZero()
	}
	return p.State == "consuming" && p.Version == 2 && expiryTime(p.ConsumedAt) &&
		!p.ConsumedAt.Before(p.CreatedAt) && p.ConsumedAt.Before(p.ExpiresAt)
}

func expiryTime(at time.Time) bool {
	return !at.IsZero() && at.Year() >= 1970 && at.Year() <= 9999 && at.Nanosecond()%1000 == 0
}

// Params returns a value copy of original metadata, not a live expiry lease.
func (snapshot ExpirySnapshot) Params() ExpirySnapshotParams { return snapshot.params }

// DeploymentID returns the trusted cleanup assignment.
func (snapshot ExpirySnapshot) DeploymentID() deployment.ID { return snapshot.params.DeploymentID }

// TransactionID identifies the original AuthTransaction.
func (snapshot ExpirySnapshot) TransactionID() TransactionID { return snapshot.params.TransactionID }

// State returns only pending or consuming for valid evidence.
func (snapshot ExpirySnapshot) State() string { return snapshot.params.State }

// Version returns the original lifecycle version.
func (snapshot ExpirySnapshot) Version() int64 { return snapshot.params.Version }

// CreatedAt returns original canonical creation time.
func (snapshot ExpirySnapshot) CreatedAt() time.Time { return snapshot.params.CreatedAt }

// ExpiresAt returns the original exclusive deadline.
func (snapshot ExpirySnapshot) ExpiresAt() time.Time { return snapshot.params.ExpiresAt }

// ConsumedAt returns the original claim time or zero for pending.
func (snapshot ExpirySnapshot) ConsumedAt() time.Time { return snapshot.params.ConsumedAt }

// SemanticHash returns the immutable creation hash, never a fabricated legacy hash.
func (snapshot ExpirySnapshot) SemanticHash() [32]byte { return snapshot.params.SemanticHash }

// String redacts original lifecycle metadata.
func (ExpirySnapshot) String() string { return "[REDACTED]" }

// GoString redacts detailed formatting.
func (ExpirySnapshot) GoString() string { return "oidcauth.ExpirySnapshot([REDACTED])" }

// LogValue redacts structured formatting.
func (ExpirySnapshot) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Expired describes an unconfirmed no-grant terminal transition.
type Expired struct {
	snapshot ExpirySnapshot
	at       time.Time
}

// NewExpired validates a fresh DB decision at or beyond the exclusive deadline.
func NewExpired(snapshot ExpirySnapshot, at time.Time) (Expired, error) {
	terminal := Expired{snapshot: snapshot, at: at.UTC()}
	if !terminal.IsValid() {
		return Expired{}, ErrInvalidExpiry
	}
	return terminal, nil
}

// IsValid checks expiry metadata, not Commit confirmation or browser possession.
func (terminal Expired) IsValid() bool {
	return terminal.snapshot.IsValid() && expiryTime(terminal.at) && !terminal.at.Before(terminal.snapshot.ExpiresAt())
}

// Snapshot returns original no-grant cleanup evidence.
func (terminal Expired) Snapshot() ExpirySnapshot { return terminal.snapshot }

// ExpiredAt returns the DB decision after Auth/audit lock waits.
func (terminal Expired) ExpiredAt() time.Time { return terminal.at }

// Version returns the next version, zero for invalid evidence.
func (terminal Expired) Version() int64 {
	if !terminal.IsValid() {
		return 0
	}
	return terminal.snapshot.Version() + 1
}

// ConsumedAt preserves consuming claims; pending receives only a terminal tombstone.
func (terminal Expired) ConsumedAt() time.Time {
	if terminal.snapshot.State() == "pending" {
		return terminal.at
	}
	return terminal.snapshot.ConsumedAt()
}

// BeforeSemanticHash reuses the existing browser-claim lifecycle encoding.
func (terminal Expired) BeforeSemanticHash() [32]byte {
	if !terminal.IsValid() {
		return [32]byte{}
	}
	version := uint64(1)
	if terminal.snapshot.State() == "consuming" {
		version = 2
	}
	return hashClaimLifecycle(terminal.snapshot.SemanticHash(), version, terminal.snapshot.ConsumedAt())
}

// AfterSemanticHash binds the terminal version and decision to the original lifecycle.
func (terminal Expired) AfterSemanticHash() [32]byte {
	if !terminal.IsValid() {
		return [32]byte{}
	}
	before := terminal.BeforeSemanticHash()
	material := append([]byte("meshtransit/oidc-auth/browser-expiry-lifecycle/v1\x00"), before[:]...)
	version := uint64(2)
	if terminal.snapshot.State() == "consuming" {
		version = 3
	}
	material = binary.BigEndian.AppendUint64(material, version)
	return sha256.Sum256(binary.AppendVarint(material, terminal.at.UnixMicro()))
}

// String redacts terminal metadata.
func (Expired) String() string { return "[REDACTED]" }

// GoString redacts detailed formatting.
func (Expired) GoString() string { return "oidcauth.Expired([REDACTED])" }

// LogValue redacts structured formatting.
func (Expired) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// ExpiryCommand binds original cleanup metadata to three fresh evidence IDs.
type ExpiryCommand struct {
	snapshot ExpirySnapshot
	ids      MutationIDs
}

// NewExpiryCommand rejects malformed or colliding evidence IDs before Begin.
func NewExpiryCommand(snapshot ExpirySnapshot, ids MutationIDs) (ExpiryCommand, error) {
	command := ExpiryCommand{snapshot: snapshot, ids: ids}
	if !command.IsValid() {
		return ExpiryCommand{}, ErrInvalidExpiry
	}
	return command, nil
}

// IsValid checks shape, not current durable state or a grant.
func (command ExpiryCommand) IsValid() bool {
	id := publicid.ID(command.snapshot.TransactionID())
	return command.snapshot.IsValid() && command.ids.IsValid() && id != command.ids.ChangeID() &&
		id != command.ids.AuditEventID() && id != command.ids.OutboxEventID()
}

// Snapshot returns immutable original cleanup evidence.
func (command ExpiryCommand) Snapshot() ExpirySnapshot { return command.snapshot }

// MutationIDs returns only this transition's fresh evidence identities.
func (command ExpiryCommand) MutationIDs() MutationIDs { return command.ids }

// String redacts cleanup commands.
func (ExpiryCommand) String() string { return "[REDACTED]" }

// GoString redacts detailed formatting.
func (ExpiryCommand) GoString() string { return "oidcauth.ExpiryCommand([REDACTED])" }

// LogValue redacts structured formatting.
func (ExpiryCommand) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// ExpiryCandidates reads a bounded, ordered hint batch without proof or routing I/O.
type ExpiryCandidates interface {
	// ListDue returns original lifecycle hints, not an expiry/authorization lease.
	ListDue(context.Context, deployment.ID, int) ([]ExpirySnapshot, error)
}

// ExpiryTransactions opens a single owned no-grant write unit.
type ExpiryTransactions interface {
	// BeginExpiry fixes the exact trusted Deployment assignment for one owned unit.
	BeginExpiry(context.Context, deployment.ID) (ExpiryTransaction, error)
}

// ExpiryTransaction rejects overlapping methods without queuing database I/O.
type ExpiryTransaction interface {
	// Expire compares original metadata and commits neither transition nor evidence.
	Expire(context.Context, ExpiryCommand) (Expired, error)
	// Commit confirms the single prepared no-grant transition without replay.
	Commit(context.Context) error
	// Rollback joins bounded cleanup and cannot resolve an unknown Commit.
	Rollback(context.Context) error
}

// ExpiryOptions bounds the complete pass, each unit and independent joined cleanup.
type ExpiryOptions struct {
	BatchSize                                 int
	PassTimeout, UnitTimeout, RollbackTimeout time.Duration
}

// ExpiryDependencies excludes browser/provider/cipher/session and retry effects.
type ExpiryDependencies struct {
	Candidates   ExpiryCandidates
	Transactions ExpiryTransactions
	IDs          ClaimIDGenerator
	Clock        StartClock
}

// ExpiryService runs explicit bounded no-grant passes; it owns no background work.
type ExpiryService struct {
	options      ExpiryOptions
	dependencies ExpiryDependencies
}

// NewExpiryService validates finite bounds before any authority effect.
func NewExpiryService(options ExpiryOptions, dependencies ExpiryDependencies) (*ExpiryService, error) {
	service := &ExpiryService{options: options, dependencies: dependencies}
	if !service.valid() {
		return nil, ErrInvalidExpiry
	}
	return service, nil
}

func (service *ExpiryService) valid() bool {
	if service == nil {
		return false
	}
	options, dependencies := service.options, service.dependencies
	if options.BatchSize < 1 || options.BatchSize > 128 || options.PassTimeout <= 0 ||
		options.PassTimeout > 30*time.Second || !validClaimOptions(ClaimOptions{
		RequestTimeout: options.UnitTimeout, RollbackTimeout: options.RollbackTimeout,
	}) || nilExpiryDependency(dependencies.Candidates) || nilExpiryDependency(dependencies.Transactions) ||
		nilExpiryDependency(dependencies.IDs) || nilExpiryDependency(dependencies.Clock) {
		return false
	}
	return true
}

func nilExpiryDependency(value any) bool {
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

// ExpiryPass contains bounded aggregate counts, no private lifecycle identifiers.
// Attempted includes a unit rejected before SQL; Confirmed counts released receipts.
type ExpiryPass struct{ Attempted, Confirmed int }

// Sweep processes a validated hint batch sequentially; any failure ends this pass.
// Later passes reread durable open rows with fresh IDs, never replay an owned attempt.
func (service *ExpiryService) Sweep(ctx context.Context, dep deployment.ID) (ExpiryPass, error) {
	if ctx == nil || !service.valid() || !publicid.ID(dep).IsValid() {
		return ExpiryPass{}, ErrInvalidExpiry
	}
	ctx, cancel := context.WithTimeout(ctx, service.options.PassTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return ExpiryPass{}, errors.Join(ErrExpiryFailed, ctx.Err())
	}
	batch, err := service.dependencies.Candidates.ListDue(ctx, dep, service.options.BatchSize)
	if err != nil || len(batch) > service.options.BatchSize || ctx.Err() != nil {
		return ExpiryPass{}, errors.Join(ErrExpiryFailed, expiryDependencyClass(err), ctx.Err())
	}
	seen := make(map[TransactionID]struct{}, len(batch))
	for _, snapshot := range batch {
		if !snapshot.IsValid() || snapshot.DeploymentID() != dep ||
			service.dependencies.Clock.Now().Before(snapshot.ExpiresAt()) {
			return ExpiryPass{}, ErrExpiryFailed
		}
		if _, duplicate := seen[snapshot.TransactionID()]; duplicate {
			return ExpiryPass{}, ErrExpiryFailed
		}
		seen[snapshot.TransactionID()] = struct{}{}
	}
	var pass ExpiryPass
	for _, snapshot := range batch {
		pass.Attempted++
		if result, err := service.Expire(ctx, snapshot); err != nil || !result.IsValid() {
			return pass, errors.Join(ErrExpiryFailed, err)
		}
		pass.Confirmed++
	}
	return pass, ctx.Err()
}

// Expire prepares evidence before Begin and releases a receipt only after confirmed Commit.
func (service *ExpiryService) Expire(
	ctx context.Context,
	snapshot ExpirySnapshot,
) (result ExpiryResult, resultErr error) {
	if ctx == nil || !service.valid() || !snapshot.IsValid() {
		return result, ErrInvalidExpiry
	}
	ctx, cancel := context.WithTimeout(ctx, service.options.UnitTimeout)
	defer cancel()
	if ctx.Err() != nil || service.dependencies.Clock.Now().Before(snapshot.ExpiresAt()) {
		return result, errors.Join(ErrExpiryFailed, ctx.Err())
	}
	ids, err := service.dependencies.IDs.NewClaimIDs()
	if err != nil {
		return result, ErrExpiryFailed
	}
	command, err := NewExpiryCommand(snapshot, ids)
	if err != nil || ctx.Err() != nil {
		return result, errors.Join(ErrExpiryFailed, ctx.Err())
	}
	unit, beginErr := service.dependencies.Transactions.BeginExpiry(ctx, snapshot.DeploymentID())
	committed := false
	if !nilExpiryDependency(unit) {
		defer func() {
			if committed {
				return
			}
			cleanup, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), service.options.RollbackTimeout)
			defer cleanupCancel()
			if errors.Join(unit.Rollback(cleanup), cleanup.Err()) != nil {
				result, resultErr = ExpiryResult{}, errors.Join(resultErr, ErrExpiryCleanupFailed)
			}
		}()
	}
	if beginErr != nil || nilExpiryDependency(unit) || ctx.Err() != nil {
		return result, errors.Join(ErrExpiryFailed, expiryDependencyClass(beginErr), ctx.Err())
	}
	terminal, err := unit.Expire(ctx, command)
	if err != nil || !terminal.IsValid() || terminal.Snapshot().Params() != snapshot.Params() ||
		service.dependencies.Clock.Now().Before(terminal.ExpiredAt()) || ctx.Err() != nil {
		return result, errors.Join(ErrExpiryFailed, ctx.Err())
	}
	if err := unit.Commit(ctx); err != nil {
		if errors.Is(err, ErrCommitOutcomeUnknown) {
			return result, errors.Join(ErrExpiryFailed, ErrCommitOutcomeUnknown, ctx.Err())
		}
		return result, errors.Join(ErrExpiryFailed, ctx.Err())
	}
	committed = true
	if ctx.Err() != nil || service.dependencies.Clock.Now().Before(terminal.ExpiredAt()) {
		return result, errors.Join(ErrExpiryFailed, ctx.Err())
	}
	return ExpiryResult{terminal: terminal}, nil
}

// expiryDependencyClass preserves only closed ownership/cancellation categories.
// It cannot retain the dependency error chain or its potentially private text.
func expiryDependencyClass(err error) error {
	var classified error
	for _, category := range []error{ErrExpiryCleanupFailed, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, category) {
			classified = errors.Join(classified, category)
		}
	}
	return classified
}

// ExpiryResult is confirmed no-grant terminal evidence, never a browser or Session handle.
type ExpiryResult struct{ terminal Expired }

// IsValid reports that confirmed expiry evidence was released.
func (result ExpiryResult) IsValid() bool { return result.terminal.IsValid() }

// Expired returns immutable no-grant terminal evidence.
func (result ExpiryResult) Expired() Expired { return result.terminal }

// String redacts confirmed lifecycle evidence.
func (ExpiryResult) String() string { return "[REDACTED]" }

// GoString redacts detailed formatting.
func (ExpiryResult) GoString() string { return "oidcauth.ExpiryResult([REDACTED])" }

// LogValue redacts structured formatting.
func (ExpiryResult) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
