package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

var (
	// ErrInvalidStartService reports incomplete dependencies or unsafe budgets.
	ErrInvalidStartService = errors.New("oidc auth: invalid start service")
	// ErrStartFailed reports a login start that cannot release a browser redirect.
	ErrStartFailed = errors.New("oidc auth: login start failed")
	// ErrStartExpired reports creation evidence no longer safe to redirect.
	ErrStartExpired = errors.New("oidc auth: login start expired")
	// ErrStartRollbackFailed reports unsuccessful bounded transaction cleanup.
	ErrStartRollbackFailed = errors.New("oidc auth: login start rollback failed")
)

// MetadataResolver validates provider discovery against a Core-owned route.
type MetadataResolver interface {
	Resolve(context.Context, Route) (Metadata, error)
}

// StartIDGenerator supplies one distinct transaction/audit/outbox identity set.
type StartIDGenerator interface {
	NewStartIDs() (TransactionID, MutationIDs, error)
}

// SecretsGenerator supplies independent operating-system CSPRNG material.
type SecretsGenerator interface {
	NewSecrets() (Secrets, error)
}

// CreationClock supplies authoritative creation time before pending evidence is sealed.
type CreationClock interface {
	CreationTime(context.Context) (time.Time, error)
}

// StartClock supplies the local release decision time.
type StartClock interface {
	Now() time.Time
}

// StartObserver receives only safe, closed categories. Implementations must be
// concurrency-safe and nonblocking; no secret-bearing value reaches telemetry.
type StartObserver interface {
	StartOpened()
	StartClosed(StartOutcome, time.Duration)
}

// StartOptions bounds preparation, durable work, cleanup, and transaction expiry.
type StartOptions struct {
	RequestTimeout  time.Duration
	PendingLifetime time.Duration
	RollbackTimeout time.Duration
	ResolveTimeout  time.Duration
}

// StartDependencies names explicitly owned login-start effects and resident keys.
type StartDependencies struct {
	Metadata       MetadataResolver
	Transactions   Transactions
	Committed      CommittedCreationResolver
	IDs            StartIDGenerator
	Secrets        SecretsGenerator
	CreationClock  CreationClock
	Clock          StartClock
	Observer       StartObserver
	DigestKey      DigestKey
	VerifierCipher *VerifierCipher
}

// StartService prepares one browser transaction, commits it, then releases its
// redirect. It starts no goroutines and keeps no per-request or sticky state.
type StartService struct {
	options      StartOptions
	dependencies StartDependencies
}

// NewStartService rejects unsafe construction before any effect or listener.
func NewStartService(options StartOptions, dependencies StartDependencies) (*StartService, error) {
	if !validStartOptions(options) || !validStartDependencies(dependencies) {
		return nil, ErrInvalidStartService
	}
	return &StartService{options: options, dependencies: dependencies}, nil
}

// Start accepts only an exact route already selected by Core configuration or
// durable routing authority. An HTTP adapter must not construct it from caller
// URLs, and must enforce browser binding/CSRF and admission before invoking Start.
// This use case grants no identity, membership, or Account Session authority.
func (service *StartService) Start(
	ctx context.Context,
	route Route,
) (_ StartResult, resultErr error) {
	if ctx == nil || service == nil || !validStartOptions(service.options) ||
		!validStartDependencies(service.dependencies) {
		return StartResult{}, ErrInvalidStartService
	}
	startedAt := time.Now()
	service.dependencies.Observer.StartOpened()
	defer func() {
		service.dependencies.Observer.StartClosed(startOutcome(resultErr), time.Since(startedAt))
	}()
	if !route.IsValid() {
		return StartResult{}, errors.Join(ErrStartFailed, ErrInvalidRoute)
	}
	requestCtx, cancel := context.WithTimeout(ctx, service.options.RequestTimeout)
	defer cancel()
	prepared, err := service.prepare(requestCtx, route)
	if err != nil {
		return StartResult{}, errors.Join(ErrStartFailed, err)
	}
	pending := prepared.pending
	created, err := service.create(requestCtx, pending)
	if errors.Is(err, ErrCommitOutcomeUnknown) {
		// Settle durable evidence even after caller cancellation, but never release
		// a redirect to a canceled caller. No creation is retried after this lookup.
		resolveCtx, resolveCancel := context.WithTimeout(
			context.WithoutCancel(requestCtx),
			service.options.ResolveTimeout,
		)
		resolved, found, resolveErr := service.dependencies.Committed.ResolveCommitted(resolveCtx, pending)
		resolveErr = errors.Join(resolveErr, resolveCtx.Err())
		resolveCancel()
		if resolveErr != nil || !found {
			return StartResult{}, errors.Join(ErrStartFailed, err, resolveErr)
		}
		if !createdMatchesPending(resolved, pending) {
			return StartResult{}, errors.Join(ErrStartFailed, err, ErrInvalidCreated)
		}
		if errors.Is(err, ErrStartRollbackFailed) {
			return StartResult{}, errors.Join(ErrStartFailed, err)
		}
		created, err = resolved, nil
	}
	if err != nil {
		return StartResult{}, errors.Join(ErrStartFailed, err)
	}
	if err := requestCtx.Err(); err != nil {
		return StartResult{}, errors.Join(ErrStartFailed, err)
	}
	now := service.dependencies.Clock.Now().UTC()
	if !authorityTimeReached(now, created.CreatedAt()) || !now.Before(created.ExpiresAt()) {
		return StartResult{}, errors.Join(ErrStartFailed, ErrStartExpired)
	}
	return StartResult{
		created: created, request: pending.AuthorizationRequest(), preAuthCookie: prepared.preAuthCookie,
	}, nil
}

type preparedStart struct {
	pending       Pending
	preAuthCookie PreAuthCookie
}

func (service *StartService) prepare(ctx context.Context, route Route) (preparedStart, error) {
	if err := ctx.Err(); err != nil {
		return preparedStart{}, err
	}
	metadata, err := service.dependencies.Metadata.Resolve(ctx, route)
	if err != nil {
		return preparedStart{}, fmt.Errorf("resolve login metadata: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return preparedStart{}, err
	}
	transactionID, mutationIDs, err := service.dependencies.IDs.NewStartIDs()
	if err != nil {
		return preparedStart{}, fmt.Errorf("generate login identities: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return preparedStart{}, err
	}
	secrets, err := service.dependencies.Secrets.NewSecrets()
	if err != nil {
		return preparedStart{}, fmt.Errorf("generate login secrets: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return preparedStart{}, err
	}
	now, err := service.dependencies.CreationClock.CreationTime(ctx)
	if err != nil {
		return preparedStart{}, fmt.Errorf("read login creation time: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return preparedStart{}, err
	}
	now = now.UTC()
	if now.IsZero() {
		return preparedStart{}, ErrInvalidPending
	}
	localNow := service.dependencies.Clock.Now().UTC()
	if !authorityTimeReached(localNow, now) || !localNow.Before(now.Add(service.options.PendingLifetime)) {
		return preparedStart{}, ErrStartExpired
	}
	pending, err := NewPending(PendingParams{
		TransactionID: transactionID, Route: route, Metadata: metadata,
		Secrets: secrets, DigestKey: service.dependencies.DigestKey,
		VerifierCipher: service.dependencies.VerifierCipher, MutationIDs: mutationIDs,
		CreatedAt: now, ExpiresAt: now.Add(service.options.PendingLifetime),
	})
	if err != nil {
		return preparedStart{}, err
	}
	return preparedStart{pending: pending, preAuthCookie: secrets.PreAuthCookie()}, nil
}

func (service *StartService) create(
	ctx context.Context,
	pending Pending,
) (_ Created, resultErr error) {
	if err := ctx.Err(); err != nil {
		return Created{}, err
	}
	transaction, beginErr := service.dependencies.Transactions.Begin(ctx, pending.Route())
	if transaction == nil {
		return Created{}, errors.Join(ErrInvalidStartService, beginErr)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		// This only closes owned resources. After a Commit error a successful
		// Rollback does not establish whether PostgreSQL committed the creation.
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.options.RollbackTimeout)
		defer cancel()
		if err := errors.Join(transaction.Rollback(rollbackCtx), rollbackCtx.Err()); err != nil {
			resultErr = errors.Join(resultErr, ErrStartRollbackFailed, fmt.Errorf("rollback login creation: %w", err))
		}
	}()
	if beginErr != nil {
		return Created{}, fmt.Errorf("begin login creation: %w", beginErr)
	}
	if err := ctx.Err(); err != nil {
		return Created{}, err
	}
	created, err := transaction.Create(ctx, pending)
	if err != nil {
		return Created{}, fmt.Errorf("create login transaction: %w", err)
	}
	if !createdMatchesPending(created, pending) {
		return Created{}, ErrInvalidCreated
	}
	if err := ctx.Err(); err != nil {
		return Created{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return Created{}, fmt.Errorf("commit login creation: %w", err)
	}
	committed = true
	return created, nil
}

func createdMatchesPending(created Created, pending Pending) bool {
	return created.IsValid() && created.TransactionID() == pending.TransactionID() &&
		created.CreatedAt().Equal(pending.CreatedAt()) && created.ExpiresAt().Equal(pending.ExpiresAt())
}

func validStartOptions(options StartOptions) bool {
	return options.RequestTimeout > 0 && options.RequestTimeout <= 30*time.Second &&
		options.PendingLifetime >= time.Minute && options.PendingLifetime <= maximumPendingLifetime &&
		options.RollbackTimeout > 0 && options.RollbackTimeout <= 5*time.Second &&
		options.ResolveTimeout > 0 && options.ResolveTimeout <= 5*time.Second
}

func validStartDependencies(dependencies StartDependencies) bool {
	return dependencies.Metadata != nil && dependencies.Transactions != nil &&
		dependencies.Committed != nil && dependencies.IDs != nil && dependencies.Secrets != nil &&
		dependencies.CreationClock != nil && dependencies.Clock != nil && dependencies.Observer != nil && dependencies.DigestKey.isValid() &&
		dependencies.VerifierCipher != nil && dependencies.VerifierCipher.ID().IsValid()
}

// StartResult contains only confirmed durable creation and its secret-bearing
// redirect. Its zero value is invalid and all ordinary formatting is redacted.
type StartResult struct {
	created       Created
	request       AuthorizationRequest
	preAuthCookie PreAuthCookie
}

// Created returns the exact confirmed transaction identity and canonical lifetime.
func (result StartResult) Created() Created { return result.created }

// AuthorizationRequest explicitly releases the secret-bearing browser redirect.
func (result StartResult) AuthorizationRequest() AuthorizationRequest { return result.request }

// PreAuthCookie explicitly releases the independent handle only after confirmed creation.
func (result StartResult) PreAuthCookie() PreAuthCookie { return result.preAuthCookie }

// IsValid reports whether this result contains complete creation and redirect evidence.
func (result StartResult) IsValid() bool {
	return result.created.IsValid() && result.request.IsValid() && result.preAuthCookie.IsValid()
}

// String prevents accidental browser authorization disclosure.
func (StartResult) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed authorization disclosure.
func (StartResult) GoString() string { return "oidcauth.StartResult([REDACTED])" }

// LogValue prevents accidental structured-log authorization disclosure.
func (StartResult) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }
