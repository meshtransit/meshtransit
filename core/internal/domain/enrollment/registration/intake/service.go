package intake

import (
	"context"
	"errors"
	"fmt"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
)

const (
	maxAttempts   = 5
	maxPendingTTL = 24 * time.Hour
)

var (
	// ErrInvalidService reports missing dependencies or unsafe bounds.
	ErrInvalidService = errors.New("registration intake: invalid service")
	// ErrAuthenticationFailed is the non-oracular credential rejection returned to callers.
	ErrAuthenticationFailed = errors.New("registration intake: authentication failed")
	// ErrCredentialRejected marks unavailable credential authority at an adapter boundary.
	ErrCredentialRejected = errors.New("registration intake: credential rejected")
	// ErrPrepareFailed classifies an intent that was not prepared durably.
	ErrPrepareFailed = errors.New("registration intake: prepare failed")
	// ErrRetryableTransaction marks a whole transaction that may be replayed.
	ErrRetryableTransaction = errors.New("registration intake: retryable transaction")
	// ErrCommitOutcomeUnknown marks a commit requiring durable intent resolution.
	ErrCommitOutcomeUnknown = errors.New("registration intake: commit outcome unknown")
	// ErrRetryExhausted reports a consumed bounded retry budget.
	ErrRetryExhausted = errors.New("registration intake: retry budget exhausted")
	// ErrRollbackFailed reports a transaction that could not be closed cleanly.
	ErrRollbackFailed = errors.New("registration intake: rollback failed")
)

// Options bounds whole-transaction retry, rollback cleanup, and intent lifetime.
type Options struct {
	MaxAttempts     int
	RollbackTimeout time.Duration
	PendingTTL      time.Duration
}

// Service authenticates credential proof and prepares a durable pending intent.
// It starts no goroutines and retains no request-specific mutable state.
type Service struct {
	options      Options
	transactions Transactions
	prepared     PreparedIntentResolver
	verifier     CredentialVerifier
	evidenceIDs  EvidenceIDGenerator
	retry        RetryWaiter
}

// NewService validates and constructs a registration-intake application service.
func NewService(options Options, dependencies Dependencies) (*Service, error) {
	missingDependency := dependencies.Transactions == nil || dependencies.PreparedIntents == nil ||
		dependencies.CredentialProofs == nil || dependencies.EvidenceIDs == nil ||
		dependencies.Retry == nil
	unsafeBounds := options.MaxAttempts <= 0 || options.MaxAttempts > maxAttempts ||
		options.RollbackTimeout <= 0 || options.RollbackTimeout > 5*time.Second ||
		options.PendingTTL <= 0 || options.PendingTTL > maxPendingTTL
	if missingDependency || unsafeBounds {
		return nil, ErrInvalidService
	}
	return &Service{
		options:      options,
		transactions: dependencies.Transactions,
		prepared:     dependencies.PreparedIntents,
		verifier:     dependencies.CredentialProofs,
		evidenceIDs:  dependencies.EvidenceIDs,
		retry:        dependencies.Retry,
	}, nil
}

// Prepare authenticates a credential without persisting its bearer token and
// creates or replays one semantic registration intent.
func (service *Service) Prepare(ctx context.Context, request Request) (registration.Command, error) {
	if ctx == nil || service == nil || service.transactions == nil || service.prepared == nil ||
		service.verifier == nil || service.evidenceIDs == nil ||
		service.retry == nil || !request.IsValid() {
		return registration.Command{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return registration.Command{}, errors.Join(ErrPrepareFailed, err)
	}
	lookup := Lookup{
		RegistrationID:     request.RegistrationID,
		CredentialID:       request.CredentialID,
		MachineFingerprint: request.Identity.MachineKey().Fingerprint(),
		RequestedNodeKey:   request.Identity.NodeKey().Bytes(),
	}
	if !lookup.IsValid() {
		return registration.Command{}, ErrInvalidRequest
	}

	var evidenceIDs EvidenceIDs
	var lastErr error
	for attempt := 1; attempt <= service.options.MaxAttempts; attempt++ {
		command, err := service.attempt(ctx, request, lookup, &evidenceIDs)
		if err == nil {
			return command, nil
		}
		lastErr = err

		if errors.Is(err, ErrCommitOutcomeUnknown) && command.IsValid() {
			storedHash, found, resolveErr := service.prepared.ResolvePrepared(ctx, command)
			if resolveErr == nil && found {
				commandHash, hashErr := command.RequestHash()
				if hashErr != nil || storedHash != commandHash {
					return registration.Command{}, errors.Join(ErrPrepareFailed, registration.ErrIntentConflict)
				}
				return command, nil
			}
			lastErr = errors.Join(lastErr, resolveErr)
		}

		if !errors.Is(err, ErrRetryableTransaction) && !errors.Is(err, ErrCommitOutcomeUnknown) {
			return registration.Command{}, errors.Join(ErrPrepareFailed, err)
		}
		if attempt == service.options.MaxAttempts {
			return registration.Command{}, errors.Join(ErrPrepareFailed, ErrRetryExhausted, lastErr)
		}
		if err := service.retry.Wait(ctx, attempt); err != nil {
			return registration.Command{}, errors.Join(ErrPrepareFailed, lastErr, err)
		}
	}
	return registration.Command{}, errors.Join(ErrPrepareFailed, ErrRetryExhausted, lastErr)
}

func (service *Service) attempt(
	ctx context.Context,
	request Request,
	lookup Lookup,
	evidenceIDs *EvidenceIDs,
) (command registration.Command, resultErr error) {
	transaction, err := service.transactions.Begin(ctx, lookup)
	if err != nil {
		if errors.Is(err, ErrCredentialRejected) {
			return registration.Command{}, ErrAuthenticationFailed
		}
		return registration.Command{}, fmt.Errorf("begin registration intake: %w", err)
	}
	if transaction == nil {
		return registration.Command{}, ErrInvalidResolution
	}
	finished := false
	defer func() {
		if finished {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			service.options.RollbackTimeout,
		)
		defer cancel()
		if err := transaction.Rollback(rollbackCtx); err != nil {
			unknownCommit := errors.Is(resultErr, ErrCommitOutcomeUnknown)
			command = registration.Command{}
			resultErr = errors.Join(
				ErrRollbackFailed,
				fmt.Errorf("rollback registration intake: %w", err),
			)
			if unknownCommit {
				resultErr = errors.Join(resultErr, ErrCommitOutcomeUnknown)
			}
		}
	}()

	// Credential validity, the pending intent's lifetime and every persisted
	// time are the database clock's.
	now := transaction.DecisionTime()
	if now.IsZero() {
		return registration.Command{}, ErrInvalidService
	}
	resolution, err := transaction.Resolve(ctx, lookup)
	if err != nil {
		if errors.Is(err, ErrCredentialRejected) {
			return registration.Command{}, ErrAuthenticationFailed
		}
		return registration.Command{}, fmt.Errorf("resolve registration intake: %w", err)
	}
	if !resolution.IsValid() {
		return registration.Command{}, ErrInvalidResolution
	}
	authority := resolution.Authority()
	if authority.Credential().ID() != request.CredentialID {
		return registration.Command{}, ErrInvalidResolution
	}
	if !service.verifier.Verify(
		authority.DeploymentID(),
		authority.Credential().IssuedRecoveryEpoch(),
		request.Token,
		authority.Digest(),
	) {
		return registration.Command{}, ErrAuthenticationFailed
	}
	if err := authority.Profile().ValidateCredential(authority.Credential()); err != nil {
		return registration.Command{}, ErrAuthenticationFailed
	}

	intentID := request.RegistrationID
	existingID, existingHash, exists := resolution.ExistingIntent()
	if exists {
		intentID = existingID
	}
	command = registration.Command{
		RegistrationID: intentID,
		Scope:          authority.Scope(),
		CredentialID:   request.CredentialID,
		Identity:       request.Identity,
		Hostname:       request.Hostname,
		RecoveryEpoch:  authority.RecoveryEpoch(),
	}
	requestHash, err := command.RequestHash()
	if err != nil {
		return registration.Command{}, ErrInvalidResolution
	}
	if exists {
		if requestHash != existingHash {
			return registration.Command{}, registration.ErrIntentConflict
		}
		if _, err := authority.Credential().Consume(now, authority.RecoveryEpoch()); err != nil &&
			!errors.Is(err, enrollment.ErrCredentialExhausted) {
			return registration.Command{}, ErrAuthenticationFailed
		}
		return command, nil
	}
	if _, err := authority.Credential().Consume(now, authority.RecoveryEpoch()); err != nil {
		return registration.Command{}, ErrAuthenticationFailed
	}

	if !evidenceIDs.IsValid() {
		*evidenceIDs, err = service.evidenceIDs.NewEvidenceIDs()
		if err != nil || !evidenceIDs.IsValid() {
			return registration.Command{}, errors.Join(ErrInvalidEvidenceIDs, err)
		}
	}
	expiresAt := now.Add(service.options.PendingTTL)
	if authority.Credential().ExpiresAt().Before(expiresAt) {
		expiresAt = authority.Credential().ExpiresAt()
	}
	pending, err := enrollment.NewRegistration(enrollment.RegistrationParams{
		ID:                 command.RegistrationID,
		Scope:              command.Scope,
		ProfileID:          authority.Profile().ID(),
		MachineFingerprint: lookup.MachineFingerprint,
		State:              enrollment.RegistrationStatePending,
		CreatedAt:          now,
		ExpiresAt:          expiresAt,
	})
	if err != nil {
		return registration.Command{}, ErrInvalidChange
	}
	change, err := NewChange(command, pending, requestHash, *evidenceIDs, now)
	if err != nil {
		return registration.Command{}, err
	}
	if err := transaction.Apply(ctx, change); err != nil {
		return registration.Command{}, fmt.Errorf("apply registration intake: %w", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return command, fmt.Errorf("commit registration intake: %w", err)
	}
	finished = true
	return command, nil
}
