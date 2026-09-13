package registration

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/node"
)

const maxRegistrationAttempts = 5

var (
	// ErrInvalidService reports missing dependencies or unsafe retry settings.
	ErrInvalidService = errors.New("registration: invalid service")
	// ErrRegistrationFailed classifies a registration that did not commit.
	ErrRegistrationFailed = errors.New("registration: operation failed")
	// ErrRetryableTransaction marks a complete transaction attempt that may be replayed.
	ErrRetryableTransaction = errors.New("registration: retryable transaction")
	// ErrCommitOutcomeUnknown marks a commit whose durable outcome must be resolved by intent ID.
	ErrCommitOutcomeUnknown = errors.New("registration: commit outcome unknown")
	// ErrRetryExhausted reports that the bounded whole-transaction retry budget was consumed.
	ErrRetryExhausted = errors.New("registration: retry budget exhausted")
	// ErrRollbackFailed reports that a failed transaction could not be closed cleanly.
	ErrRollbackFailed = errors.New("registration: rollback failed")
)

// Options bounds transaction retry and rollback cleanup behavior.
type Options struct {
	MaxAttempts     int
	RollbackTimeout time.Duration
}

// Service owns registration transaction boundaries and domain orchestration.
// It starts no goroutines and retains no request-specific mutable state.
type Service struct {
	options      Options
	transactions Transactions
	ids          NodeIDGenerator
	clock        Clock
	retry        RetryWaiter
}

// NewService validates and constructs a registration application service.
func NewService(
	options Options,
	transactions Transactions,
	ids NodeIDGenerator,
	clock Clock,
	retry RetryWaiter,
) (*Service, error) {
	if transactions == nil || ids == nil || clock == nil || retry == nil ||
		options.MaxAttempts <= 0 || options.MaxAttempts > maxRegistrationAttempts ||
		options.RollbackTimeout <= 0 || options.RollbackTimeout > 5*time.Second {
		return nil, ErrInvalidService
	}
	return &Service{
		options:      options,
		transactions: transactions,
		ids:          ids,
		clock:        clock,
		retry:        retry,
	}, nil
}

// Register creates or resumes one logical Node. Retry replays the entire
// transaction with the same decision time and generated Node ID.
func (service *Service) Register(ctx context.Context, command Command) (Result, error) {
	if ctx == nil || service == nil || service.transactions == nil || service.ids == nil ||
		service.clock == nil || service.retry == nil || !command.IsValid() {
		return Result{}, ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return Result{}, errors.Join(ErrRegistrationFailed, err)
	}
	now := service.clock.Now().UTC()
	if now.IsZero() {
		return Result{}, ErrInvalidService
	}

	var generatedNodeID node.ID
	var lastErr error
	for attempt := 1; attempt <= service.options.MaxAttempts; attempt++ {
		result, err := service.attempt(ctx, command, now, &generatedNodeID)
		if err == nil {
			return result, nil
		}
		lastErr = err

		if errors.Is(err, ErrCommitOutcomeUnknown) {
			resolved, found, resolveErr := service.transactions.ResolveCommitted(ctx, command)
			if resolveErr == nil && found {
				if !resultMatchesCommand(resolved, command) {
					return Result{}, errors.Join(ErrRegistrationFailed, ErrInvalidResult)
				}
				return resolved, nil
			}
			lastErr = errors.Join(lastErr, resolveErr)
		}

		if !errors.Is(err, ErrRetryableTransaction) && !errors.Is(err, ErrCommitOutcomeUnknown) {
			return Result{}, errors.Join(ErrRegistrationFailed, err)
		}
		if attempt == service.options.MaxAttempts {
			return Result{}, errors.Join(ErrRegistrationFailed, ErrRetryExhausted, lastErr)
		}
		if err := service.retry.Wait(ctx, attempt); err != nil {
			return Result{}, errors.Join(ErrRegistrationFailed, lastErr, err)
		}
	}
	return Result{}, errors.Join(ErrRegistrationFailed, ErrRetryExhausted, lastErr)
}

func (service *Service) attempt(
	ctx context.Context,
	command Command,
	now time.Time,
	generatedNodeID *node.ID,
) (result Result, resultErr error) {
	transaction, err := service.transactions.Begin(ctx, command.Scope)
	if err != nil {
		return Result{}, fmt.Errorf("begin registration transaction: %w", err)
	}
	finished := false
	defer func() {
		if finished {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.options.RollbackTimeout)
		defer cancel()
		if err := transaction.Rollback(rollbackCtx); err != nil {
			unknownCommit := errors.Is(resultErr, ErrCommitOutcomeUnknown)
			attemptErr := resultErr
			attemptMessage := "no prior error"
			if attemptErr != nil {
				attemptMessage = attemptErr.Error()
			}
			result = Result{}
			resultErr = errors.Join(
				ErrRollbackFailed,
				fmt.Errorf("rollback registration transaction after %s: %w", attemptMessage, err),
			)
			if unknownCommit {
				resultErr = errors.Join(resultErr, ErrCommitOutcomeUnknown)
			}
		}
	}()

	resolution, err := transaction.Resolve(ctx, command)
	if err != nil {
		return Result{}, fmt.Errorf("resolve registration under lock: %w", err)
	}
	if err := validateResolution(command, resolution); err != nil {
		return Result{}, err
	}
	if completed, ok := resolution.CompletedResult(); ok {
		return completed, nil
	}

	credential, err := resolution.Credential().Consume(now, command.RecoveryEpoch)
	if err != nil {
		return Result{}, err
	}
	registration := resolution.Registration()
	if registration.State() == enrollment.RegistrationStatePending {
		registration, err = registration.Authorize(now)
		if err != nil {
			return Result{}, err
		}
	}

	nodeID, exists := resolution.ExistingNodeID()
	disposition := DispositionResumed
	if !exists {
		disposition = DispositionCreated
		if !generatedNodeID.IsValid() {
			*generatedNodeID, err = service.ids.NewNodeID()
			if err != nil {
				return Result{}, fmt.Errorf("generate Node ID: %w", err)
			}
		}
		nodeID = *generatedNodeID
	}
	registration, err = registration.Complete(nodeID, now)
	if err != nil {
		return Result{}, err
	}
	change, err := NewChange(
		registration,
		credential,
		command.Identity,
		nodeID,
		command.Hostname,
		disposition,
		now,
	)
	if err != nil {
		return Result{}, err
	}
	result, err = transaction.Apply(ctx, change)
	if err != nil {
		return Result{}, fmt.Errorf("apply registration change: %w", err)
	}
	if !resultMatchesChange(result, change) {
		return Result{}, ErrInvalidResult
	}
	if err := transaction.Commit(ctx); err != nil {
		return Result{}, fmt.Errorf("commit registration transaction: %w", err)
	}
	finished = true
	return result, nil
}

func validateResolution(command Command, resolution Resolution) error {
	registration := resolution.Registration()
	if !registration.IsValid() || registration.ID() != command.RegistrationID ||
		registration.Scope() != command.Scope {
		return ErrInvalidResolution
	}
	if registration.MachineFingerprint() != command.Identity.MachineKey().Fingerprint() {
		return ErrIntentConflict
	}
	requestHash, err := command.RequestHash()
	if err != nil {
		return ErrInvalidCommand
	}
	if resolution.RequestHash() != requestHash {
		return ErrIntentConflict
	}
	if completed, ok := resolution.CompletedResult(); ok {
		identity, identityOK := resolution.CompletedIdentity()
		if !identityOK {
			return ErrInvalidResolution
		}
		if identity != command.Identity || resolution.CredentialID() != command.CredentialID {
			return ErrIntentConflict
		}
		if !resultMatchesCommand(completed, command) {
			return ErrInvalidResolution
		}
		return nil
	}
	credential := resolution.Credential()
	if !credential.IsValid() || credential.ProfileID() != registration.ProfileID() {
		return ErrInvalidResolution
	}
	if credential.ID() != command.CredentialID {
		return ErrIntentConflict
	}
	return nil
}

func resultMatchesCommand(result Result, command Command) bool {
	return result.IsValid() && result.RegistrationID() == command.RegistrationID &&
		result.Scope() == command.Scope
}

func resultMatchesChange(result Result, change Change) bool {
	return result.IsValid() && result.RegistrationID() == change.Registration().ID() &&
		result.Scope() == change.Registration().Scope() && result.NodeID() == change.NodeID() &&
		result.Disposition() == change.Disposition()
}
