package registration

import (
	"context"
	"errors"
	"fmt"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/node"
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
	committed    CommittedResultResolver
	nodeIDs      NodeIDGenerator
	mutationIDs  MutationIDGenerator
	retry        RetryWaiter
}

// NewService validates and constructs a registration application service.
func NewService(options Options, dependencies Dependencies) (*Service, error) {
	if dependencies.Transactions == nil || dependencies.CommittedResults == nil ||
		dependencies.NodeIDs == nil ||
		dependencies.MutationIDs == nil || dependencies.Retry == nil ||
		options.MaxAttempts <= 0 || options.MaxAttempts > maxRegistrationAttempts ||
		options.RollbackTimeout <= 0 || options.RollbackTimeout > 5*time.Second {
		return nil, ErrInvalidService
	}
	return &Service{
		options:      options,
		transactions: dependencies.Transactions,
		committed:    dependencies.CommittedResults,
		nodeIDs:      dependencies.NodeIDs,
		mutationIDs:  dependencies.MutationIDs,
		retry:        dependencies.Retry,
	}, nil
}

// Register creates or resumes one logical Node. Retry replays the entire
// transaction with the same application-generated IDs; each attempt decides
// on its own transaction's database time.
func (service *Service) Register(ctx context.Context, command Command) (Result, error) {
	if ctx == nil || service == nil || service.transactions == nil || service.committed == nil ||
		service.nodeIDs == nil ||
		service.mutationIDs == nil || service.retry == nil || !command.IsValid() {
		return Result{}, ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return Result{}, errors.Join(ErrRegistrationFailed, err)
	}
	var generatedNodeID node.ID
	var generatedMutationIDs MutationIDs
	var lastErr error
	for attempt := 1; attempt <= service.options.MaxAttempts; attempt++ {
		result, err := service.attempt(
			ctx,
			command,
			&generatedNodeID,
			&generatedMutationIDs,
		)
		if err == nil {
			return result, nil
		}
		lastErr = err

		if errors.Is(err, ErrCommitOutcomeUnknown) {
			resolved, found, resolveErr := service.committed.ResolveCommitted(ctx, command)
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
	generatedNodeID *node.ID,
	generatedMutationIDs *MutationIDs,
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

	// Credential and registration validity, the Device's expiry and every
	// persisted time are the database clock's.
	now := transaction.DecisionTime()
	if now.IsZero() {
		return Result{}, ErrInvalidService
	}
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

	profile := resolution.Profile()
	if err := profile.ValidateCredential(resolution.Credential()); err != nil {
		return Result{}, err
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
			*generatedNodeID, err = service.nodeIDs.NewNodeID()
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
	if !generatedMutationIDs.IsValid() {
		*generatedMutationIDs, err = service.mutationIDs.NewMutationIDs()
		if err != nil {
			return Result{}, fmt.Errorf("generate registration mutation IDs: %w", err)
		}
		if !generatedMutationIDs.IsValid() {
			return Result{}, ErrInvalidMutationIDs
		}
	}
	change, err := NewChange(ChangeParams{
		Registration: registration,
		Profile:      profile,
		Credential:   credential,
		Identity:     command.Identity,
		OwnerID:      credential.IssuerID(),
		CustodianID:  credential.IssuerID(),
		NodeID:       nodeID,
		Hostname:     command.Hostname,
		Disposition:  disposition,
		MutationIDs:  *generatedMutationIDs,
		OccurredAt:   now,
	})
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
	profile := resolution.Profile()
	if !credential.IsValid() || !profile.IsValid() || profile.Scope() != command.Scope ||
		profile.ID() != registration.ProfileID() || credential.ProfileID() != profile.ID() {
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
