package control

import (
	"context"
	"errors"
	"fmt"

	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration/intake"
)

var (
	// ErrInvalidRegistrationService reports a missing application dependency.
	ErrInvalidRegistrationService = errors.New("control: invalid registration service")
	// ErrRegistrationFailed classifies a bound registration that did not commit.
	ErrRegistrationFailed = errors.New("control: registration failed")
)

// RegistrationPreparer prepares a credential-authenticated durable intent.
type RegistrationPreparer interface {
	Prepare(context.Context, intake.Request) (registration.Command, error)
}

// RegistrationExecutor commits one prepared registration command.
type RegistrationExecutor interface {
	Register(context.Context, registration.Command) (registration.Result, error)
}

// RegistrationService binds transport identity, prepares durable intent, and
// executes the authoritative registration mutation. It retains no request
// state and starts no goroutines.
type RegistrationService struct {
	preparer RegistrationPreparer
	executor RegistrationExecutor
}

// NewRegistrationService constructs the authenticated registration boundary.
func NewRegistrationService(
	preparer RegistrationPreparer,
	executor RegistrationExecutor,
) (*RegistrationService, error) {
	if preparer == nil || executor == nil {
		return nil, ErrInvalidRegistrationService
	}
	return &RegistrationService{preparer: preparer, executor: executor}, nil
}

// Register binds the transport-proven machine to the request Node key before
// preparing durable intent and committing the authoritative mutation. Success
// always represents a validated committed result for the prepared command.
func (service *RegistrationService) Register(
	ctx context.Context,
	machine AuthenticatedMachine,
	request RegistrationRequest,
) (registration.Result, error) {
	if ctx == nil || service == nil || service.preparer == nil || service.executor == nil {
		return registration.Result{}, ErrInvalidRegistrationService
	}
	if err := ctx.Err(); err != nil {
		return registration.Result{}, errors.Join(ErrRegistrationFailed, err)
	}
	bound, err := machine.BindRegistration(request)
	if err != nil {
		return registration.Result{}, err
	}
	command, err := service.preparer.Prepare(ctx, bound)
	if err != nil {
		return registration.Result{}, fmt.Errorf("%w: prepare authenticated request: %w", ErrRegistrationFailed, err)
	}
	if !command.IsValid() {
		return registration.Result{}, ErrRegistrationFailed
	}
	result, err := service.executor.Register(ctx, command)
	if err != nil {
		return registration.Result{}, fmt.Errorf("%w: execute prepared registration: %w", ErrRegistrationFailed, err)
	}
	if !result.IsValid() || result.RegistrationID() != command.RegistrationID ||
		result.Scope() != command.Scope {
		return registration.Result{}, ErrRegistrationFailed
	}
	return result, nil
}
