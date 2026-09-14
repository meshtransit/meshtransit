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
	// ErrRegistrationFailed classifies a bound registration preparation failure.
	ErrRegistrationFailed = errors.New("control: registration failed")
)

// RegistrationPreparer prepares a credential-authenticated durable intent.
type RegistrationPreparer interface {
	Prepare(context.Context, intake.Request) (registration.Command, error)
}

// RegistrationService binds transport identity before registration intake. It
// retains no request state and starts no goroutines.
type RegistrationService struct {
	preparer RegistrationPreparer
}

// NewRegistrationService constructs the authenticated registration boundary.
func NewRegistrationService(preparer RegistrationPreparer) (*RegistrationService, error) {
	if preparer == nil {
		return nil, ErrInvalidRegistrationService
	}
	return &RegistrationService{preparer: preparer}, nil
}

// Register binds the transport-proven machine to the request Node key before
// invoking credential authentication and durable intent preparation.
func (service *RegistrationService) Register(
	ctx context.Context,
	machine AuthenticatedMachine,
	request RegistrationRequest,
) (registration.Command, error) {
	if ctx == nil || service == nil || service.preparer == nil {
		return registration.Command{}, ErrInvalidRegistrationService
	}
	if err := ctx.Err(); err != nil {
		return registration.Command{}, errors.Join(ErrRegistrationFailed, err)
	}
	bound, err := machine.BindRegistration(request)
	if err != nil {
		return registration.Command{}, err
	}
	command, err := service.preparer.Prepare(ctx, bound)
	if err != nil {
		return registration.Command{}, fmt.Errorf("%w: prepare authenticated request: %w", ErrRegistrationFailed, err)
	}
	if !command.IsValid() {
		return registration.Command{}, ErrRegistrationFailed
	}
	return command, nil
}
