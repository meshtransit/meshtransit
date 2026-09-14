package control_test

import (
	"context"
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration/intake"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestRegistrationServiceBindsBeforePreparing(t *testing.T) {
	t.Parallel()

	params := validRegistrationRequestParams(t)
	machineKey := registrationMachineKey(t, 0x11)
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatalf("NewAuthenticatedMachine() error = %v", err)
	}
	request, err := control.NewRegistrationRequest(params)
	if err != nil {
		t.Fatalf("NewRegistrationRequest() error = %v", err)
	}
	want := validRegistrationCommand(t, params, machineKey)
	preparer := &recordingRegistrationPreparer{command: want}
	service, err := control.NewRegistrationService(preparer)
	if err != nil {
		t.Fatalf("NewRegistrationService() error = %v", err)
	}

	got, err := service.Register(t.Context(), machine, request)
	if err != nil {
		t.Fatalf("RegistrationService.Register() error = %v", err)
	}
	if got != want || preparer.calls != 1 || preparer.request.Identity.MachineKey() != machineKey ||
		preparer.request.Identity.NodeKey() != params.NodeKey {
		t.Fatal("RegistrationService.Register() did not bind the authenticated identity exactly once")
	}
}

func TestRegistrationServiceFailsClosed(t *testing.T) {
	t.Parallel()

	if _, err := control.NewRegistrationService(nil); !errors.Is(
		err,
		control.ErrInvalidRegistrationService,
	) {
		t.Fatalf("NewRegistrationService(nil) error = %v, want invalid service", err)
	}
	params := validRegistrationRequestParams(t)
	machine, err := control.NewAuthenticatedMachine(registrationMachineKey(t, 0x11))
	if err != nil {
		t.Fatalf("NewAuthenticatedMachine() error = %v", err)
	}
	request, err := control.NewRegistrationRequest(params)
	if err != nil {
		t.Fatalf("NewRegistrationRequest() error = %v", err)
	}

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()

		preparer := &recordingRegistrationPreparer{}
		service, serviceErr := control.NewRegistrationService(preparer)
		if serviceErr != nil {
			t.Fatalf("NewRegistrationService() error = %v", serviceErr)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, registerErr := service.Register(ctx, machine, request)
		if !errors.Is(registerErr, context.Canceled) || preparer.calls != 0 {
			t.Fatalf("Register(canceled) = %v with %d calls, want cancellation before prepare", registerErr, preparer.calls)
		}
	})

	t.Run("invalid binding", func(t *testing.T) {
		t.Parallel()

		preparer := &recordingRegistrationPreparer{}
		service, serviceErr := control.NewRegistrationService(preparer)
		if serviceErr != nil {
			t.Fatalf("NewRegistrationService() error = %v", serviceErr)
		}
		_, registerErr := service.Register(t.Context(), control.AuthenticatedMachine{}, request)
		if !errors.Is(registerErr, control.ErrInvalidRegistrationRequest) || preparer.calls != 0 {
			t.Fatalf("Register(invalid binding) = %v with %d calls", registerErr, preparer.calls)
		}
	})

	t.Run("preparer error", func(t *testing.T) {
		t.Parallel()

		wantErr := errors.New("controlled prepare failure")
		preparer := &recordingRegistrationPreparer{err: wantErr}
		service, serviceErr := control.NewRegistrationService(preparer)
		if serviceErr != nil {
			t.Fatalf("NewRegistrationService() error = %v", serviceErr)
		}
		_, registerErr := service.Register(t.Context(), machine, request)
		if !errors.Is(registerErr, control.ErrRegistrationFailed) ||
			!errors.Is(registerErr, wantErr) || preparer.calls != 1 {
			t.Fatalf("Register(preparer error) = %v with %d calls", registerErr, preparer.calls)
		}
	})

	t.Run("invalid command", func(t *testing.T) {
		t.Parallel()

		preparer := &recordingRegistrationPreparer{}
		service, serviceErr := control.NewRegistrationService(preparer)
		if serviceErr != nil {
			t.Fatalf("NewRegistrationService() error = %v", serviceErr)
		}
		_, registerErr := service.Register(t.Context(), machine, request)
		if !errors.Is(registerErr, control.ErrRegistrationFailed) || preparer.calls != 1 {
			t.Fatalf("Register(invalid command) = %v with %d calls", registerErr, preparer.calls)
		}
	})
}

type recordingRegistrationPreparer struct {
	request intake.Request
	command registration.Command
	err     error
	calls   int
}

func (preparer *recordingRegistrationPreparer) Prepare(
	_ context.Context,
	request intake.Request,
) (registration.Command, error) {
	preparer.request = request
	preparer.calls++
	return preparer.command, preparer.err
}

func validRegistrationCommand(
	t *testing.T,
	params control.RegistrationRequestParams,
	machineKey node.MachineKey,
) registration.Command {
	t.Helper()

	workspaceID, err := workspace.ParseID("01890f80-0000-7000-8000-000000000003")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID("01890f80-0000-7000-8000-000000000004")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	identity, err := node.NewRegistrationIdentity(machineKey, params.NodeKey)
	if err != nil {
		t.Fatalf("node.NewRegistrationIdentity() error = %v", err)
	}
	return registration.Command{
		RegistrationID: params.RegistrationID,
		Scope:          scope,
		CredentialID:   params.Credential.CredentialID(),
		Identity:       identity,
		Hostname:       params.Hostname,
		RecoveryEpoch:  1,
	}
}
