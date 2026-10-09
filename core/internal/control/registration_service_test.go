package control_test

import (
	"context"
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/control"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment/registration"
	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment/registration/intake"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/node/keyrotation"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
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
	wantResult := validRegistrationResult(t, want)
	preparer := &recordingRegistrationPreparer{command: want}
	executor := &recordingRegistrationExecutor{result: wantResult}
	service, err := control.NewRegistrationService(preparer, executor)
	if err != nil {
		t.Fatalf("NewRegistrationService() error = %v", err)
	}

	got, err := service.Register(t.Context(), machine, request)
	if err != nil {
		t.Fatalf("RegistrationService.Register() error = %v", err)
	}
	if got != wantResult || preparer.calls != 1 || executor.calls != 1 || executor.command != want ||
		preparer.request.Identity.MachineKey() != machineKey ||
		preparer.request.Identity.NodeKey() != params.NodeKey {
		t.Fatal("RegistrationService.Register() did not prepare and execute the bound identity exactly once")
	}
}

func TestRegistrationServiceFailsClosed(t *testing.T) {
	t.Parallel()

	for _, dependencies := range []struct {
		preparer control.RegistrationPreparer
		executor control.RegistrationExecutor
	}{
		{executor: &recordingRegistrationExecutor{}},
		{preparer: &recordingRegistrationPreparer{}},
	} {
		if _, err := control.NewRegistrationService(
			dependencies.preparer,
			dependencies.executor,
		); !errors.Is(err, control.ErrInvalidRegistrationService) {
			t.Fatalf("NewRegistrationService(incomplete) error = %v, want invalid service", err)
		}
	}
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

	t.Run("canceled context", func(t *testing.T) {
		t.Parallel()

		preparer := &recordingRegistrationPreparer{}
		executor := &recordingRegistrationExecutor{}
		service, serviceErr := control.NewRegistrationService(preparer, executor)
		if serviceErr != nil {
			t.Fatalf("NewRegistrationService() error = %v", serviceErr)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, registerErr := service.Register(ctx, machine, request)
		if !errors.Is(registerErr, context.Canceled) || preparer.calls != 0 || executor.calls != 0 {
			t.Fatalf("Register(canceled) = %v with prepare=%d execute=%d calls", registerErr, preparer.calls, executor.calls)
		}
	})

	t.Run("invalid binding", func(t *testing.T) {
		t.Parallel()

		preparer := &recordingRegistrationPreparer{}
		executor := &recordingRegistrationExecutor{}
		service, serviceErr := control.NewRegistrationService(preparer, executor)
		if serviceErr != nil {
			t.Fatalf("NewRegistrationService() error = %v", serviceErr)
		}
		_, registerErr := service.Register(t.Context(), control.AuthenticatedMachine{}, request)
		if !errors.Is(registerErr, control.ErrInvalidRegistrationRequest) ||
			preparer.calls != 0 || executor.calls != 0 {
			t.Fatalf("Register(invalid binding) = %v with prepare=%d execute=%d calls", registerErr, preparer.calls, executor.calls)
		}
	})

	t.Run("preparer error", func(t *testing.T) {
		t.Parallel()

		wantErr := errors.New("controlled prepare failure")
		preparer := &recordingRegistrationPreparer{err: wantErr}
		executor := &recordingRegistrationExecutor{}
		service, serviceErr := control.NewRegistrationService(preparer, executor)
		if serviceErr != nil {
			t.Fatalf("NewRegistrationService() error = %v", serviceErr)
		}
		_, registerErr := service.Register(t.Context(), machine, request)
		if !errors.Is(registerErr, control.ErrRegistrationFailed) ||
			!errors.Is(registerErr, wantErr) || preparer.calls != 1 || executor.calls != 0 {
			t.Fatalf("Register(preparer error) = %v with prepare=%d execute=%d calls", registerErr, preparer.calls, executor.calls)
		}
	})

	t.Run("invalid command", func(t *testing.T) {
		t.Parallel()

		preparer := &recordingRegistrationPreparer{}
		executor := &recordingRegistrationExecutor{}
		service, serviceErr := control.NewRegistrationService(preparer, executor)
		if serviceErr != nil {
			t.Fatalf("NewRegistrationService() error = %v", serviceErr)
		}
		_, registerErr := service.Register(t.Context(), machine, request)
		if !errors.Is(registerErr, control.ErrRegistrationFailed) ||
			preparer.calls != 1 || executor.calls != 0 {
			t.Fatalf("Register(invalid command) = %v with prepare=%d execute=%d calls", registerErr, preparer.calls, executor.calls)
		}
	})

	t.Run("executor error", func(t *testing.T) {
		t.Parallel()

		command := validRegistrationCommand(t, params, machineKey)
		wantErr := errors.New("controlled execute failure")
		preparer := &recordingRegistrationPreparer{command: command}
		executor := &recordingRegistrationExecutor{err: wantErr}
		service, serviceErr := control.NewRegistrationService(preparer, executor)
		if serviceErr != nil {
			t.Fatalf("NewRegistrationService() error = %v", serviceErr)
		}
		_, registerErr := service.Register(t.Context(), machine, request)
		if !errors.Is(registerErr, control.ErrRegistrationFailed) ||
			!errors.Is(registerErr, wantErr) || executor.calls != 1 {
			t.Fatalf("Register(executor error) = %v with execute=%d calls", registerErr, executor.calls)
		}
	})

	t.Run("invalid committed result", func(t *testing.T) {
		t.Parallel()

		command := validRegistrationCommand(t, params, machineKey)
		preparer := &recordingRegistrationPreparer{command: command}
		executor := &recordingRegistrationExecutor{}
		service, serviceErr := control.NewRegistrationService(preparer, executor)
		if serviceErr != nil {
			t.Fatalf("NewRegistrationService() error = %v", serviceErr)
		}
		_, registerErr := service.Register(t.Context(), machine, request)
		if !errors.Is(registerErr, control.ErrRegistrationFailed) || executor.calls != 1 {
			t.Fatalf("Register(invalid result) = %v with execute=%d calls", registerErr, executor.calls)
		}
	})

	t.Run("unrelated committed result", func(t *testing.T) {
		t.Parallel()

		command := validRegistrationCommand(t, params, machineKey)
		otherCommand := command
		otherID, parseErr := enrollment.ParseRegistrationID("01890f80-0000-7000-8000-000000000006")
		if parseErr != nil {
			t.Fatalf("enrollment.ParseRegistrationID() error = %v", parseErr)
		}
		otherCommand.RegistrationID = otherID
		preparer := &recordingRegistrationPreparer{command: command}
		executor := &recordingRegistrationExecutor{result: validRegistrationResult(t, otherCommand)}
		service, serviceErr := control.NewRegistrationService(preparer, executor)
		if serviceErr != nil {
			t.Fatalf("NewRegistrationService() error = %v", serviceErr)
		}
		_, registerErr := service.Register(t.Context(), machine, request)
		if !errors.Is(registerErr, control.ErrRegistrationFailed) || executor.calls != 1 {
			t.Fatalf("Register(unrelated result) = %v with execute=%d calls", registerErr, executor.calls)
		}
	})
}

func TestRegistrationServiceRoutesAuthenticatedNodeKeyRotation(t *testing.T) {
	t.Parallel()

	params := validRegistrationRequestParams(t)
	params.Credential = enrollment.CredentialPresentation{}
	params.OldNodeKey = registrationNodeKey(t, 0x21)
	request, err := control.NewRegistrationRequest(params)
	if err != nil {
		t.Fatalf("NewRegistrationRequest() error = %v", err)
	}
	machineKey := registrationMachineKey(t, 0x11)
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatalf("NewAuthenticatedMachine() error = %v", err)
	}
	command, err := keyrotation.NewCommand(keyrotation.CommandParams{
		OperationID: params.RegistrationID,
		MachineKey:  machineKey,
		OldNodeKey:  params.OldNodeKey,
		NewNodeKey:  params.NodeKey,
	})
	if err != nil {
		t.Fatalf("keyrotation.NewCommand() error = %v", err)
	}
	want := validNodeKeyRotationResult(t, command, params.Hostname)
	rotator := &recordingNodeKeyRotator{result: want}
	preparer := &recordingRegistrationPreparer{}
	executor := &recordingRegistrationExecutor{}
	service, err := control.NewRegistrationServiceWithNodeKeyRotation(
		preparer,
		executor,
		rotator,
	)
	if err != nil {
		t.Fatalf("NewRegistrationServiceWithNodeKeyRotation() error = %v", err)
	}

	result, err := service.Register(t.Context(), machine, request)
	if err != nil {
		t.Fatalf("RegistrationService.Register(rotation) error = %v", err)
	}
	if rotator.calls != 1 || rotator.command != command || preparer.calls != 0 || executor.calls != 0 ||
		result.Disposition() != registration.DispositionRotated ||
		result.NodeID() != want.NodeID() || result.NetworkRevision() != want.NetworkRevision() {
		t.Fatal("RegistrationService.Register(rotation) did not route exact authenticated transition")
	}
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

type recordingRegistrationExecutor struct {
	command registration.Command
	result  registration.Result
	err     error
	calls   int
}

type recordingNodeKeyRotator struct {
	command keyrotation.Command
	result  keyrotation.Result
	err     error
	calls   int
}

func (rotator *recordingNodeKeyRotator) Rotate(
	_ context.Context,
	command keyrotation.Command,
) (keyrotation.Result, error) {
	rotator.command = command
	rotator.calls++
	return rotator.result, rotator.err
}

func (executor *recordingRegistrationExecutor) Register(
	_ context.Context,
	command registration.Command,
) (registration.Result, error) {
	executor.command = command
	executor.calls++
	return executor.result, executor.err
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

func validRegistrationResult(
	t *testing.T,
	command registration.Command,
) registration.Result {
	t.Helper()

	nodeID, err := node.ParseID("01890f80-0000-7000-8000-000000000005")
	if err != nil {
		t.Fatalf("node.ParseID() error = %v", err)
	}
	result, err := registration.NewResult(
		command.RegistrationID,
		command.Scope,
		nodeID,
		command.Hostname,
		registration.DispositionCreated,
		1,
	)
	if err != nil {
		t.Fatalf("registration.NewResult() error = %v", err)
	}
	return result
}

func validNodeKeyRotationResult(
	t *testing.T,
	command keyrotation.Command,
	hostname node.Hostname,
) keyrotation.Result {
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
	nodeID, err := node.ParseID("01890f80-0000-7000-8000-000000000005")
	if err != nil {
		t.Fatalf("node.ParseID() error = %v", err)
	}
	result, err := keyrotation.NewResult(keyrotation.ResultParams{
		OperationID:       command.OperationID(),
		Scope:             scope,
		NodeID:            nodeID,
		Hostname:          hostname,
		DeviceVersion:     2,
		NodeKeyEpoch:      2,
		SessionGeneration: 2,
		NetworkRevision:   2,
		InventoryRevision: 2,
	})
	if err != nil {
		t.Fatalf("keyrotation.NewResult() error = %v", err)
	}
	return result
}
