package control_test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/node"
)

func TestAuthenticatedMachineBindsRegistrationIdentity(t *testing.T) {
	t.Parallel()

	machineKey := registrationMachineKey(t, 0x11)
	nodeKey := registrationNodeKey(t, 0x22)
	params := validRegistrationRequestParams(t)
	params.NodeKey = nodeKey
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatalf("NewAuthenticatedMachine() error = %v", err)
	}
	request, err := control.NewRegistrationRequest(params)
	if err != nil {
		t.Fatalf("NewRegistrationRequest() error = %v", err)
	}

	bound, err := machine.BindRegistration(request)
	if err != nil {
		t.Fatalf("AuthenticatedMachine.BindRegistration() error = %v", err)
	}
	if !bound.IsValid() || bound.Identity.MachineKey() != machineKey ||
		bound.Identity.NodeKey() != nodeKey {
		t.Fatal("BindRegistration() did not preserve the authenticated machine and requested Node key")
	}
	if bound.RegistrationID != params.RegistrationID ||
		bound.CredentialID != params.Credential.CredentialID() ||
		bound.Token != params.Credential.Token() || bound.Hostname != params.Hostname {
		t.Fatal("BindRegistration() changed validated registration semantics")
	}
}

func TestRegistrationRequestShapeCannotCarryScopeAuthority(t *testing.T) {
	t.Parallel()

	typeOfParams := reflect.TypeFor[control.RegistrationRequestParams]()
	wantFields := []string{"RegistrationID", "Credential", "NodeKey", "Hostname"}
	if typeOfParams.NumField() != len(wantFields) {
		t.Fatalf("RegistrationRequestParams has %d fields, want %d", typeOfParams.NumField(), len(wantFields))
	}
	for index, want := range wantFields {
		if got := typeOfParams.Field(index).Name; got != want {
			t.Fatalf("RegistrationRequestParams field %d = %q, want %q", index, got, want)
		}
	}
}

func TestRegistrationBindingRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	valid := validRegistrationRequestParams(t)
	tests := []struct {
		name   string
		mutate func(*control.RegistrationRequestParams)
	}{
		{name: "missing registration id", mutate: func(params *control.RegistrationRequestParams) {
			params.RegistrationID = enrollment.RegistrationID{}
		}},
		{name: "missing credential", mutate: func(params *control.RegistrationRequestParams) {
			params.Credential = enrollment.CredentialPresentation{}
		}},
		{name: "missing node key", mutate: func(params *control.RegistrationRequestParams) {
			params.NodeKey = node.Key{}
		}},
		{name: "missing hostname", mutate: func(params *control.RegistrationRequestParams) {
			params.Hostname = node.Hostname{}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			params := valid
			test.mutate(&params)
			if _, err := control.NewRegistrationRequest(params); !errors.Is(
				err,
				control.ErrInvalidRegistrationRequest,
			) {
				t.Fatalf("NewRegistrationRequest() error = %v, want invalid request", err)
			}
		})
	}

	if _, err := control.NewAuthenticatedMachine(node.MachineKey{}); !errors.Is(
		err,
		control.ErrInvalidAuthenticatedMachine,
	) {
		t.Fatalf("NewAuthenticatedMachine() error = %v, want invalid machine", err)
	}
	validRequest, err := control.NewRegistrationRequest(valid)
	if err != nil {
		t.Fatalf("NewRegistrationRequest(valid) error = %v", err)
	}
	if _, err := (control.AuthenticatedMachine{}).BindRegistration(validRequest); !errors.Is(
		err,
		control.ErrInvalidRegistrationRequest,
	) {
		t.Fatalf("zero AuthenticatedMachine.BindRegistration() error = %v, want invalid request", err)
	}
	machine, err := control.NewAuthenticatedMachine(registrationMachineKey(t, 0x11))
	if err != nil {
		t.Fatalf("NewAuthenticatedMachine(valid) error = %v", err)
	}
	if _, err := machine.BindRegistration(control.RegistrationRequest{}); !errors.Is(
		err,
		control.ErrInvalidRegistrationRequest,
	) {
		t.Fatalf("BindRegistration(zero request) error = %v, want invalid request", err)
	}
}

func TestRegistrationTrustBoundaryFormattingIsRedacted(t *testing.T) {
	t.Parallel()

	params := validRegistrationRequestParams(t)
	machine, err := control.NewAuthenticatedMachine(registrationMachineKey(t, 0x11))
	if err != nil {
		t.Fatalf("NewAuthenticatedMachine() error = %v", err)
	}
	request, err := control.NewRegistrationRequest(params)
	if err != nil {
		t.Fatalf("NewRegistrationRequest() error = %v", err)
	}
	if fmt.Sprint(machine) != "[REDACTED]" ||
		fmt.Sprintf("%#v", machine) != "control.AuthenticatedMachine([REDACTED])" ||
		fmt.Sprint(params) != "[REDACTED]" ||
		fmt.Sprintf("%#v", params) != "control.RegistrationRequestParams([REDACTED])" ||
		fmt.Sprint(request) != "[REDACTED]" ||
		fmt.Sprintf("%#v", request) != "control.RegistrationRequest([REDACTED])" {
		t.Fatal("registration trust boundary formatting disclosed identity or bearer proof")
	}
}

func validRegistrationRequestParams(t *testing.T) control.RegistrationRequestParams {
	t.Helper()

	registrationID, err := enrollment.ParseRegistrationID("01890f80-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("ParseRegistrationID() error = %v", err)
	}
	credentialID, err := enrollment.ParseCredentialID("01890f80-0000-7000-8000-000000000002")
	if err != nil {
		t.Fatalf("ParseCredentialID() error = %v", err)
	}
	var tokenBytes [32]byte
	for index := range tokenBytes {
		tokenBytes[index] = byte(index + 1)
	}
	token, err := enrollment.NewCredentialToken(tokenBytes)
	if err != nil {
		t.Fatalf("NewCredentialToken() error = %v", err)
	}
	credential, err := enrollment.NewCredentialPresentation(credentialID, token)
	if err != nil {
		t.Fatalf("NewCredentialPresentation() error = %v", err)
	}
	hostname, err := node.ParseHostname("node-one.example")
	if err != nil {
		t.Fatalf("ParseHostname() error = %v", err)
	}
	return control.RegistrationRequestParams{
		RegistrationID: registrationID,
		Credential:     credential,
		NodeKey:        registrationNodeKey(t, 0x22),
		Hostname:       hostname,
	}
}

func registrationMachineKey(t *testing.T, seed byte) node.MachineKey {
	t.Helper()

	value := [32]byte{0: seed}
	key, err := node.NewMachineKey(value)
	if err != nil {
		t.Fatalf("NewMachineKey() error = %v", err)
	}
	return key
}

func registrationNodeKey(t *testing.T, seed byte) node.Key {
	t.Helper()

	value := [32]byte{0: seed}
	key, err := node.NewKey(value)
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}
	return key
}
