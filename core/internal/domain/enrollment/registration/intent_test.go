package registration_test

import (
	"encoding/hex"
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/enrollment"
	registration "meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/workspace"
)

func TestCommandRequestHashBindsSemanticInputs(t *testing.T) {
	t.Parallel()

	command := mustCommand(t)
	want, err := command.RequestHash()
	if err != nil {
		t.Fatalf("Command.RequestHash() error = %v", err)
	}
	if !want.IsValid() || want.Bytes() == ([32]byte{}) {
		t.Fatal("Command.RequestHash() returned invalid hash")
	}
	wantBytes := want.Bytes()
	if got := hex.EncodeToString(wantBytes[:]); got != "c31b4872e2dcd997c32a3c126e6175566f9f02189fc7dd207437ede3fc48ed31" {
		t.Fatalf("Command.RequestHash() = %q, want stable protocol vector", got)
	}

	differentID := command
	differentID.RegistrationID = mustRegistrationID(t, "01890f20-0000-7000-8000-000000000099")
	if got, err := differentID.RequestHash(); err != nil || got != want {
		t.Fatalf("Registration ID changed semantic hash: hash=%x error=%v", got.Bytes(), err)
	}

	tests := []struct {
		name   string
		mutate func(*registration.Command)
	}{
		{
			name: "scope",
			mutate: func(command *registration.Command) {
				workspaceID, parseErr := workspace.ParseID("01890f20-0000-7000-8000-000000000014")
				if parseErr != nil {
					t.Fatalf("workspace.ParseID() error = %v", parseErr)
				}
				networkID, parseErr := network.ParseID("01890f20-0000-7000-8000-000000000015")
				if parseErr != nil {
					t.Fatalf("network.ParseID() error = %v", parseErr)
				}
				command.Scope, parseErr = network.NewScope(workspaceID, networkID)
				if parseErr != nil {
					t.Fatalf("network.NewScope() error = %v", parseErr)
				}
			},
		},
		{
			name: "credential",
			mutate: func(command *registration.Command) {
				command.CredentialID = mustCredentialID(t, "01890f20-0000-7000-8000-000000000016")
			},
		},
		{
			name: "machine key",
			mutate: func(command *registration.Command) {
				machineKey, keyErr := node.NewMachineKey(filled32(0x44))
				if keyErr != nil {
					t.Fatalf("node.NewMachineKey() error = %v", keyErr)
				}
				command.Identity, keyErr = node.NewRegistrationIdentity(machineKey, command.Identity.NodeKey())
				if keyErr != nil {
					t.Fatalf("node.NewRegistrationIdentity() error = %v", keyErr)
				}
			},
		},
		{
			name: "node key",
			mutate: func(command *registration.Command) {
				nodeKey, keyErr := node.NewKey(filled32(0x45))
				if keyErr != nil {
					t.Fatalf("node.NewKey() error = %v", keyErr)
				}
				command.Identity, keyErr = node.NewRegistrationIdentity(command.Identity.MachineKey(), nodeKey)
				if keyErr != nil {
					t.Fatalf("node.NewRegistrationIdentity() error = %v", keyErr)
				}
			},
		},
		{name: "recovery epoch", mutate: func(command *registration.Command) { command.RecoveryEpoch++ }},
		{
			name: "hostname",
			mutate: func(command *registration.Command) {
				hostname, parseErr := node.ParseHostname("node-two.example")
				if parseErr != nil {
					t.Fatalf("node.ParseHostname() error = %v", parseErr)
				}
				command.Hostname = hostname
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			changed := command
			test.mutate(&changed)
			got, hashErr := changed.RequestHash()
			if hashErr != nil {
				t.Fatalf("Command.RequestHash() error = %v", hashErr)
			}
			if got == want {
				t.Fatal("semantic input change did not change request hash")
			}
		})
	}
}

func TestRequestHashRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	if _, err := registration.NewRequestHash([32]byte{}); !errors.Is(err, registration.ErrInvalidRequestHash) {
		t.Fatalf("NewRequestHash(zero) error = %v, want ErrInvalidRequestHash", err)
	}
	if (registration.RequestHash{}).IsValid() {
		t.Fatal("zero RequestHash is valid")
	}
	command := mustCommand(t)
	command.CredentialID = enrollment.CredentialID{}
	if _, err := command.RequestHash(); !errors.Is(err, registration.ErrInvalidCommand) {
		t.Fatalf("Command.RequestHash(invalid) error = %v, want ErrInvalidCommand", err)
	}
}
