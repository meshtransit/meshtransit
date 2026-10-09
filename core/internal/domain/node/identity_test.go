package node_test

import (
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/node"
)

func TestParseID(t *testing.T) {
	t.Parallel()

	const value = "01890f00-0000-7000-8000-000000000301"
	id, err := node.ParseID(value)
	if err != nil {
		t.Fatalf("ParseID() error = %v", err)
	}
	if id.String() != value || !id.IsValid() {
		t.Fatalf("ParseID() = %q, want valid %q", id.String(), value)
	}
}

func TestParseIDRejectsInvalidValue(t *testing.T) {
	t.Parallel()

	if _, err := node.ParseID("invalid"); !errors.Is(err, node.ErrInvalidID) {
		t.Fatalf("ParseID() error = %v, want ErrInvalidID", err)
	}
	if (node.ID{}).IsValid() {
		t.Fatal("zero ID is valid")
	}
}

func TestRegistrationIdentity(t *testing.T) {
	t.Parallel()

	machineKey := mustMachineKey(t, 1)
	nodeKey := mustNodeKey(t, 2)
	identity, err := node.NewRegistrationIdentity(machineKey, nodeKey)
	if err != nil {
		t.Fatalf("NewRegistrationIdentity() error = %v", err)
	}
	if identity.MachineKey() != machineKey || identity.NodeKey() != nodeKey || !identity.IsValid() {
		t.Fatal("NewRegistrationIdentity() did not preserve the key binding")
	}
	if identity.MachineKey().Fingerprint() == identity.NodeKey().Fingerprint() {
		t.Fatal("machine and Node key fingerprints are not domain separated")
	}
}

func TestRegistrationIdentityRejectsMissingKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		machineKey node.MachineKey
		nodeKey    node.Key
	}{
		{name: "missing machine key", nodeKey: mustNodeKey(t, 2)},
		{name: "missing node key", machineKey: mustMachineKey(t, 1)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := node.NewRegistrationIdentity(test.machineKey, test.nodeKey)
			if !errors.Is(err, node.ErrInvalidRegistrationIdentity) {
				t.Fatalf("NewRegistrationIdentity() error = %v, want ErrInvalidRegistrationIdentity", err)
			}
		})
	}
	if (node.RegistrationIdentity{}).IsValid() {
		t.Fatal("zero RegistrationIdentity is valid")
	}
}

func mustMachineKey(t *testing.T, seed byte) node.MachineKey {
	t.Helper()

	value := [32]byte{}
	value[len(value)-1] = seed
	key, err := node.NewMachineKey(value)
	if err != nil {
		t.Fatalf("NewMachineKey() error = %v", err)
	}
	return key
}

func mustNodeKey(t *testing.T, seed byte) node.Key {
	t.Helper()

	value := [32]byte{}
	value[len(value)-1] = seed
	key, err := node.NewKey(value)
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}
	return key
}
