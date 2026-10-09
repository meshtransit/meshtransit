package control

import (
	"testing"

	"meshtransit.net/core/internal/domain/node"
)

func TestAuthenticatedMachineBindsNodeKey(t *testing.T) {
	machineKey, err := node.NewMachineKey([32]byte{1})
	if err != nil {
		t.Fatalf("node.NewMachineKey() error = %v", err)
	}
	nodeKey, err := node.NewKey([32]byte{2})
	if err != nil {
		t.Fatalf("node.NewKey() error = %v", err)
	}
	machine, err := NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatalf("NewAuthenticatedMachine() error = %v", err)
	}

	identity, err := machine.BindNodeKey(nodeKey)
	if err != nil {
		t.Fatalf("BindNodeKey() error = %v", err)
	}
	if !identity.IsValid() {
		t.Fatal("bound identity is invalid")
	}
	if got, want := identity.MachineFingerprint(), machineKey.Fingerprint(); got != want {
		t.Fatalf("machine fingerprint = %x, want %x", got, want)
	}
	if got := identity.NodeKey(); got != nodeKey {
		t.Fatalf("Node key = %v, want expected key", got)
	}
	if got := identity.String(); got != "[REDACTED]" {
		t.Fatalf("String() = %q, want redacted value", got)
	}
}

func TestAuthenticatedMachineRejectsInvalidNodeBinding(t *testing.T) {
	machineKey, err := node.NewMachineKey([32]byte{1})
	if err != nil {
		t.Fatalf("node.NewMachineKey() error = %v", err)
	}
	machine, err := NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatalf("NewAuthenticatedMachine() error = %v", err)
	}

	if _, err := machine.BindNodeKey(node.Key{}); err == nil {
		t.Fatal("BindNodeKey() error = nil, want invalid identity")
	}
	if _, err := (AuthenticatedMachine{}).BindNodeKey(node.Key{}); err == nil {
		t.Fatal("zero machine BindNodeKey() error = nil, want invalid identity")
	}
}
