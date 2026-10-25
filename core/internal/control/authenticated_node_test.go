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

// A node key is proven only when the transport proved that exact key in the
// session; binding another key, or none, is unproven.
func TestBindNodeKeyCarriesTheSessionProof(t *testing.T) {
	t.Parallel()
	machineKey := node.MachineKey{1}
	proven, other := node.Key{2}, node.Key{3}
	machine, err := NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatal(err)
	}
	if identity, _ := machine.BindNodeKey(proven); identity.Proven() {
		t.Fatal("a key is proven without a session proof")
	}
	withProof := machine.WithProvenNodeKey(proven)
	if key, ok := withProof.ProvenNodeKey(); !ok || key != proven {
		t.Fatalf("ProvenNodeKey() = %v, %t", key, ok)
	}
	if identity, _ := withProof.BindNodeKey(proven); !identity.Proven() {
		t.Fatal("the proven key is not proven")
	}
	if identity, _ := withProof.BindNodeKey(other); identity.Proven() {
		t.Fatal("another key inherited the proof")
	}
	if _, ok := machine.WithProvenNodeKey(node.Key{}).ProvenNodeKey(); ok {
		t.Fatal("a zero key is proven")
	}
	if _, ok := machine.ProvenNodeKey(); ok {
		t.Fatal("WithProvenNodeKey changed the original machine")
	}
}
