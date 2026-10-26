package node_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/node"
)

func TestPresenceLeasePreservesValidatedSessionFence(t *testing.T) {
	t.Parallel()

	nodeID := mustPresenceNodeID(t)
	lease, err := node.NewPresenceLease(nodeID, 7, "control-a.example", 30*time.Second)
	if err != nil {
		t.Fatalf("NewPresenceLease() error = %v", err)
	}
	if !lease.IsValid() || lease.NodeID() != nodeID || lease.Generation() != 7 ||
		lease.ReplicaID() != "control-a.example" || lease.TTL() != 30*time.Second {
		t.Fatalf("NewPresenceLease() = %+v, want exact validated lease", lease)
	}
}

func TestPresenceLeaseRejectsUnsafeFields(t *testing.T) {
	t.Parallel()

	validID := mustPresenceNodeID(t)
	tests := []struct {
		name       string
		nodeID     node.ID
		generation int64
		replicaID  string
		ttl        time.Duration
	}{
		{name: "missing node", generation: 1, replicaID: "control-a", ttl: time.Second},
		{name: "zero generation", nodeID: validID, replicaID: "control-a", ttl: time.Second},
		{name: "negative generation", nodeID: validID, generation: -1, replicaID: "control-a", ttl: time.Second},
		{name: "missing replica", nodeID: validID, generation: 1, ttl: time.Second},
		{name: "spaced replica", nodeID: validID, generation: 1, replicaID: " control-a", ttl: time.Second},
		{name: "invalid replica", nodeID: validID, generation: 1, replicaID: "control/a", ttl: time.Second},
		{name: "long replica", nodeID: validID, generation: 1, replicaID: strings.Repeat("a", 129), ttl: time.Second},
		{name: "short ttl", nodeID: validID, generation: 1, replicaID: "control-a", ttl: time.Second - 1},
		{name: "long ttl", nodeID: validID, generation: 1, replicaID: "control-a", ttl: 5*time.Minute + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			lease, err := node.NewPresenceLease(
				test.nodeID,
				test.generation,
				test.replicaID,
				test.ttl,
			)
			if !errors.Is(err, node.ErrInvalidPresenceLease) || lease.IsValid() {
				t.Fatalf("NewPresenceLease() = (%+v, %v), want invalid lease", lease, err)
			}
		})
	}
}

func mustPresenceNodeID(t *testing.T) node.ID {
	t.Helper()
	var value [16]byte
	value[0] = 1
	value[6] = 0x70
	value[8] = 0x80
	id, err := node.NewID(value)
	if err != nil {
		t.Fatalf("NewID() error = %v", err)
	}
	return id
}

// A Kubernetes gateway's lease names its holder, one Serve, and the
// fingerprint of its machine key (K1a1 plan §16.12).
func TestPresenceLeaseCarriesGatewayHolder(t *testing.T) {
	t.Parallel()

	lease, err := node.NewPresenceLease(mustPresenceNodeID(t), 7, "control-a", 30*time.Second)
	if err != nil {
		t.Fatalf("NewPresenceLease() error = %v", err)
	}
	if lease.Gateway() {
		t.Fatal("a Node lease is a gateway's")
	}
	holder := node.PresenceHolder{1, 2, 3}
	machine := [32]byte{9}
	gateway, err := lease.WithGateway(holder, machine)
	if err != nil {
		t.Fatalf("WithGateway() error = %v", err)
	}
	if !gateway.IsValid() || !gateway.Gateway() || gateway.Holder() != holder ||
		gateway.MachineFingerprint() != machine || gateway.NodeID() != lease.NodeID() ||
		gateway.Generation() != 7 || gateway.ReplicaID() != "control-a" {
		t.Fatalf("WithGateway() = %+v", gateway)
	}
	for name, input := range map[string]struct {
		holder  node.PresenceHolder
		machine [32]byte
	}{
		"no holder":  {machine: machine},
		"no machine": {holder: holder},
	} {
		if got, err := lease.WithGateway(input.holder, input.machine); !errors.Is(err, node.ErrInvalidPresenceLease) ||
			got.IsValid() {
			t.Errorf("%s: WithGateway() = (%+v, %v)", name, got, err)
		}
	}
	if _, err := (node.PresenceLease{}).WithGateway(holder, machine); !errors.Is(err, node.ErrInvalidPresenceLease) {
		t.Errorf("WithGateway() on an invalid lease = %v", err)
	}
}

func TestNewPresenceHolderIsRandom(t *testing.T) {
	t.Parallel()

	first, err := node.NewPresenceHolder()
	if err != nil {
		t.Fatal(err)
	}
	second, err := node.NewPresenceHolder()
	if err != nil {
		t.Fatal(err)
	}
	if first.IsZero() || second.IsZero() || first == second {
		t.Fatalf("NewPresenceHolder() = %x, %x", first, second)
	}
	if len(first.String()) != 32 {
		t.Fatalf("String() = %q", first.String())
	}
}
