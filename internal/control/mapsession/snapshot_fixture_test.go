package mapsession

import (
	"net/netip"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func snapshotFixture(t *testing.T) Snapshot {
	t.Helper()
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	nodeID, err := node.ParseID("01890f00-0000-7000-8000-000000000701")
	if err != nil {
		t.Fatalf("node.ParseID() error = %v", err)
	}
	hostname, err := node.ParseHostname("node-1.example")
	if err != nil {
		t.Fatalf("node.ParseHostname() error = %v", err)
	}
	machineKey, err := node.NewMachineKey([32]byte{1})
	if err != nil {
		t.Fatalf("node.NewMachineKey() error = %v", err)
	}
	nodeKey, err := node.NewKey([32]byte{2})
	if err != nil {
		t.Fatalf("node.NewKey() error = %v", err)
	}
	createdAt := time.Date(2026, time.September, 14, 3, 0, 0, 0, time.UTC)
	snapshot, err := NewSnapshot(SnapshotParams{
		Scope:             scope,
		NetworkRevision:   7,
		RecoveryEpoch:     2,
		SessionGeneration: 3,
		NumericNodeID:     701,
		NumericOwnerID:    11,
		NodeID:            nodeID,
		Hostname:          hostname,
		MachineKey:        machineKey,
		NodeKey:           nodeKey,
		Addresses:         []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		CreatedAt:         createdAt,
		KeyExpiry:         createdAt.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	return snapshot
}
