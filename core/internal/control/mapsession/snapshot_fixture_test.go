package mapsession

import (
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/relay"
	"meshtransit.net/core/internal/domain/workspace"
)

func snapshotFixture(t testing.TB) Snapshot {
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
	networkName, err := network.ParseDisplayName("Development Mesh")
	if err != nil {
		t.Fatalf("network.ParseDisplayName() error = %v", err)
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
	packetPolicy, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    scope,
		Revision: 5,
		Rules:    nil,
	})
	if err != nil {
		t.Fatalf("policy.NewSnapshot() error = %v", err)
	}
	snapshot, err := NewSnapshot(SnapshotParams{
		Scope:             scope,
		NetworkName:       networkName,
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
		PacketPolicy:      packetPolicy,
		RelayDirectory:    relayDirectoryFixture(t),
	})
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	return snapshot
}

func relayDirectoryFixture(t testing.TB) relay.Directory {
	t.Helper()
	node, err := relay.NewNode(relay.NodeParams{
		Name:      "1a",
		HostName:  "relay-sin.example.com",
		IPv4:      "192.0.2.10",
		IPv6:      "2001:db8::10",
		STUNPort:  3478,
		RelayPort: 443,
	})
	if err != nil {
		t.Fatalf("relay.NewNode() error = %v", err)
	}
	region, err := relay.NewRegion(relay.RegionParams{
		ID: 1, Code: "sin", Name: "Singapore", Nodes: []relay.Node{node},
	})
	if err != nil {
		t.Fatalf("relay.NewRegion() error = %v", err)
	}
	directory, err := relay.NewDirectory(relay.DirectoryParams{
		Revision: 1,
		Regions:  []relay.Region{region},
	})
	if err != nil {
		t.Fatalf("relay.NewDirectory() error = %v", err)
	}
	return directory
}
