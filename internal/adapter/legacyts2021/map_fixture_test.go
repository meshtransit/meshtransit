package legacyts2021

import (
	"net/netip"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const mapRequestBody = `{
  "Version":142,
  "Compress":"zstd",
  "KeepAlive":true,
  "NodeKey":"nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  "Stream":false,
  "OmitPeers":false,
  "Hostinfo":{"Hostname":"node-one.example"}
}`

func mapSnapshotFixture(t *testing.T) mapsession.Snapshot {
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
	hostname, err := node.ParseHostname("node-one.example")
	if err != nil {
		t.Fatalf("node.ParseHostname() error = %v", err)
	}
	machineKey, err := node.NewMachineKey([32]byte{1})
	if err != nil {
		t.Fatalf("node.NewMachineKey() error = %v", err)
	}
	var rawNodeKey [32]byte
	for index := range rawNodeKey {
		rawNodeKey[index] = byte(index + 1)
	}
	nodeKey, err := node.NewKey(rawNodeKey)
	if err != nil {
		t.Fatalf("node.NewKey() error = %v", err)
	}
	createdAt := time.Date(2026, time.September, 14, 3, 0, 0, 0, time.UTC)
	snapshot, err := mapsession.NewSnapshot(mapsession.SnapshotParams{
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
		t.Fatalf("mapsession.NewSnapshot() error = %v", err)
	}
	return snapshot
}
