//go:build integration

package integration

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
)

// assertSharedInventoryMatchesDirectRead loads each identity's snapshot
// through a shared-inventory store and through the direct candidate read
// and requires identical authority (scale-out design S1: the derived
// snapshot must equal the reference read for every fixture).
func assertSharedInventoryMatchesDirectRead(
	ctx context.Context,
	t *testing.T,
	pool *postgresadapter.Pool,
	direct mapsession.SnapshotStore,
	identities ...control.AuthenticatedNode,
) {
	t.Helper()
	shared, err := postgresadapter.NewMapSessionStore(pool, postgresadapter.MapSessionOptions{
		StatementTimeout:          5 * time.Second,
		IdleTimeout:               5 * time.Second,
		PeerCandidateLimit:        mapsession.MaximumPeerCandidates,
		PolicyRuleLimit:           mapsession.MaximumPacketPolicyRules,
		RelayDirectory:            integrationRelayDirectory(t),
		SharedInventory:           true,
		InventoryStatementTimeout: 30 * time.Second,
		InventoryMaxAge:           30 * time.Second,
	})
	if err != nil {
		t.Fatalf("shared NewMapSessionStore() error = %v", err)
	}
	loaded, derivedCount := 0, 0
	for index, identity := range identities {
		want, wantErr := direct.Load(ctx, identity)
		got, gotErr := shared.Load(ctx, identity)
		if (wantErr == nil) != (gotErr == nil) ||
			errors.Is(wantErr, mapsession.ErrUnauthorized) != errors.Is(gotErr, mapsession.ErrUnauthorized) ||
			errors.Is(wantErr, mapsession.ErrSuspended) != errors.Is(gotErr, mapsession.ErrSuspended) {
			t.Fatalf("identity %d: shared error %v, direct error %v", index, gotErr, wantErr)
		}
		if wantErr != nil {
			continue
		}
		loaded++
		if got.NodeID() != want.NodeID() || got.Scope() != want.Scope() ||
			got.NetworkRevision() != want.NetworkRevision() || got.SessionGeneration() != want.SessionGeneration() ||
			!got.KeyExpiry().Equal(want.KeyExpiry()) || !got.PacketPolicy().Equal(want.PacketPolicy()) ||
			!reflect.DeepEqual(got.Addresses(), want.Addresses()) {
			t.Fatalf("identity %d: shared self %+v differs from direct %+v", index, got, want)
		}
		if !reflect.DeepEqual(got.PeerCandidates(), want.PeerCandidates()) {
			t.Fatalf("identity %d: shared candidates %+v differ from direct %+v", index, got.PeerCandidates(), want.PeerCandidates())
		}
		if !reflect.DeepEqual(got.AuthorizedPeers(), want.AuthorizedPeers()) {
			t.Fatalf("identity %d: shared peers %+v differ from direct %+v", index, got.AuthorizedPeers(), want.AuthorizedPeers())
		}
		if derived, found, err := shared.Derive(ctx, got, 0); err != nil {
			t.Fatalf("identity %d: Derive() error = %v", index, err)
		} else if found {
			derivedCount++
			if derived.NodeID() != want.NodeID() || derived.NetworkRevision() != want.NetworkRevision() ||
				derived.RecoveryEpoch() != want.RecoveryEpoch() || derived.NetworkName() != want.NetworkName() ||
				derived.Hostname() != want.Hostname() || derived.SessionGeneration() != want.SessionGeneration() ||
				!derived.CreatedAt().Equal(want.CreatedAt()) || !derived.KeyExpiry().Equal(want.KeyExpiry()) ||
				!derived.PacketPolicy().Equal(want.PacketPolicy()) || !reflect.DeepEqual(derived.Addresses(), want.Addresses()) ||
				!reflect.DeepEqual(derived.PeerCandidates(), want.PeerCandidates()) ||
				!reflect.DeepEqual(derived.AuthorizedPeers(), want.AuthorizedPeers()) {
				t.Fatalf("identity %d: derived snapshot %+v differs from direct %+v", index, derived, want)
			}
		} else if !want.HasDirectProjections() {
			t.Fatalf("identity %d: Derive() declined a Device without direct projections", index)
		}
		gotDNS, gotDNSErr := got.SharedDNSRecords()
		wantDNS, wantDNSErr := want.SharedDNSRecords()
		if !reflect.DeepEqual(got.InboundPacketRules(), want.InboundPacketRules()) ||
			!reflect.DeepEqual(got.SharingScopes(), want.SharingScopes()) ||
			!got.ProjectionExpiry().Equal(want.ProjectionExpiry()) ||
			!reflect.DeepEqual(gotDNS, wantDNS) || (gotDNSErr == nil) != (wantDNSErr == nil) {
			t.Fatalf("identity %d: shared direct projections differ from direct read", index)
		}
	}
	stats := shared.InventoryStats()
	if stats.PolicyMismatches != 0 {
		t.Fatalf("Network policy expansion disagreed with the per-Device policy read: %+v", stats)
	}
	if stats.Derived != uint64(derivedCount) {
		t.Fatalf("derived counter %d, compared %d", stats.Derived, derivedCount)
	}
	if loaded > 0 && (stats.Shared != uint64(loaded) || stats.Reads == 0) {
		t.Fatalf("shared inventory never used: %+v", stats)
	}
}

// assertNetworkMapsMatchDirectRead runs the shared-inventory comparison for
// every active Device of one Network, building each identity from the keys
// PostgreSQL holds.
func assertNetworkMapsMatchDirectRead(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	pool *postgresadapter.Pool,
	networkPublicID string,
) {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT machine.public_key, node_key.public_key
FROM mesh.device AS device
JOIN mesh.network AS network ON network.workspace_id = device.workspace_id AND network.id = device.network_id
JOIN mesh.device_machine_key_epoch AS machine
  ON machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch AND machine.state = 'active'
JOIN mesh.device_node_key_epoch AS node_key
  ON node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch AND node_key.state = 'active'
WHERE network.public_id = $1::UUID AND device.state = 'active' AND device.deleted_at IS NULL
ORDER BY device.id`, networkPublicID)
	if err != nil {
		t.Fatalf("read Network identities: %v", err)
	}
	var identities []control.AuthenticatedNode
	for rows.Next() {
		var machineKey, nodeKey []byte
		if err := rows.Scan(&machineKey, &nodeKey); err != nil {
			rows.Close()
			t.Fatalf("scan Network identity: %v", err)
		}
		identities = append(identities, identityFromKeys(t, machineKey, nodeKey))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate Network identities: %v", err)
	}
	if len(identities) == 0 {
		t.Fatal("no active Devices to compare")
	}
	direct, err := postgresadapter.NewMapSessionStore(pool, postgresadapter.MapSessionOptions{
		StatementTimeout:   5 * time.Second,
		IdleTimeout:        5 * time.Second,
		PeerCandidateLimit: mapsession.MaximumPeerCandidates,
		PolicyRuleLimit:    mapsession.MaximumPacketPolicyRules,
		RelayDirectory:     integrationRelayDirectory(t),
	})
	if err != nil {
		t.Fatalf("direct NewMapSessionStore() error = %v", err)
	}
	assertSharedInventoryMatchesDirectRead(ctx, t, pool, direct, identities...)
}

func identityFromKeys(t *testing.T, machineValue, nodeValue []byte) control.AuthenticatedNode {
	t.Helper()
	if len(machineValue) != 32 || len(nodeValue) != 32 {
		t.Fatal("malformed key epoch")
	}
	machineKey, err := node.NewMachineKey([32]byte(machineValue))
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := node.NewKey([32]byte(nodeValue))
	if err != nil {
		t.Fatal(err)
	}
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := machine.BindNodeKey(nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	return identity
}
