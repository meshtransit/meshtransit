//go:build integration

package integration

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	postgresmapsession "meshtransit.net/core/internal/adapter/postgres/mapsession"
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
	loaded, derivedCount, unchangedCount := 0, 0, 0
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
		assertSecondSharedLoadMatches(ctx, t, shared, identity, index, want)
		declinesBefore := shared.InventoryStats().SharingDeclines
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
			// A snapshot derived from the latest view needs no rebuild at
			// reconcile while the Network stays as it is.
			unchanged, err := shared.Unchanged(ctx, derived, 0)
			if err != nil {
				t.Fatalf("identity %d: Unchanged() error = %v", index, err)
			}
			if unchanged {
				unchangedCount++
			}
		} else if !want.HasDirectProjections() && shared.InventoryStats().SharingDeclines == declinesBefore {
			// Only a Network that takes part in a Device share sends a
			// Device without projections of its own to its own read.
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
	if stats.Unchanged != uint64(unchangedCount) || (derivedCount > 0 && unchangedCount == 0) {
		t.Fatalf("unchanged counter %d, %d of %d derived snapshots unchanged", stats.Unchanged, unchangedCount,
			derivedCount)
	}
	if loaded > 0 && (stats.Shared != uint64(2*loaded) || stats.Reads == 0) {
		t.Fatalf("shared inventory never used: %+v", stats)
	}
	// Each read that expanded the Network policy (or read it for a shadow
	// check) is one that skipped the share readers; its policy was compared
	// with the direct read above.
	if stats.PoliciesExpanded+stats.PolicyShadowChecks > stats.SharesSkipped {
		t.Fatalf("policies expanded for a Device whose shares were read: %+v", stats)
	}
}

// sharedPoliciesExpanded counts, across the migration test, the second
// shared loads that expanded the Network policy and matched the direct read.
var sharedPoliciesExpanded atomic.Uint64

// assertSecondSharedLoadMatches loads identity through the shared store
// again, now that its Network's inventory is cached: a Device in no share
// then skips the share readers and expands the Network policy instead of
// reading its own (or reads it for a shadow check), and the snapshot must
// still equal the direct read.
func assertSecondSharedLoadMatches(
	ctx context.Context,
	t *testing.T,
	shared *postgresmapsession.Store,
	identity control.AuthenticatedNode,
	index int,
	want mapsession.Snapshot,
) {
	t.Helper()
	before := shared.InventoryStats()
	got, err := shared.Load(ctx, identity)
	if err != nil {
		t.Fatalf("identity %d: second shared Load() error = %v", index, err)
	}
	after := shared.InventoryStats()
	if !got.PacketPolicy().Equal(want.PacketPolicy()) ||
		!reflect.DeepEqual(got.PeerCandidates(), want.PeerCandidates()) ||
		!reflect.DeepEqual(got.AuthorizedPeers(), want.AuthorizedPeers()) ||
		!reflect.DeepEqual(got.InboundPacketRules(), want.InboundPacketRules()) {
		t.Fatalf("identity %d: second shared snapshot (policy expanded %t) differs from direct read",
			index, after.PoliciesExpanded > before.PoliciesExpanded)
	}
	sharedPoliciesExpanded.Add(after.PoliciesExpanded - before.PoliciesExpanded)
	skipped := after.SharesSkipped - before.SharesSkipped
	policies := (after.PoliciesExpanded - before.PoliciesExpanded) + (after.PolicyShadowChecks - before.PolicyShadowChecks)
	if skipped != policies {
		t.Fatalf("identity %d: %d reads skipped the share readers but %d expanded or shadow-checked the policy",
			index, skipped, policies)
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
