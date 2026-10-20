//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/devicelifecycle"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

// assertPostgreSQLExitOffers qualifies schema 203: a node stores whether it
// offers to be an exit node only for the active Device whose current keys it
// holds; an unchanged offer writes nothing; a Device that is no exit node
// moves no map, while an exit node's change advances the Network and route
// revisions with device.exit_offer_changed, and decides whether it may serve.
func assertPostgreSQLExitOffers(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewExitOfferStore(runtimePool, postgresadapter.AccountSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	device, machineKey, nodeKey := activeFixtureDeviceKeys(ctx, t, admin)
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := machine.BindNodeKey(nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	revisions := func() (int64, int64) {
		networkRevision, _ := fixtureNetworkRevisions(ctx, t, admin)
		return networkRevision, fixtureRouteRevision(ctx, t, admin)
	}
	audits := func() int64 {
		var count int64
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE action = 'device.exit_offer_changed'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}

	networkBefore, routeBefore := revisions()
	if changed, err := store.ReportExitOffer(ctx, identity, false); err != nil || changed {
		t.Fatalf("withdrawing an offer never made changed %t, error %v", changed, err)
	}
	if changed, err := store.ReportExitOffer(ctx, identity, true); err != nil || !changed || audits() != 1 {
		t.Fatalf("first offer changed %t, error %v, audits %d", changed, err, audits())
	}
	if changed, err := store.ReportExitOffer(ctx, identity, true); err != nil || changed || audits() != 1 {
		t.Fatalf("the same offer changed %t, error %v", changed, err)
	}
	if networkAfter, routeAfter := revisions(); networkAfter != networkBefore || routeAfter != routeBefore {
		t.Fatal("the offer of a Device that is no exit node moved maps")
	}
	var otherKey node.Key
	copy(otherKey[:], nodeKey[:])
	otherKey[0] ^= 0xff
	if other, err := machine.BindNodeKey(otherKey); err != nil {
		t.Fatal(err)
	} else if _, err := store.ReportExitOffer(ctx, other, false); !errors.Is(err, postgresadapter.ErrRouteOfferNotFound) {
		t.Fatalf("an offer with another node key: %v", err)
	}

	// Make the Device an exit node: its offer now decides whether it serves.
	pools := newIntegrationExitPoolService(t, runtimePool)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	networkID, err := network.ParseID(guardrailFixtureNetwork)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	if row := readIntegrationDevice(ctx, t, admin, device); row.ownership != "workspace" {
		if _, err := newIntegrationDeviceLifecycle(t, runtimePool).Change(ctx, owner, devicelifecycle.Request{
			Scope: scope, DeviceID: device, Action: devicelifecycle.ActionTransferWorkspace, Reason: "Exit node",
			ExpectedVersion: row.version, CorrelationID: newCorrelationID(t)}); err != nil {
			t.Fatalf("transfer the exit node to the Workspace: %v", err)
		}
	}
	created, err := pools.Create(ctx, owner, scope, exitpool.Definition{Name: "Offer pool",
		ConntrackPerConsumer: exitpool.DefaultConntrackPerConsumer}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	withNode, err := pools.PutNode(ctx, owner, scope, created.Pool.ID, 1, exitpool.NodeAssignment{DeviceID: device,
		Priority: 1, State: exitpool.NodeActive}, newCorrelationID(t))
	if err != nil || !withNode.Pool.Nodes[0].Eligible {
		t.Fatalf("an offering exit node = %+v, error = %v", withNode, err)
	}
	networkBefore, routeBefore = revisions()
	if changed, err := store.ReportExitOffer(ctx, identity, false); err != nil || !changed {
		t.Fatalf("withdrawing the offer changed %t, error %v", changed, err)
	}
	if networkAfter, routeAfter := revisions(); networkAfter != networkBefore+1 || routeAfter != routeBefore+1 {
		t.Fatal("an exit node's withdrawn offer did not advance the Network and route revisions")
	}
	var wakes bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mesh_ops.outbox_event AS outbox
WHERE outbox.event_class = 'network.revision.advanced' AND outbox.payload->>'device_id' = $1::TEXT)`,
		device.String()).Scan(&wakes); err != nil || !wakes {
		t.Fatalf("an exit node's offer change did not wake maps: %v", err)
	}
	if reading, err := pools.Read(ctx, owner, scope, created.Pool.ID); err != nil || reading.Pool.Nodes[0].Eligible {
		t.Fatalf("an exit node without offer = %+v, error = %v", reading, err)
	}
	if _, err := pools.Delete(ctx, owner, scope, created.Pool.ID, 2, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the offer pool: %v", err)
	}
	if err := fixtureRouteOffer(ctx, admin, `DELETE FROM mesh.device_exit_offer`); err != nil {
		t.Fatal(err)
	}
}
