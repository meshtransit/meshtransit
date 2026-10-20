//go:build integration

package integration

import (
	"context"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/devicelifecycle"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/primaryelection"
	"meshtransit.net/core/internal/domain/publicid"
)

// assertPostgreSQLExitPoolElection qualifies schema 204: the worker store
// lists each pool with its exit nodes in priority order and whether each may
// serve (active, unexpired, owned by the Workspace and offering); it records
// each change once at its generation with one system event that wakes maps,
// and refuses a decision made on an older generation, for a Device that is
// no exit node of the pool, or for one that stopped offering since the list.
// The pool's read carries the elected primary and its history pages newest
// first.
func assertPostgreSQLExitPoolElection(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool, workerPool *postgresadapter.Pool) {
	t.Helper()
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
	devices := activeFixtureDevices(ctx, t, admin, 3)
	preferred, standby, outsider := devices[0], devices[1], devices[2]
	for _, device := range []node.ID{preferred, standby} {
		if row := readIntegrationDevice(ctx, t, admin, device); row.ownership != "workspace" {
			if _, err := newIntegrationDeviceLifecycle(t, runtimePool).Change(ctx, owner, devicelifecycle.Request{
				Scope: scope, DeviceID: device, Action: devicelifecycle.ActionTransferWorkspace, Reason: "Exit node",
				ExpectedVersion: row.version, CorrelationID: newCorrelationID(t)}); err != nil {
				t.Fatalf("transfer an exit node to the Workspace: %v", err)
			}
		}
	}
	offer := func(device node.ID, offered bool) {
		t.Helper()
		if err := fixtureRouteOffer(ctx, admin, `INSERT INTO mesh.device_exit_offer AS offer
    (device_id, workspace_id, network_id, public_id, offered, reported_at)
SELECT id, workspace_id, network_id, public_id, $2::BOOLEAN, now() FROM mesh.device WHERE public_id = $1::UUID
ON CONFLICT (device_id) DO UPDATE SET offered = EXCLUDED.offered, reported_at = EXCLUDED.reported_at,
    version = offer.version + 1`, device.String(), offered); err != nil {
			t.Fatal(err)
		}
	}
	offer(preferred, true)
	offer(standby, true)
	defer func() {
		if err := fixtureRouteOffer(ctx, admin, `DELETE FROM mesh.device_exit_offer`); err != nil {
			t.Error(err)
		}
	}()
	created, err := pools.Create(ctx, owner, scope, exitpool.Definition{Name: "Election pool",
		ConntrackPerConsumer: exitpool.DefaultConntrackPerConsumer}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	poolID := created.Pool.ID
	version := created.Pool.Version
	for priority, device := range []node.ID{preferred, standby} {
		changed, err := pools.PutNode(ctx, owner, scope, poolID, version, exitpool.NodeAssignment{DeviceID: device,
			Priority: priority + 1, State: exitpool.NodeActive}, newCorrelationID(t))
		if err != nil {
			t.Fatalf("add exit node %d: %v", priority+1, err)
		}
		version = changed.Pool.Version
	}
	if reading, err := pools.Read(ctx, owner, scope, poolID); err != nil || reading.Primary != nil {
		t.Fatalf("primary before any election = %+v, error %v", reading.Primary, err)
	}

	store, err := postgresadapter.NewExitPoolPrimaryStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	var installationText string
	if err := admin.QueryRow(ctx, `SELECT deployment.installation_public_id::TEXT
FROM mesh.network_exit_pool AS exit_pool JOIN mesh.deployment AS deployment ON deployment.id = exit_pool.deployment_id
WHERE exit_pool.public_id = $1::UUID`, poolID.String()).Scan(&installationText); err != nil {
		t.Fatal(err)
	}
	installation, err := deployment.ParseID(installationText)
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.List(ctx, installation, "", primaryelection.PageSize)
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	index := slices.IndexFunc(page.Groups, func(facts primaryelection.GroupFacts) bool {
		return facts.Group == poolID.String()
	})
	if index < 0 {
		t.Fatalf("List() lacks the pool: %+v", page)
	}
	facts := page.Groups[index]
	if facts.Generation != 0 || facts.Primary.IsValid() || facts.Failback || len(facts.Members) != 2 ||
		facts.Members[0].Device != preferred || facts.Members[1].Device != standby ||
		!facts.Members[0].Eligible || !facts.Members[1].Eligible || facts.Members[1].Draining {
		t.Fatalf("listed pool = %+v", facts)
	}
	record := func(expected int64, primary node.ID, reason string, want bool) {
		t.Helper()
		changed, err := store.Record(ctx, installation, primaryelection.Decision{Group: poolID.String(),
			ExpectedGeneration: expected, Primary: primary, Reason: reason})
		if err != nil || changed != want {
			t.Fatalf("Record(%d, %s, %s) = %t, %v, want %t", expected, primary, reason, changed, err, want)
		}
	}
	networkBefore, _ := fixtureNetworkRevisions(ctx, t, admin)
	record(0, standby, primaryelection.ReasonFailover, true)
	record(0, standby, primaryelection.ReasonFailover, false) // decided on an older generation
	record(1, standby, primaryelection.ReasonFailover, false) // already the primary
	record(1, outsider, primaryelection.ReasonElected, false) // no exit node of the pool
	if networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin); networkAfter != networkBefore+1 {
		t.Fatalf("one election advanced the Network from %d to %d", networkBefore, networkAfter)
	}
	record(1, node.ID{}, primaryelection.ReasonNone, true)
	record(2, preferred, primaryelection.ReasonElected, true)
	// prepare checks again that the exit node may serve: one that stopped
	// offering since the list is not recorded.
	offer(standby, false)
	record(3, standby, primaryelection.ReasonFailover, false)

	var events, systemActors, outbox int
	if err := admin.QueryRow(ctx, `WITH elected AS (
    SELECT identity.change_public_id, event.actor_principal_public_id
    FROM mesh_audit.audit_event AS event
    JOIN mesh_audit.audit_event_identity AS identity
      ON identity.id = event.event_identity_id AND identity.occurred_at = event.occurred_at
    WHERE event.action = 'exit_pool.primary_changed' AND event.target_public_id = $1::UUID
)
SELECT
    (SELECT pg_catalog.count(*) FROM elected),
    (SELECT pg_catalog.count(*) FROM elected WHERE actor_principal_public_id IS NULL),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event AS outbox
     WHERE outbox.change_public_id IN (SELECT change_public_id FROM elected)
       AND outbox.event_class = 'network.revision.advanced')`, poolID.String()).Scan(&events, &systemActors,
		&outbox); err != nil {
		t.Fatalf("read election evidence: %v", err)
	}
	if events != 3 || systemActors != 3 || outbox != 3 {
		t.Fatalf("election evidence: events %d, system %d, outbox %d", events, systemActors, outbox)
	}

	reading, err := pools.Read(ctx, owner, scope, poolID)
	if err != nil || reading.Primary == nil || reading.Primary.Device != preferred || reading.Primary.Generation != 3 ||
		reading.Primary.Reason != primaryelection.ReasonElected {
		t.Fatalf("pool read primary = %+v, error %v", reading.Primary, err)
	}
	first, err := pools.PrimaryChanges(ctx, owner, scope, poolID, publicid.ID{}, 2)
	if err != nil || len(first.Changes) != 2 || !first.HasMore || first.Changes[0].Device != preferred ||
		first.Changes[0].Previous.IsValid() || first.Changes[0].Generation != 3 ||
		first.Changes[1].Reason != primaryelection.ReasonNone || first.Changes[1].Previous != standby {
		t.Fatalf("first history page = %+v, error %v", first, err)
	}
	rest, err := pools.PrimaryChanges(ctx, owner, scope, poolID, first.Changes[1].EventID, 2)
	if err != nil || len(rest.Changes) != 1 || rest.HasMore || rest.Changes[0].Device != standby ||
		rest.Changes[0].Reason != primaryelection.ReasonFailover || rest.Changes[0].Generation != 1 {
		t.Fatalf("second history page = %+v, error %v", rest, err)
	}
	if _, err := pools.Delete(ctx, owner, scope, poolID, reading.Pool.Version, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the election pool: %v", err)
	}
}
