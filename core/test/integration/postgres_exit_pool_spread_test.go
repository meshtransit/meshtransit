//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
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

// assertPostgreSQLExitPoolSpread qualifies schema 210: a pool becomes spread
// only while the deployment allows it and keeps its first salt across mode
// changes; an update without a mode keeps it; the worker lists a spread
// pool with its serving set and records a set once at its generation, only
// of exit nodes that can serve, with one system event that wakes maps; the
// pool's read carries the set and its history; going back to failover drops
// the set.
func assertPostgreSQLExitPoolSpread(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool, workerPool *postgresadapter.Pool) {
	t.Helper()
	disabled := newIntegrationExitPoolService(t, runtimePool)
	pools, err := disabled.WithSpread(true)
	if err != nil {
		t.Fatal(err)
	}
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
	first, second, outsider := devices[0], devices[1], devices[2]
	for _, device := range []node.ID{first, second} {
		if row := readIntegrationDevice(ctx, t, admin, device); row.ownership != "workspace" {
			if _, err := newIntegrationDeviceLifecycle(t, runtimePool).Change(ctx, owner, devicelifecycle.Request{
				Scope: scope, DeviceID: device, Action: devicelifecycle.ActionTransferWorkspace, Reason: "Exit node",
				ExpectedVersion: row.version, CorrelationID: newCorrelationID(t)}); err != nil {
				t.Fatalf("transfer an exit node to the Workspace: %v", err)
			}
		}
		if err := fixtureRouteOffer(ctx, admin, `INSERT INTO mesh.device_exit_offer AS offer
    (device_id, workspace_id, network_id, public_id, offered, reported_at)
SELECT id, workspace_id, network_id, public_id, TRUE, now() FROM mesh.device WHERE public_id = $1::UUID
ON CONFLICT (device_id) DO UPDATE SET offered = TRUE, reported_at = EXCLUDED.reported_at,
    version = offer.version + 1`, device.String()); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		if err := fixtureRouteOffer(ctx, admin, `DELETE FROM mesh.device_exit_offer`); err != nil {
			t.Error(err)
		}
	}()
	definition := exitpool.Definition{Name: "Spread pool", ConntrackPerConsumer: exitpool.DefaultConntrackPerConsumer}
	created, err := pools.Create(ctx, owner, scope, definition, newCorrelationID(t))
	if err != nil || created.Pool.Mode != exitpool.ModeFailover {
		t.Fatalf("create a pool without a mode = %+v, %v", created.Pool.Definition, err)
	}
	poolID, version := created.Pool.ID, created.Pool.Version
	for priority, device := range []node.ID{first, second} {
		changed, err := pools.PutNode(ctx, owner, scope, poolID, version, exitpool.NodeAssignment{DeviceID: device,
			Priority: 1, State: exitpool.NodeActive}, newCorrelationID(t))
		if err != nil || changed.Pool.Mode != exitpool.ModeFailover {
			t.Fatalf("add exit node %d: %+v, %v", priority+1, changed.Pool.Definition, err)
		}
		version = changed.Pool.Version
	}
	spread := definition
	spread.Mode = exitpool.ModeSpread
	if _, err := disabled.Update(ctx, owner, scope, poolID, version, spread, newCorrelationID(t)); !errors.Is(err,
		exitpool.ErrSpreadDisabled) {
		t.Fatalf("spread while disabled = %v", err)
	}
	salt := func() []byte {
		t.Helper()
		var value []byte
		if err := admin.QueryRow(ctx, `SELECT spread_salt FROM mesh.network_exit_pool WHERE public_id = $1::UUID`,
			poolID.String()).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if salt() != nil {
		t.Fatal("a failover pool has a salt")
	}
	updated, err := pools.Update(ctx, owner, scope, poolID, version, spread, newCorrelationID(t))
	if err != nil || updated.Pool.Mode != exitpool.ModeSpread || updated.Previous.Mode != exitpool.ModeFailover {
		t.Fatalf("become spread = %+v, %v", updated, err)
	}
	firstSalt := salt()
	if len(firstSalt) != exitpool.SpreadSaltSize {
		t.Fatalf("salt = %x", firstSalt)
	}
	renamed := spread
	renamed.Name, renamed.Mode = "Spread pool 2", exitpool.ModeKeep
	kept, err := pools.Update(ctx, owner, scope, poolID, updated.Pool.Version, renamed, newCorrelationID(t))
	if err != nil || kept.Pool.Mode != exitpool.ModeSpread || !bytes.Equal(salt(), firstSalt) {
		t.Fatalf("an update without mode = %+v, %v", kept.Pool.Definition, err)
	}
	if listing, err := pools.List(ctx, owner, scope, exitpool.ID{}, exitpool.MaximumPage); err != nil ||
		!slices.ContainsFunc(listing.Pools, func(pool exitpool.Pool) bool {
			return pool.ID == poolID && pool.Mode == exitpool.ModeSpread
		}) {
		t.Fatalf("listed modes = %+v, %v", listing.Pools, err)
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
	listed := func() primaryelection.GroupFacts {
		t.Helper()
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
		return page.Groups[index]
	}
	if facts := listed(); !facts.Spread || len(facts.Serving) != 0 || facts.ServingGeneration != 0 ||
		!facts.ServingChangedAt.IsZero() {
		t.Fatalf("listed spread pool = %+v", facts)
	}
	record := func(expected int64, devices []node.ID, reason string, want bool) {
		t.Helper()
		changed, err := store.RecordServing(ctx, installation, primaryelection.ServingDecision{Group: poolID.String(),
			ExpectedGeneration: expected, Devices: devices, Reason: reason})
		if err != nil || changed != want {
			t.Fatalf("RecordServing(%d, %v, %s) = %t, %v, want %t", expected, devices, reason, changed, err, want)
		}
	}
	networkBefore, _ := fixtureNetworkRevisions(ctx, t, admin)
	record(0, []node.ID{first, second}, primaryelection.ServingElected, true)
	record(0, []node.ID{first}, primaryelection.ServingFailover, false)         // an older generation
	record(1, []node.ID{second, first}, primaryelection.ServingJoined, false)   // the same set
	record(1, []node.ID{first, outsider}, primaryelection.ServingJoined, false) // no exit node of the pool
	if networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin); networkAfter != networkBefore+1 {
		t.Fatalf("one serving election advanced the Network from %d to %d", networkBefore, networkAfter)
	}
	record(1, []node.ID{second}, primaryelection.ServingOverloaded, true)
	if facts := listed(); !slices.Equal(facts.Serving, []node.ID{second}) || facts.ServingGeneration != 2 ||
		facts.ServingChangedAt.IsZero() {
		t.Fatalf("listed serving set = %+v", facts)
	}
	reading, err := pools.Read(ctx, owner, scope, poolID)
	if err != nil || reading.Serving == nil || !slices.Equal(reading.Serving.Devices, []node.ID{second}) ||
		reading.Serving.Generation != 2 || reading.Serving.Reason != primaryelection.ServingOverloaded {
		t.Fatalf("pool read serving = %+v, %v", reading.Serving, err)
	}
	history, err := pools.ServingChanges(ctx, owner, scope, poolID, publicid.ID{}, 10)
	if err != nil || len(history.Changes) != 2 || history.HasMore ||
		!slices.Equal(history.Changes[0].Devices, []node.ID{second}) || history.Changes[0].Generation != 2 ||
		len(history.Changes[0].Previous) != 2 || history.Changes[1].Reason != primaryelection.ServingElected ||
		len(history.Changes[1].Previous) != 0 {
		t.Fatalf("serving history = %+v, %v", history, err)
	}
	var events, systemActors int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*),
    pg_catalog.count(*) FILTER (WHERE event.actor_principal_public_id IS NULL)
FROM mesh_audit.audit_event AS event
WHERE event.action = 'exit_pool.serving_changed' AND event.target_public_id = $1::UUID`,
		poolID.String()).Scan(&events, &systemActors); err != nil {
		t.Fatal(err)
	}
	if events != 2 || systemActors != 2 {
		t.Fatalf("serving evidence: events %d, system %d", events, systemActors)
	}

	failover := renamed
	failover.Mode = exitpool.ModeFailover
	back, err := pools.Update(ctx, owner, scope, poolID, reading.Pool.Version, failover, newCorrelationID(t))
	if err != nil || back.Pool.Mode != exitpool.ModeFailover {
		t.Fatalf("back to failover = %+v, %v", back.Pool.Definition, err)
	}
	if again, err := pools.Read(ctx, owner, scope, poolID); err != nil || again.Serving != nil ||
		!bytes.Equal(salt(), firstSalt) {
		t.Fatalf("a failover pool read = %+v, %v", again.Serving, err)
	}
	// A failover pool has no serving set to record.
	record(0, []node.ID{first}, primaryelection.ServingElected, false)
	if facts := listed(); facts.Spread || len(facts.Serving) != 0 {
		t.Fatalf("listed failover pool = %+v", facts)
	}
	if _, err := pools.Delete(ctx, owner, scope, poolID, back.Pool.Version, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the spread pool: %v", err)
	}
}
