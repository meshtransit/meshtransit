//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/resource"
	authority "meshtransit.net/core/internal/domain/resource/authority"
	"meshtransit.net/core/internal/domain/resource/retirement"
)

// resourceRetirementInstallation is the installation of the fixture
// Workspace the retirement worker serves.
func resourceRetirementInstallation(ctx context.Context, t *testing.T, admin *pgx.Conn, id resource.ID) deployment.ID {
	t.Helper()
	var text string
	if err := admin.QueryRow(ctx, `SELECT deployment.installation_public_id::TEXT
FROM mesh.resource AS resource JOIN mesh.deployment AS deployment ON deployment.id = resource.deployment_id
WHERE resource.public_id = $1::UUID`, id.String()).Scan(&text); err != nil {
		t.Fatalf("read the Resource installation: %v", err)
	}
	installation, err := deployment.ParseID(text)
	if err != nil {
		t.Fatal(err)
	}
	return installation
}

func listsResourceRetirement(ctx context.Context, t *testing.T, store *postgresadapter.ResourceRetirementStore,
	installation deployment.ID, id resource.ID,
) bool {
	t.Helper()
	cursor := retirement.Cursor{}
	for range 64 {
		page, err := store.List(ctx, installation, cursor, 128)
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		for _, candidate := range page.Items {
			if candidate.ResourceID == id {
				return true
			}
		}
		if page.Done {
			return false
		}
		cursor = page.Next
	}
	t.Fatal("Resource retirement discovery did not finish")
	return false
}

func resourceRetirementState(ctx context.Context, t *testing.T, admin *pgx.Conn, id resource.ID) (string, string) {
	t.Helper()
	var resourceState, targetState string
	if err := admin.QueryRow(ctx, `SELECT resource.state, target.state
FROM mesh.resource AS resource
JOIN mesh.resource_device_target AS target
  ON target.workspace_id = resource.workspace_id AND target.network_id = resource.network_id
 AND target.resource_id = resource.id AND target.target_generation = resource.target_generation
WHERE resource.public_id = $1::UUID`, id.String()).Scan(&resourceState, &targetState); err != nil {
		t.Fatalf("read Resource %s: %v", id, err)
	}
	return resourceState, targetState
}

// assertResourceRetirementDeferred qualifies schema 185 for a Resource of a
// revoked Device that is still in use: it is queued, and the worker leaves
// it and its queue row as they are.
func assertResourceRetirementDeferred(ctx context.Context, t *testing.T, admin *pgx.Conn,
	workerPool *postgresadapter.Pool, id resource.ID, why string,
) {
	t.Helper()
	store, err := postgresadapter.NewResourceRetirementStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	installation := resourceRetirementInstallation(ctx, t, admin, id)
	if !resourceRetirementQueued(ctx, t, admin, id) {
		t.Fatalf("%s: the Resource of a revoked Device was not queued", why)
	}
	retired, err := store.Retire(ctx, installation, id)
	if err != nil || retired {
		t.Fatalf("%s: Retire() = %v, %v, want deferred", why, retired, err)
	}
	if resourceState, targetState := resourceRetirementState(ctx, t, admin, id); resourceState != "active" ||
		targetState != "active" || !resourceRetirementQueued(ctx, t, admin, id) {
		t.Fatalf("%s: deferred Resource is %s/%s or left the queue", why, resourceState, targetState)
	}
	// It waits before discovery offers it again.
	if listsResourceRetirement(ctx, t, store, installation, id) {
		t.Fatalf("%s: a Resource in use is offered again at once", why)
	}
}

func resourceRetirementQueued(ctx context.Context, t *testing.T, admin *pgx.Conn, id resource.ID) bool {
	t.Helper()
	var queued bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (
    SELECT 1 FROM mesh_ops.resource_device_removal WHERE resource_public_id = $1::UUID)`,
		id.String()).Scan(&queued); err != nil {
		t.Fatalf("read the retirement queue: %v", err)
	}
	return queued
}

// assertResourceRetired qualifies schema 185 once the Resource is no longer
// in use: the worker deletes it, supersedes its target so its name and
// Device are free, advances the Network once with one system event, and is
// idempotent; only the worker role can call it.
func assertResourceRetired(ctx context.Context, t *testing.T, admin *pgx.Conn,
	workerPool *postgresadapter.Pool, id resource.ID,
) {
	t.Helper()
	store, err := postgresadapter.NewResourceRetirementStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	installation := resourceRetirementInstallation(ctx, t, admin, id)
	beforeNetwork, beforeInventory := resourceRetirementRevisions(ctx, t, admin, id)
	retired, err := store.Retire(ctx, installation, id)
	if err != nil || !retired {
		t.Fatalf("Retire() = %v, %v", retired, err)
	}
	if resourceState, targetState := resourceRetirementState(ctx, t, admin, id); resourceState != "deleted" ||
		targetState != "superseded" {
		t.Fatalf("retired Resource is %s/%s, want deleted/superseded", resourceState, targetState)
	}
	afterNetwork, afterInventory := resourceRetirementRevisions(ctx, t, admin, id)
	if afterNetwork != beforeNetwork+1 || afterInventory != beforeInventory+1 {
		t.Fatalf("revisions %d/%d -> %d/%d, want each advanced once",
			beforeNetwork, beforeInventory, afterNetwork, afterInventory)
	}
	var events, systemActors, outbox, sameName int
	if err := admin.QueryRow(ctx, `WITH retired AS (
    SELECT identity.change_public_id, event.actor_principal_public_id, event.payload
    FROM mesh_audit.audit_event AS event
    JOIN mesh_audit.audit_event_identity AS identity
      ON identity.id = event.event_identity_id AND identity.occurred_at = event.occurred_at
    WHERE event.action = 'resource.retired' AND event.target_public_id = $1::UUID
)
SELECT
    (SELECT pg_catalog.count(*) FROM retired WHERE payload ->> 'reason' = 'device_removed'),
    (SELECT pg_catalog.count(*) FROM retired WHERE actor_principal_public_id IS NULL),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event AS outbox
     WHERE outbox.change_public_id IN (SELECT change_public_id FROM retired)
       AND outbox.event_class = 'network.revision.advanced'),
    (SELECT pg_catalog.count(*) FROM mesh.resource AS current
     JOIN mesh.resource AS retired_resource
       ON retired_resource.workspace_id = current.workspace_id AND retired_resource.network_id = current.network_id
      AND retired_resource.name_key = current.name_key
     WHERE retired_resource.public_id = $1::UUID AND current.state <> 'deleted')`,
		id.String()).Scan(&events, &systemActors, &outbox, &sameName); err != nil {
		t.Fatalf("read Resource retirement evidence: %v", err)
	}
	if events != 1 || systemActors != 1 || outbox != 1 || sameName != 0 {
		t.Fatalf("retirement evidence: events %d, system %d, outbox %d, current Resources with the name %d",
			events, systemActors, outbox, sameName)
	}
	retired, err = store.Retire(ctx, installation, id)
	if err != nil || retired {
		t.Fatalf("repeated Retire() = %v, %v, want unchanged", retired, err)
	}
	if resourceRetirementQueued(ctx, t, admin, id) {
		t.Fatal("retired Resource is still queued")
	}
	if network, inventory := resourceRetirementRevisions(ctx, t, admin, id); network != afterNetwork || inventory != afterInventory {
		t.Fatal("repeated retirement advanced the Network")
	}
	assertResourceRetirementWorkerOnly(ctx, t, admin, installation, id)
}

func resourceRetirementRevisions(ctx context.Context, t *testing.T, admin *pgx.Conn, id resource.ID) (int64, int64) {
	t.Helper()
	var networkRevision, inventoryRevision int64
	if err := admin.QueryRow(ctx, `SELECT revision.network_revision, revision.inventory_revision
FROM mesh.resource AS resource
JOIN mesh_ops.network_revision AS revision
  ON revision.workspace_id = resource.workspace_id AND revision.network_id = resource.network_id
WHERE resource.public_id = $1::UUID`, id.String()).Scan(&networkRevision, &inventoryRevision); err != nil {
		t.Fatalf("read Resource Network revisions: %v", err)
	}
	return networkRevision, inventoryRevision
}

// assertResourceRetirementWorkerOnly checks the runtime role cannot list or
// retire, the worker cannot write the queue, and a retired Resource cannot be
// finalized again.
func assertResourceRetirementWorkerOnly(ctx context.Context, t *testing.T, admin *pgx.Conn,
	installation deployment.ID, id resource.ID,
) {
	t.Helper()
	change := newIntegrationPublicationID(t).String()
	scope, target := installation.String(), id.String()
	for _, testCase := range []struct {
		name, role, query, code string
		args                    []any
	}{
		{name: "runtime list", role: "mesh_runtime", code: "42501", args: []any{scope},
			query: `SELECT mesh_ops.list_resource_device_removals_v1($1::UUID, NULL, NULL, 1)`},
		{name: "runtime prepare", role: "mesh_runtime", code: "42501", args: []any{scope, target, change},
			query: `SELECT mesh_ops.prepare_resource_device_removal_v1($1::UUID, $2::UUID, $3::UUID)`},
		{name: "worker in-use check", role: "mesh_worker", code: "42501",
			query: `SELECT mesh_ops.resource_retirement_blocked_internal_v1(1)`},
		{name: "worker queue write", role: "mesh_worker", code: "42501", args: []any{target},
			query: `INSERT INTO mesh_ops.resource_device_removal
    (resource_id, resource_public_id, deployment_id, workspace_id, network_id, requested_at, next_attempt_at)
VALUES (1, $1::UUID, 1, 1, 1, pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp())
RETURNING resource_id`},
		// Not prepared in this transaction: finalize refuses before any evidence.
		{name: "worker finalize without prepare", role: "mesh_worker", code: "23514", args: []any{scope, target, change},
			query: `SELECT mesh_ops.finalize_resource_device_removal_v1($1::UUID, $2::UUID, $3::UUID, '{}'::JSONB)`},
	} {
		transaction, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.Exec(ctx, `SET LOCAL ROLE `+testCase.role); err != nil {
			t.Fatal(err)
		}
		var ignored any
		err = transaction.QueryRow(ctx, testCase.query, testCase.args...).Scan(&ignored)
		if rollbackErr := transaction.Rollback(ctx); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if err == nil {
			t.Fatalf("%s succeeded", testCase.name)
		}
		assertPostgreSQLCode(t, err, testCase.code)
	}
}

// deleteInactiveDeviceResourceGroups deletes the Resource Groups that hold
// the revoked Device's Resource, so nothing uses it any more.
func deleteInactiveDeviceResourceGroups(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, owner accountsession.Session, scope network.Scope, groups ...resource.GroupID,
) {
	t.Helper()
	service := newIntegrationResourceLifecycleService(t, runtimePool)
	for index, group := range groups {
		var version int64
		if err := admin.QueryRow(ctx, `SELECT version FROM mesh.resource_group WHERE public_id = $1::UUID`,
			group.String()).Scan(&version); err != nil {
			t.Fatalf("read Resource Group version: %v", err)
		}
		command, err := authority.NewGroupLifecycleCommand(authority.LifecycleDeleteGroup, scope, group, version,
			owner, resourceAuthorityReason(t, "the Device of its member left"), resourceAuthorityProof(t, byte(185+index)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.Transition(ctx, command); err != nil {
			t.Fatalf("delete Resource Group: %v", err)
		}
	}
}
