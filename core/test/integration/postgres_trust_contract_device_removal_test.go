//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/domain/sharing/contractexpiry"
)

const leavingShareLabel = "leaving-db"

// shareLeavingDevice shares the Resource of the Device that the inactive
// Device scenario suspends, resumes and then revokes, so the share outlives
// a suspension and ends with the revocation (schema 178).
func shareLeavingDevice(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	session accountsession.Session,
	providerScope network.Scope,
	resourceID resource.ID,
) labeledShare {
	t.Helper()
	consumerScope := resourceAuthorityScope(t, 103, 204)
	reason, err := sharing.NewAuditReason("share the leaving Device with the consumer Network")
	if err != nil {
		t.Fatal(err)
	}
	importedName, err := resource.ParseDisplayName("Leaving shared Device")
	if err != nil {
		t.Fatal(err)
	}
	return createShareWithLabel(ctx, t, newIntegrationResourceSharingStore(t, runtimePool), session,
		providerScope, consumerScope, resourceID, integrationSharingTraffic(t), reason, importedName,
		leavingShareLabel, integrationDatabaseNow(ctx, t, admin).Add(time.Hour), 200)
}

// assertNoDeviceRemovalQueued checks a suspended or active provider Device
// leaves its share open and unqueued: suspension can be undone.
func assertNoDeviceRemovalQueued(ctx context.Context, t *testing.T, admin *pgx.Conn, share labeledShare) {
	t.Helper()
	var queued int
	var state string
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh_ops.trust_contract_device_removal AS removal
     WHERE removal.contract_public_id = contract.public_id),
    contract.state
FROM mesh.trust_contract AS contract WHERE contract.public_id = $1::UUID`,
		share.contract.ID().String()).Scan(&queued, &state); err != nil {
		t.Fatalf("read the leaving Device share: %v", err)
	}
	if queued != 0 || state != "active" {
		t.Fatalf("share of a suspended Device: queued %d, state %s; want open and unqueued", queued, state)
	}
}

// assertDeviceRemovalEndsShare qualifies schema 178: revoking the provider
// Device queues its open share; the worker ends it as invalidated on both
// sides with system evidence, releases the access name and alias, advances
// both Networks once and is idempotent.
func assertDeviceRemovalEndsShare(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	workerPool *postgresadapter.Pool,
	share labeledShare,
) {
	t.Helper()
	contract := share.contract.ID()
	removal, err := postgresadapter.NewTrustContractDeviceRemovalStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	installation := contractInstallation(ctx, t, admin, contract)
	if !listsDeviceRemoval(ctx, t, removal, installation, contract) {
		t.Fatal("share of a revoked provider Device was not queued")
	}
	before := shareRevisions(ctx, t, admin, contract)
	changed, err := removal.End(ctx, installation, contract)
	if err != nil || !changed {
		t.Fatalf("End() = %v, %v", changed, err)
	}
	assertInvalidatedShareRows(ctx, t, admin, share.contract)
	after := shareRevisions(ctx, t, admin, contract)
	for index := range before {
		if after[index] != before[index]+1 {
			t.Fatalf("revisions before %v after %v, want each advanced once", before, after)
		}
	}
	assertDeviceRemovalEvidence(ctx, t, admin, contract)

	changed, err = removal.End(ctx, installation, contract)
	if err != nil || changed {
		t.Fatalf("repeated End() = %v, %v, want unchanged", changed, err)
	}
	if listsDeviceRemoval(ctx, t, removal, installation, contract) {
		t.Fatal("ended share is still queued")
	}
	if got := shareRevisions(ctx, t, admin, contract); got != after {
		t.Fatalf("repeated end advanced revisions %v -> %v", after, got)
	}
	assertImportedResourceAccessName(ctx, t, admin, share.contract.ImportedResourceID(), share.accessName, "withdrawn", 2)
	assertDeviceRemovalEntryPointsAreWorkerOnly(ctx, t, admin, installation, contract)
}

func listsDeviceRemoval(
	ctx context.Context,
	t *testing.T,
	removal *postgresadapter.TrustContractDeviceRemovalStore,
	installation deployment.ID,
	contract sharing.ContractID,
) bool {
	t.Helper()
	cursor := contractexpiry.Cursor{}
	for range 64 {
		page, err := removal.List(ctx, installation, cursor, 128)
		if err != nil {
			t.Fatalf("List() error = %v", err)
		}
		for _, candidate := range page.Items {
			if candidate.ContractID == contract {
				return true
			}
		}
		if page.Done {
			return false
		}
		cursor = page.Next
	}
	t.Fatal("device removal discovery did not finish")
	return false
}

func assertInvalidatedShareRows(ctx context.Context, t *testing.T, admin *pgx.Conn, contract sharing.Contract) {
	t.Helper()
	var contractState, importState, endpointState, leaseState string
	var contractVersion int64
	var endedBeforeExpiry, endedMatchesUpdate bool
	if err := admin.QueryRow(ctx, `SELECT contract.state, contract.version,
    contract.ended_at < contract.expires_at, contract.ended_at = contract.updated_at,
    imported.state, endpoint.state, lease.state
FROM mesh.trust_contract AS contract
JOIN mesh.imported_resource AS imported ON imported.trust_contract_id = contract.id
JOIN mesh.private_endpoint AS endpoint ON endpoint.trust_contract_id = contract.id
JOIN mesh.federation_alias_lease AS lease ON lease.id = endpoint.alias_lease_id
WHERE contract.public_id = $1::UUID`, contract.ID().String()).Scan(
		&contractState, &contractVersion, &endedBeforeExpiry, &endedMatchesUpdate,
		&importState, &endpointState, &leaseState,
	); err != nil {
		t.Fatalf("read ended share rows: %v", err)
	}
	if contractState != "invalidated" || contractVersion != contract.Version()+1 || !endedBeforeExpiry ||
		!endedMatchesUpdate || importState != "invalidated" || endpointState != "invalidated" || leaseState != "withdrawn" {
		t.Fatalf("ended share rows = contract %s v%d ended %t/%t, import %s, endpoint %s, lease %s",
			contractState, contractVersion, endedBeforeExpiry, endedMatchesUpdate, importState, endpointState, leaseState)
	}
}

func assertDeviceRemovalEvidence(ctx context.Context, t *testing.T, admin *pgx.Conn, contract sharing.ContractID) {
	t.Helper()
	var changes, events, systemActors, reasons, sides, outbox, mutations int
	if err := admin.QueryRow(ctx, `WITH ended AS (
    SELECT identity.change_public_id, event.actor_principal_public_id, event.payload
    FROM mesh_audit.audit_event AS event
    JOIN mesh_audit.audit_event_identity AS identity
      ON identity.id = event.event_identity_id AND identity.occurred_at = event.occurred_at
    WHERE event.action = 'trust_contract.invalidated' AND event.target_public_id = $1::UUID
)
SELECT
    (SELECT pg_catalog.count(DISTINCT change_public_id) FROM ended),
    (SELECT pg_catalog.count(*) FROM ended),
    (SELECT pg_catalog.count(*) FROM ended WHERE actor_principal_public_id IS NULL),
    (SELECT pg_catalog.count(*) FROM ended WHERE payload ->> 'reason' = 'provider_device_removed'),
    (SELECT pg_catalog.count(DISTINCT payload ->> 'authority_side') FROM ended),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event AS outbox
     WHERE outbox.change_public_id IN (SELECT change_public_id FROM ended)
       AND outbox.event_class = 'network.revision.advanced'),
    (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation AS mutation
     WHERE mutation.change_public_id IN (SELECT change_public_id FROM ended))`,
		contract.String()).Scan(&changes, &events, &systemActors, &reasons, &sides, &outbox, &mutations); err != nil {
		t.Fatalf("read device removal evidence: %v", err)
	}
	// Contract, Imported Resource, access name, Private Endpoint, alias lease.
	if changes != 1 || events != 2 || systemActors != 2 || reasons != 2 || sides != 2 || outbox != 2 || mutations != 5 {
		t.Fatalf("device removal evidence: changes %d, events %d, system %d, reasons %d, sides %d, outbox %d, mutations %d",
			changes, events, systemActors, reasons, sides, outbox, mutations)
	}
}

// assertDeviceRemovalEntryPointsAreWorkerOnly checks the runtime role cannot
// end a share, the worker cannot write the queue, and an ended share cannot
// be finalized again.
func assertDeviceRemovalEntryPointsAreWorkerOnly(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	installation deployment.ID,
	contract sharing.ContractID,
) {
	t.Helper()
	change := newIntegrationPublicationID(t).String()
	scope, target := installation.String(), contract.String()
	for _, testCase := range []struct {
		name, role, query, code string
		args                    []any
	}{
		{name: "runtime list", role: "mesh_runtime", code: "42501", args: []any{scope},
			query: `SELECT mesh_ops.list_trust_contract_device_removals_v1($1::UUID, NULL, NULL, 1)`},
		{name: "runtime prepare", role: "mesh_runtime", code: "42501", args: []any{scope, target, change},
			query: `SELECT mesh_ops.prepare_trust_contract_device_removal_v1($1::UUID, $2::UUID, $3::UUID)`},
		{name: "worker removal check", role: "mesh_worker", code: "42501",
			query: `SELECT mesh_ops.trust_contract_provider_device_removed_internal_v1(1)`},
		{name: "worker queue write", role: "mesh_worker", code: "42501", args: []any{target},
			query: `INSERT INTO mesh_ops.trust_contract_device_removal
    (contract_id, contract_public_id, deployment_id, requested_at)
VALUES (1, $1::UUID, 1, pg_catalog.clock_timestamp()) RETURNING contract_id`},
		// An ended contract has left the queue: finalize refuses before any evidence.
		{name: "worker finalize of an ended share", role: "mesh_worker", code: "40001", args: []any{scope, target, change},
			query: `SELECT mesh_ops.finalize_trust_contract_device_removal_v1($1::UUID, $2::UUID, $3::UUID,
    '[{"stream_id":"1"},{"stream_id":"2"}]'::JSONB)`},
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
