//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph/ledger"
	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

// assertPostgreSQLAccessEdgeLedger qualifies schema 134: revisions keep their
// time, the worker records a baseline once and then only changes, every
// recorded change is sealed on the Network stream with its digest, retention
// keeps recent rows, and the history read answers at an instant under
// policy.read and device.read.
func assertPostgreSQLAccessEdgeLedger(ctx context.Context, t *testing.T,
	admin *pgx.Conn, workerPool, runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	var installationText string
	if err := admin.QueryRow(ctx, `SELECT installation_public_id::TEXT FROM mesh.deployment WHERE id = 1`).
		Scan(&installationText); err != nil {
		t.Fatal(err)
	}
	installation, err := deployment.ParseID(installationText)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000103")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000203")
	scope, _ := network.NewScope(workspaceID, networkID)
	var internalNetwork int64
	if err := admin.QueryRow(ctx, `SELECT id FROM mesh.network WHERE public_id = $1::UUID`, networkID.String()).
		Scan(&internalNetwork); err != nil {
		t.Fatal(err)
	}
	var backfilled bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mesh_ops.network_revision_history AS history
JOIN mesh_ops.network_revision AS revision USING (workspace_id, network_id, network_revision)
WHERE history.workspace_id = 103 AND history.network_id = $1)`, internalNetwork).Scan(&backfilled); err != nil || !backfilled {
		t.Fatal("current revision was not backfilled", err)
	}

	store, err := postgresadapter.NewAccessLedgerStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	due, err := store.ListDue(ctx, installation, 64)
	if err != nil || !containsScope(due, scope) {
		t.Fatalf("unrecorded Network is not due: %v %v", due, err)
	}
	if outcome, err := store.Record(ctx, installation, scope); err != nil || outcome != ledger.OutcomeRecorded {
		t.Fatalf("baseline record = %v %v", outcome, err)
	}
	if outcome, err := store.Record(ctx, installation, scope); err != nil || outcome != ledger.OutcomeUnchanged {
		t.Fatalf("current ledger record = %v %v", outcome, err)
	}
	assertAccessLedgerSealed(ctx, t, admin, internalNetwork, 1)

	// A revision that leaves the edge set alone advances the cursor only.
	bumpIntegrationNetworkRevision(ctx, t, admin, internalNetwork)
	if outcome, err := store.Record(ctx, installation, scope); err != nil || outcome != ledger.OutcomeUnchanged {
		t.Fatalf("unchanged revision record = %v %v", outcome, err)
	}
	assertAccessLedgerSealed(ctx, t, admin, internalNetwork, 1)

	// An edge that is no longer in effect closes at the next revision.
	staleFrom := time.Now().UTC().Add(-time.Hour)
	if _, err := admin.Exec(ctx, `INSERT INTO mesh_ops.access_edge_history (
    workspace_id, network_id, edge_key, access_rule_public_id, selector_kind, source_device_public_id,
    destination_device_public_id, protocol, destination_ports, expires_at, valid_from_revision, valid_from_at
) VALUES (103, $1, pg_catalog.sha256('integration-stale-edge'::BYTEA), '01890f00-0000-7000-8000-000000013401'::UUID,
    'device', '01890f00-0000-7000-8000-000000013402'::UUID, '01890f00-0000-7000-8000-000000013403'::UUID,
    'tcp', '{[22,23)}'::INT4MULTIRANGE, TIMESTAMPTZ '2200-01-01 00:00:00+00', 1, $2)`,
		internalNetwork, staleFrom); err != nil {
		t.Fatal("seed stale edge", err)
	}
	bumpIntegrationNetworkRevision(ctx, t, admin, internalNetwork)
	if outcome, err := store.Record(ctx, installation, scope); err != nil || outcome != ledger.OutcomeRecorded {
		t.Fatalf("changed revision record = %v %v", outcome, err)
	}
	assertAccessLedgerSealed(ctx, t, admin, internalNetwork, 2)
	var closedAt time.Time
	if err := admin.QueryRow(ctx, `SELECT valid_to_at FROM mesh_ops.access_edge_history
WHERE network_id = $1 AND edge_key = pg_catalog.sha256('integration-stale-edge'::BYTEA)`, internalNetwork).
		Scan(&closedAt); err != nil {
		t.Fatal("stale edge was not closed", err)
	}
	if removed, err := store.Prune(ctx, installation, 100); err != nil || removed != 0 {
		t.Fatalf("retention removed recent rows: %d %v", removed, err)
	}

	assertAccessGraphHistoryRead(ctx, t, admin, workspaceID, networkID, staleFrom, closedAt)
}

func containsScope(scopes []network.Scope, want network.Scope) bool {
	for _, scope := range scopes {
		if scope == want {
			return true
		}
	}
	return false
}

func bumpIntegrationNetworkRevision(ctx context.Context, t *testing.T, admin *pgx.Conn, internalNetwork int64) {
	t.Helper()
	var before, recorded int64
	if err := admin.QueryRow(ctx, `UPDATE mesh_ops.network_revision SET network_revision = network_revision + 1,
updated_at = pg_catalog.now() WHERE workspace_id = 103 AND network_id = $1 RETURNING network_revision`,
		internalNetwork).Scan(&before); err != nil {
		t.Fatal("advance revision", err)
	}
	if err := admin.QueryRow(ctx, `SELECT network_revision FROM mesh_ops.network_revision_history
WHERE workspace_id = 103 AND network_id = $1 ORDER BY network_revision DESC LIMIT 1`, internalNetwork).
		Scan(&recorded); err != nil || recorded != before {
		t.Fatalf("revision history = %d, want %d (%v)", recorded, before, err)
	}
}

func assertAccessLedgerSealed(ctx context.Context, t *testing.T, admin *pgx.Conn, internalNetwork int64, want int) {
	t.Helper()
	var snapshots, sealed, outbox int
	var digestsMatch bool
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh_ops.access_edge_snapshot WHERE network_id = $1),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event AS event
     WHERE event.network_id = $1 AND event.action = 'access_graph.recorded' AND event.hash_version = 2
       AND event.target_kind = 'access_edge_snapshot'),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event
     WHERE network_id = $1 AND event_class = 'access_graph.recorded'),
    NOT EXISTS (
        SELECT 1 FROM mesh_ops.access_edge_snapshot AS snapshot
        LEFT JOIN mesh_audit.audit_event AS event
          ON event.target_public_id = snapshot.public_id AND event.action = 'access_graph.recorded'
        WHERE snapshot.network_id = $1
          AND (event.after_semantic_hash IS DISTINCT FROM snapshot.digest
               OR (event.payload->>'digest') IS DISTINCT FROM pg_catalog.encode(snapshot.digest, 'hex'))
    )`, internalNetwork).Scan(&snapshots, &sealed, &outbox, &digestsMatch); err != nil {
		t.Fatal(err)
	}
	if snapshots != want || sealed != want || outbox != want || !digestsMatch {
		t.Fatalf("snapshots=%d sealed=%d outbox=%d digests=%t, want %d", snapshots, sealed, outbox, digestsMatch, want)
	}
	var openEdges, latestCount int
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh_ops.access_edge_history WHERE network_id = $1 AND valid_to_revision IS NULL),
    (SELECT edge_count FROM mesh_ops.access_edge_snapshot WHERE network_id = $1 ORDER BY network_revision DESC LIMIT 1)`,
		internalNetwork).Scan(&openEdges, &latestCount); err != nil || openEdges != latestCount {
		t.Fatalf("open edges %d differ from the sealed count %d (%v)", openEdges, latestCount, err)
	}
}

func assertAccessGraphHistoryRead(ctx context.Context, t *testing.T, admin *pgx.Conn,
	workspaceID workspace.ID, networkID network.ID, staleFrom, closedAt time.Time,
) {
	t.Helper()
	session := authorityConfirmerAccountSessionFixture(t)
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	read := func(at time.Time) *string {
		t.Helper()
		var encoded *string
		if err := transaction.QueryRow(ctx, `SELECT mesh_ops.read_access_graph_history_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TIMESTAMPTZ, $13::TIMESTAMPTZ, NULL, NULL, NULL, NULL, NULL, 501)::TEXT`,
			session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
			session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
			session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
			workspaceID.String(), networkID.String(), time.Now().UTC(), at).Scan(&encoded); err != nil {
			t.Fatal("runtime history read", err)
		}
		return encoded
	}
	if _, err := transaction.Exec(ctx, "SET LOCAL ROLE mesh_runtime"); err != nil {
		t.Fatal(err)
	}
	if read(time.Now().UTC()) != nil {
		t.Fatal("history disclosed without policy.read and device.read")
	}
	if _, err := transaction.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	setIntegrationChange(ctx, t, transaction, "01890f00-0000-7000-8000-000000013410")
	if _, err := transaction.Exec(ctx, `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT addition.id, addition.public_id::UUID, 1, 103, 856, permission.id
FROM (VALUES
    (13411, '01890f00-0000-7000-8000-000000013411', 'device.read'),
    (13412, '01890f00-0000-7000-8000-000000013412', 'policy.read')
) AS addition(id, public_id, permission_key)
JOIN mesh.permission AS permission ON permission.permission_key = addition.permission_key
WHERE NOT EXISTS (SELECT 1 FROM mesh.role_permission AS existing
    WHERE existing.role_definition_id = 856 AND existing.permission_id = permission.id AND existing.state = 'active')`); err != nil {
		t.Fatal("seed temporary read permissions", err)
	}
	if _, err := transaction.Exec(ctx, "SET LOCAL ROLE mesh_runtime"); err != nil {
		t.Fatal(err)
	}
	type page struct {
		RecordedSince *time.Time `json:"recorded_since"`
		Snapshot      *struct {
			Digest string `json:"digest"`
		} `json:"snapshot"`
		Edges []struct {
			EdgeID      string     `json:"edge_id"`
			ValidFromAt time.Time  `json:"valid_from_at"`
			ValidToAt   *time.Time `json:"valid_to_at"`
		} `json:"edges"`
	}
	decode := func(encoded *string) page {
		t.Helper()
		var value page
		if encoded == nil || json.Unmarshal([]byte(*encoded), &value) != nil {
			t.Fatal("history read denied or malformed", encoded)
		}
		return value
	}
	staleKey := func(value page) bool {
		for _, edge := range value.Edges {
			if edge.ValidToAt != nil && edge.ValidToAt.Equal(closedAt) {
				return true
			}
		}
		return false
	}
	current := decode(read(time.Now().UTC()))
	if current.RecordedSince == nil || current.Snapshot == nil || len(current.Snapshot.Digest) != 64 || staleKey(current) {
		t.Fatal("present read is missing its snapshot or shows a closed edge", current)
	}
	// The stale edge predates the baseline, so only instants after the
	// ledger began answer; between the baseline and its close it is shown.
	between := current.RecordedSince.Add(closedAt.Sub(*current.RecordedSince) / 2)
	if between.After(staleFrom) && !staleKey(decode(read(between))) {
		t.Fatal("closed edge missing at an instant inside its validity")
	}
	if before := decode(read(current.RecordedSince.Add(-time.Second))); len(before.Edges) != 0 {
		t.Fatal("history answered before the ledger began")
	}
}
