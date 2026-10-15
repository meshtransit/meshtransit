//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/node/enforcementledger"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/shared/policydigest"
)

// assertPostgreSQLDeviceEnforcementLedger qualifies schema 136: the worker
// records enforcement intervals once per change, seals a mismatch and its
// restore on the Network stream, keeps recent rows, and the history read
// answers at an instant under device.read only.
func assertPostgreSQLDeviceEnforcementLedger(ctx context.Context, t *testing.T,
	admin *pgx.Conn, workerPool, _ *postgresadapter.Pool,
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

	store, err := postgresadapter.NewEnforcementLedgerStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := store.ListNetworks(ctx, installation, network.ID{}, 200)
	if err != nil || !containsScope(scopes, scope) {
		t.Fatalf("Network not listed: %v %v", scopes, err)
	}
	targets, err := store.ListDevices(ctx, installation, scope, node.ID{}, 500)
	if err != nil || len(targets) == 0 {
		t.Fatalf("Devices = %v, %v; the fixture needs an active Device", targets, err)
	}
	device := targets[0].DeviceID
	if targets[0].Open != (enforcementledger.Interval{}) {
		t.Fatal("a Device had evidence before any record", targets[0])
	}

	digestA, digestB := policydigest.Digest{0xa1}, policydigest.Digest{0xb2}
	record := func(enforced policydigest.Digest, want enforcementledger.Outcome) {
		t.Helper()
		now := time.Now().UTC()
		outcome, err := store.Record(ctx, installation, enforcementledger.Observation{
			Scope: scope, DeviceID: device, NetworkRevision: 3,
			Delivered: distribution.FilterSummary{Digest: digestA, Grants: 8},
			Enforced:  distribution.FilterSummary{Digest: enforced, Grants: 7},
			AppliedAt: now.Add(-time.Second), ReportedAt: now,
		})
		if err != nil || outcome != want {
			t.Fatalf("Record() = %v, %v; want %v", outcome, err, want)
		}
	}
	record(digestA, enforcementledger.OutcomeRecorded)
	record(digestA, enforcementledger.OutcomeUnchanged)
	assertEnforcementSealed(ctx, t, admin, internalNetwork, 0, 0)
	record(digestB, enforcementledger.OutcomeAudited)
	assertEnforcementSealed(ctx, t, admin, internalNetwork, 1, 0)
	targets, err = store.ListDevices(ctx, installation, scope, node.ID{}, 500)
	if err != nil || targets[0].Open != (enforcementledger.Interval{State: enforcementledger.StateMismatch,
		Delivered: digestA, Enforced: digestB}) {
		t.Fatalf("open interval after mismatch = %+v, %v", targets[0], err)
	}
	record(digestA, enforcementledger.OutcomeAudited)
	assertEnforcementSealed(ctx, t, admin, internalNetwork, 1, 1)
	if removed, err := store.Prune(ctx, installation, 100); err != nil || removed != 0 {
		t.Fatalf("retention removed recent rows: %d %v", removed, err)
	}

	var mismatchFrom, mismatchTo time.Time
	if err := admin.QueryRow(ctx, `SELECT valid_from, valid_to FROM mesh_ops.device_enforcement_history
WHERE network_id = $1 AND device_public_id = $2::UUID AND state = 'mismatch'`, internalNetwork, device.String()).
		Scan(&mismatchFrom, &mismatchTo); err != nil {
		t.Fatal("mismatch interval", err)
	}
	assertEnforcementHistoryRead(ctx, t, admin, workspaceID, networkID, device, mismatchFrom, mismatchTo)
}

func assertEnforcementSealed(ctx context.Context, t *testing.T, admin *pgx.Conn, internalNetwork int64,
	wantMismatch, wantRestored int) {
	t.Helper()
	var mismatch, restored, events, outbox int
	var digestsMatch bool
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event WHERE network_id = $1
       AND action = 'device.enforcement_mismatch' AND hash_version = 2 AND target_kind = 'device_enforcement_event'),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event WHERE network_id = $1
       AND action = 'device.enforcement_restored' AND hash_version = 2 AND target_kind = 'device_enforcement_event'),
    (SELECT pg_catalog.count(*) FROM mesh_ops.device_enforcement_event WHERE network_id = $1),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event WHERE network_id = $1
       AND event_class IN ('device.enforcement_mismatch', 'device.enforcement_restored')),
    NOT EXISTS (
        SELECT 1 FROM mesh_ops.device_enforcement_event AS recorded
        LEFT JOIN mesh_audit.audit_event AS event ON event.target_public_id = recorded.public_id
        WHERE recorded.network_id = $1
          AND (event.after_semantic_hash IS DISTINCT FROM recorded.enforced_digest
               OR (event.payload->>'enforced_digest')
                  IS DISTINCT FROM 'sha256:' || pg_catalog.encode(recorded.enforced_digest, 'hex'))
    )`, internalNetwork).Scan(&mismatch, &restored, &events, &outbox, &digestsMatch); err != nil {
		t.Fatal(err)
	}
	if mismatch != wantMismatch || restored != wantRestored || events != wantMismatch+wantRestored ||
		outbox != events || !digestsMatch {
		t.Fatalf("mismatch=%d restored=%d events=%d outbox=%d digests=%t, want %d/%d", mismatch, restored, events,
			outbox, digestsMatch, wantMismatch, wantRestored)
	}
	var open int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.device_enforcement_history
WHERE network_id = $1 AND valid_to IS NULL`, internalNetwork).Scan(&open); err != nil || open != 1 {
		t.Fatalf("open intervals = %d, %v; want exactly one", open, err)
	}
}

func assertEnforcementHistoryRead(ctx context.Context, t *testing.T, admin *pgx.Conn,
	workspaceID workspace.ID, networkID network.ID, device node.ID, mismatchFrom, mismatchTo time.Time,
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
		if err := transaction.QueryRow(ctx, `SELECT mesh_ops.read_device_enforcement_history_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TIMESTAMPTZ, $13::TIMESTAMPTZ, NULL, 101)::TEXT`,
			session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
			session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
			session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
			workspaceID.String(), networkID.String(), time.Now().UTC(), at).Scan(&encoded); err != nil {
			t.Fatal("runtime enforcement history read", err)
		}
		return encoded
	}
	if _, err := transaction.Exec(ctx, "SET LOCAL ROLE mesh_runtime"); err != nil {
		t.Fatal(err)
	}
	var mayRecord bool
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.has_function_privilege(
'mesh_ops.record_device_enforcement_v1(UUID, UUID, UUID, UUID, BIGINT, BYTEA, INTEGER, BYTEA, INTEGER, TIMESTAMPTZ, TIMESTAMPTZ, UUID, UUID)',
'EXECUTE')`).Scan(&mayRecord); err != nil || mayRecord {
		t.Fatal("the runtime role may record enforcement evidence", err)
	}
	if read(time.Now().UTC()) != nil {
		t.Fatal("enforcement history disclosed without device.read")
	}
	if _, err := transaction.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	setIntegrationChange(ctx, t, transaction, "01890f00-0000-7000-8000-000000013610")
	if _, err := transaction.Exec(ctx, `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 13611, '01890f00-0000-7000-8000-000000013611'::UUID, 1, 103, 856, permission.id
FROM mesh.permission AS permission WHERE permission.permission_key = 'device.read'
  AND NOT EXISTS (SELECT 1 FROM mesh.role_permission AS existing
    WHERE existing.role_definition_id = 856 AND existing.permission_id = permission.id AND existing.state = 'active')`); err != nil {
		t.Fatal("seed temporary device.read", err)
	}
	if _, err := transaction.Exec(ctx, "SET LOCAL ROLE mesh_runtime"); err != nil {
		t.Fatal(err)
	}
	type page struct {
		RecordedSince *time.Time `json:"recorded_since"`
		Devices       []struct {
			ID       string `json:"id"`
			State    string `json:"state"`
			Enforced string `json:"enforced_digest"`
		} `json:"devices"`
	}
	stateAt := func(at time.Time) (string, *time.Time) {
		t.Helper()
		encoded := read(at)
		var value page
		if encoded == nil || json.Unmarshal([]byte(*encoded), &value) != nil {
			t.Fatal("enforcement history denied or malformed", encoded)
		}
		for _, evidence := range value.Devices {
			if evidence.ID == device.String() {
				return evidence.State, value.RecordedSince
			}
		}
		return "", value.RecordedSince
	}
	if state, since := stateAt(time.Now().UTC()); state != "enforced" || since == nil {
		t.Fatalf("present state = %q since %v, want enforced", state, since)
	}
	if state, _ := stateAt(mismatchFrom.Add(mismatchTo.Sub(mismatchFrom) / 2)); state != "mismatch" {
		t.Fatalf("state inside the mismatch = %q", state)
	}
	if state, _ := stateAt(mismatchFrom.Add(-time.Hour)); state != "" {
		t.Fatalf("state before any evidence = %q", state)
	}
}
