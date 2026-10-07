//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/meshtransit/meshtransit/internal/audit"
)

const sealedAuditRecordsSQL = `SELECT identity.public_id::TEXT, event.occurred_at, stream.public_id::TEXT,
    identity.stream_sequence, COALESCE(stream.workspace_public_id::TEXT, ''),
    COALESCE(stream.network_public_id::TEXT, ''), identity.change_public_id::TEXT,
    COALESCE(event.actor_principal_public_id::TEXT, ''), event.action, event.permission, event.result,
    event.target_kind, event.target_public_id::TEXT, COALESCE(event.correlation_public_id::TEXT, ''),
    COALESCE(pg_catalog.encode(event.before_semantic_hash, 'hex'), ''),
    COALESCE(pg_catalog.encode(event.after_semantic_hash, 'hex'), ''), event.payload_version,
    event.payload_canonical, event.payload::TEXT, pg_catalog.encode(event.previous_seal_hash, 'hex'),
    pg_catalog.encode(event.seal_hash, 'hex'), stream.scope_kind
FROM mesh_audit.audit_event AS event
JOIN mesh_audit.audit_event_identity AS identity
  ON identity.id = event.event_identity_id AND identity.occurred_at = event.occurred_at
JOIN mesh_audit.audit_stream AS stream ON stream.id = identity.stream_id
WHERE event.hash_version = 2
ORDER BY stream.id, identity.stream_sequence`

// workspaceEvidenceActions are the evidence written about a Workspace itself.
var workspaceEvidenceActions = map[string]bool{
	"workspace.created": true, "workspace.renamed": true,
	"workspace_role.assigned": true, "workspace_role.revoked": true,
}

// assertAuditSealV2 qualifies schema 116: every event written by the flows
// above carries a database seal that the Go record verifier recomputes from
// exported fields alone, seals chain per stream without gaps, stream heads
// match, Workspace evidence sits in Workspace streams, and neither writers
// nor updates can forge a seal.
func assertAuditSealV2(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	rows, err := admin.Query(ctx, sealedAuditRecordsSQL)
	if err != nil {
		t.Fatal(err)
	}
	records, scopes := make([]audit.Record, 0, 128), make([]string, 0, 128)
	for rows.Next() {
		var record audit.Record
		var occurred time.Time
		var stored, scope string
		if err := rows.Scan(&record.EventID, &occurred, &record.StreamID, &record.Sequence, &record.WorkspaceID,
			&record.NetworkID, &record.ChangeID, &record.ActorPrincipalID, &record.Action, &record.Permission,
			&record.Result, &record.TargetKind, &record.TargetID, &record.CorrelationID, &record.BeforeSemanticHash,
			&record.AfterSemanticHash, &record.PayloadVersion, &record.PayloadCanonical, &stored,
			&record.Integrity.PreviousSeal, &record.Integrity.Seal, &scope); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		record.RecordVersion, record.EventTime = audit.RecordVersion, occurred.UTC().Format(audit.RecordTimeLayout)
		record.Integrity.Status, record.Integrity.HashVersion = audit.IntegritySealed, audit.SealHashVersion
		record.ActorKind = audit.ActorPrincipal
		if record.ActorPrincipalID == "" {
			record.ActorKind = audit.ActorSystem
		}
		if stored != record.PayloadCanonical || json.Unmarshal([]byte(record.PayloadCanonical), &record.Payload) != nil {
			rows.Close()
			t.Fatalf("event %s payload text %q does not match stored payload %q", record.EventID, record.PayloadCanonical, stored)
		}
		records, scopes = append(records, record), append(scopes, scope)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(records) < 10 {
		t.Fatalf("sealed audit events = %d, want the flows above to have written at least 10", len(records))
	}
	zero := strings.Repeat("00", 32)
	actions := map[string]bool{}
	for index, record := range records {
		if _, err := record.SealMaterial(); err != nil {
			t.Fatalf("event %s (%s, permission %s, target %s) is not a valid sealed record: %v",
				record.EventID, record.Action, record.Permission, record.TargetKind, err)
		}
		if err := record.VerifySeal(); err != nil {
			encoded, _ := json.Marshal(record)
			t.Fatalf("event %s seal does not verify: %v\n%s", record.EventID, err, encoded)
		}
		if index > 0 && records[index-1].StreamID == record.StreamID {
			previous := records[index-1]
			if record.Sequence != previous.Sequence+1 || record.Integrity.PreviousSeal != previous.Integrity.Seal {
				t.Fatalf("stream %s breaks at #%d: previous #%d", record.StreamID, record.Sequence, previous.Sequence)
			}
		} else if record.Integrity.PreviousSeal != zero {
			t.Fatalf("stream %s first sealed event #%d links to %s, want the zero seal", record.StreamID, record.Sequence, record.Integrity.PreviousSeal)
		}
		if workspaceEvidenceActions[record.Action] && scopes[index] != "workspace" {
			encoded, _ := json.Marshal(record)
			t.Fatalf("Workspace evidence %s is in a %s stream\n%s", record.Action, scopes[index], encoded)
		}
		if (scopes[index] == "deployment") != (record.WorkspaceID == "") || (scopes[index] == "network") != (record.NetworkID != "") {
			t.Fatalf("event %s scope ids do not match its %s stream", record.EventID, scopes[index])
		}
		actions[record.Action] = true
	}
	for _, action := range []string{"workspace.created", "workspace_role.assigned"} {
		if !actions[action] {
			t.Errorf("no sealed %s event; want Workspace evidence covered", action)
		}
	}

	var legacy, staleHeads, wrongScopes int
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event WHERE hash_version IS NULL),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_stream AS stream WHERE stream.sealed_sequence IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM mesh_audit.audit_event_identity AS identity
            JOIN mesh_audit.audit_event AS event ON event.event_identity_id = identity.id AND event.occurred_at = identity.occurred_at
            WHERE identity.stream_id = stream.id AND identity.stream_sequence = stream.sealed_sequence
              AND event.seal_hash = stream.latest_seal_hash
              AND stream.next_sequence = stream.sealed_sequence + 1)),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_stream AS stream
        LEFT JOIN mesh.workspace AS workspace ON workspace.id = stream.workspace_id
        LEFT JOIN mesh.network AS network ON network.id = stream.network_id
        WHERE stream.workspace_public_id IS DISTINCT FROM workspace.public_id
           OR stream.network_public_id IS DISTINCT FROM network.public_id)`).Scan(&legacy, &staleHeads, &wrongScopes); err != nil {
		t.Fatal(err)
	}
	if legacy != 0 || staleHeads != 0 || wrongScopes != 0 {
		t.Fatalf("unsealed events = %d, stale stream heads = %d, streams with wrong scope ids = %d", legacy, staleHeads, wrongScopes)
	}

	_, err = admin.Exec(ctx, `INSERT INTO mesh_audit.audit_event (event_identity_id, occurred_at, deployment_id,
    action, permission, target_kind, target_public_id, result, payload, seal_hash)
VALUES (1, pg_catalog.now(), 1, 'forged.event', 'forged.event', 'forged', pg_catalog.uuidv7(), 'succeeded', '{}',
    pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'))`)
	assertPostgreSQLCode(t, err, "23514")
	_, err = admin.Exec(ctx, `UPDATE mesh_audit.audit_stream SET sealed_sequence = sealed_sequence - 1
WHERE sealed_sequence > 1`)
	assertPostgreSQLCode(t, err, "23514")
	_, err = admin.Exec(ctx, `UPDATE mesh_audit.audit_stream SET workspace_public_id = pg_catalog.uuidv7()
WHERE scope_kind = 'workspace'`)
	assertPostgreSQLCode(t, err, "23514")
}
