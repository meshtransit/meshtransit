//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/domain/identity/accountsession"
)

// assertPostgreSQLAPIKeyAuditCredential drives schema 323 (V1-80 A2):
// mesh_audit.audit_event records actor_credential_kind and
// actor_credential_public_id from transaction GUCs and rejects invalid,
// half-set, system-actor, cross-principal, and cross-Workspace contexts.
func assertPostgreSQLAPIKeyAuditCredential(ctx context.Context, t *testing.T, admin *pgx.Conn, owner accountsession.Session) {
	t.Helper()
	f := loadLifecycleFixture(ctx, t, admin, owner.ID().String())
	assertAuditCredentialInteractiveAndKey(ctx, t, admin, owner.ID().String(), f)
	assertAuditCredentialContextRefusals(ctx, t, admin, owner.ID().String(), f)
}

func assertAuditCredentialInteractiveAndKey(ctx context.Context, t *testing.T, admin *pgx.Conn,
	ownerSession string, f apiKeyMemberFixture,
) {
	t.Helper()
	tx := beginSeededAPIKeyMemberTx(ctx, t, admin, ownerSession, f, "audit credential")
	defer func() { _ = tx.Rollback(ctx) }()

	keyID := "01890f00-0000-7000-8000-00000000d101"
	sessID := "01890f00-0000-7000-8000-00000000d102"
	_ = mustCreateKeyTx(ctx, t, tx, f.human, f.workspace, keyID, sessID, "audit-key", 30*24*time.Hour, "d101")
	evInteractive := "01890f00-0000-7000-8000-00000000d110"
	if err := appendWorkspaceAuditFixtureTx(ctx, tx, f.workspace, evInteractive, f.memberPrincipal, keyID, "api_key.created"); err != nil {
		t.Fatalf("interactive audit append: %v", err)
	}
	kind, credID, hashVer := readAuditCredentialTx(ctx, t, tx, evInteractive)
	if kind != nil || credID != nil || hashVer != 2 {
		t.Fatalf("interactive event = (%v, %v, v%d), want (nil, nil, v2)", kind, credID, hashVer)
	}

	// Self-revoke attributed to the API key via transaction-local GUCs.
	_ = mustRevokeKeyTx(ctx, t, tx, sessID, f.workspace, "", keyID)
	setActorCredentialGUCsTx(ctx, t, tx, "api_key", keyID)
	evKey := "01890f00-0000-7000-8000-00000000d111"
	if err := appendWorkspaceAuditFixtureTx(ctx, tx, f.workspace, evKey, f.memberPrincipal, keyID, "api_key.revoked"); err != nil {
		t.Fatalf("api key audit append: %v", err)
	}
	kind, credID, hashVer = readAuditCredentialTx(ctx, t, tx, evKey)
	if kind == nil || *kind != "api_key" || credID == nil || *credID != keyID || hashVer != 2 {
		t.Fatalf("api key event = (%v, %v, v%d), want ('api_key', %s, v2)", kind, credID, hashVer, keyID)
	}
}

func assertAuditCredentialContextRefusals(ctx context.Context, t *testing.T, admin *pgx.Conn,
	ownerSession string, f apiKeyMemberFixture,
) {
	t.Helper()
	tx := beginSeededAPIKeyMemberTx(ctx, t, admin, ownerSession, f, "audit credential refusals")
	defer func() { _ = tx.Rollback(ctx) }()

	keyID := "01890f00-0000-7000-8000-00000000d201"
	sessID := "01890f00-0000-7000-8000-00000000d202"
	_ = mustCreateKeyTx(ctx, t, tx, f.human, f.workspace, keyID, sessID, "refuse-key", 30*24*time.Hour, "d201")
	var ownerPrincipal string
	if err := tx.QueryRow(ctx, `SELECT p.public_id::TEXT FROM mesh.account_session AS s
JOIN mesh.principal AS p ON p.id = s.principal_id WHERE s.public_id = $1::UUID`, f.manager).Scan(&ownerPrincipal); err != nil {
		t.Fatal(err)
	}

	// Local positive control: unperturbed API key context succeeds on the Workspace stream.
	if err := inSavepointTx(ctx, t, tx, func() error {
		setActorCredentialGUCsTx(ctx, t, tx, "api_key", keyID)
		return appendWorkspaceAuditFixtureTx(ctx, tx, f.workspace, "01890f00-0000-7000-8000-00000000d2a0",
			f.memberPrincipal, keyID, "api_key.created")
	}); err != nil {
		t.Fatalf("baseline positive control failed: %v", err)
	}

	cases := []struct {
		name, ws, actor, kind, credID string
	}{
		{"kind without id", f.workspace, f.memberPrincipal, "api_key", ""},
		{"id without kind", f.workspace, f.memberPrincipal, "", keyID},
		{"unknown kind", f.workspace, f.memberPrincipal, "interactive", keyID},
		{"malformed uuid", f.workspace, f.memberPrincipal, "api_key", "not-a-uuid"},
		{"non-v7 uuid", f.workspace, f.memberPrincipal, "api_key", "11111111-1111-4111-8111-111111111111"},
		{"unknown key id", f.workspace, f.memberPrincipal, "api_key", "01890f00-0000-7000-8000-00000000d299"},
		{"cross-principal spoof", f.workspace, ownerPrincipal, "api_key", keyID},
		{"cross-workspace spoof", f.elsewhere, f.memberPrincipal, "api_key", keyID},
		{"deployment stream spoof", "", f.memberPrincipal, "api_key", keyID},
		{"system actor with key", f.workspace, "", "api_key", keyID},
	}
	for _, tc := range cases {
		err := inSavepointTx(ctx, t, tx, func() error {
			setActorCredentialGUCsTx(ctx, t, tx, tc.kind, tc.credID)
			return appendAuditFixtureTx(ctx, tx, tc.ws, "01890f00-0000-7000-8000-00000000d2aa",
				tc.actor, keyID, "api_key.created")
		})
		assertPGError(t, tc.name, err, "23514", "invalid actor credential context")
	}
}

func setActorCredentialGUCsTx(ctx context.Context, t *testing.T, tx pgx.Tx, kind, credID string) {
	t.Helper()
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.actor_credential_kind', $1, TRUE),
    pg_catalog.set_config('mesh.actor_credential_public_id', $2, TRUE)`, kind, credID); err != nil {
		t.Fatalf("set actor credential GUCs: %v", err)
	}
}

func appendWorkspaceAuditFixtureTx(ctx context.Context, tx pgx.Tx, wsPublicID, eventPublicID,
	actorPrincipalPublicID, targetPublicID, action string,
) error {
	return appendAuditFixtureTx(ctx, tx, wsPublicID, eventPublicID, actorPrincipalPublicID, targetPublicID, action)
}

func appendAuditFixtureTx(ctx context.Context, tx pgx.Tx, wsPublicID, eventPublicID,
	actorPrincipalPublicID, targetPublicID, action string,
) error {
	var streamID, nextSeq int64
	var prevHash []byte
	var err error
	if wsPublicID == "" {
		err = tx.QueryRow(ctx, `SELECT stream.id, stream.next_sequence, stream.latest_event_hash
FROM mesh_audit.audit_stream AS stream
WHERE stream.scope_kind = 'deployment' ORDER BY stream.id LIMIT 1`).Scan(&streamID, &nextSeq, &prevHash)
	} else {
		err = tx.QueryRow(ctx, `SELECT stream.id, stream.next_sequence, stream.latest_event_hash
FROM mesh_audit.audit_stream AS stream
WHERE stream.scope_kind = 'workspace' AND stream.workspace_public_id = $1::UUID`, wsPublicID).Scan(
			&streamID, &nextSeq, &prevHash)
	}
	if err != nil {
		return err
	}
	var actorArg any
	if actorPrincipalPublicID != "" {
		actorArg = actorPrincipalPublicID
	}
	var seq int64
	return tx.QueryRow(ctx, `SELECT mesh_audit.append_authority_evidence(
    $1, $2::UUID, pg_catalog.uuidv7(), $3, $4, pg_catalog.sha256(pg_catalog.convert_to($2::TEXT, 'UTF8')),
    'api_key', $5::UUID, 1, NULL, $6::UUID, $7, 'api_key.manage', pg_catalog.uuidv7(),
    NULL, NULL, '{}'::JSONB, 'api_key.changed', '{}'::JSONB)`,
		streamID, eventPublicID, nextSeq, prevHash, targetPublicID, actorArg, action).Scan(&seq)
}

func readAuditCredentialTx(ctx context.Context, t *testing.T, tx pgx.Tx, eventPublicID string) (*string, *string, int) {
	t.Helper()
	var kind, credID *string
	var hashVer int
	if err := tx.QueryRow(ctx, `SELECT event.actor_credential_kind, event.actor_credential_public_id::TEXT, event.hash_version
FROM mesh_audit.audit_event AS event
JOIN mesh_audit.audit_event_identity AS identity
  ON identity.id = event.event_identity_id AND identity.occurred_at = event.occurred_at
WHERE identity.public_id = $1::UUID`, eventPublicID).Scan(&kind, &credID, &hashVer); err != nil {
		t.Fatalf("read audit event %s: %v", eventPublicID, err)
	}
	return kind, credID, hashVer
}
