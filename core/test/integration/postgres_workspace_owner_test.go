//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
)

func assertWorkspaceOwnerAuthority(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var runtimeAllowed, workerAllowed, observerAllowed bool
	if err := admin.QueryRow(ctx, `SELECT
    has_function_privilege('mesh_runtime',$1,'EXECUTE'),
    has_function_privilege('mesh_worker',$1,'EXECUTE'),
    has_function_privilege('mesh_observer',$1,'EXECUTE')`,
		"mesh_ops.resolve_network_permission_v2(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,uuid,uuid,text,timestamptz)",
	).Scan(&runtimeAllowed, &workerAllowed, &observerAllowed); err != nil {
		t.Fatal(err)
	}
	if !runtimeAllowed || workerAllowed || observerAllowed {
		t.Fatal("owner resolver acquired an unintended execution grant")
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setIntegrationChange(ctx, t, tx, "01890f00-0000-7000-8000-000000012000")
	setIntegrationScope(ctx, t, tx, 103, 203)
	// No role can explain an owner decision in this rollback-only fixture.
	if _, err := tx.Exec(ctx, `UPDATE mesh.role_binding SET state='suspended',
    authority_generation=authority_generation+1, version=version+1,
    updated_at=pg_catalog.transaction_timestamp()
WHERE workspace_id=103 AND principal_id=11 AND state<>'revoked';
UPDATE mesh.workspace SET owner_principal_id=11,
    authority_generation=authority_generation+1, version=version+1,
    updated_at=pg_catalog.transaction_timestamp() WHERE id=103`); err != nil {
		t.Fatal(err)
	}
	session := managementRBACAccountSessionFixture(t)
	workspaceID, _ := session.LoginWorkspaceID()
	networkID := "01890f00-0000-7000-8000-000000000203"
	rows, err := tx.Query(ctx, `SELECT permission_key FROM mesh.permission
WHERE 'network'=ANY(allowed_scope_kinds) ORDER BY permission_key`)
	if err != nil {
		t.Fatal(err)
	}
	var permissions []string
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			t.Fatal(err)
		}
		permissions = append(permissions, permission)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(permissions) < 40 {
		t.Fatal("owner contract did not cover the Network permission catalog")
	}
	for _, permission := range permissions {
		count, generation := readOwnerPermission(ctx, t, tx, session, workspaceID.String(), networkID, permission)
		if count != 1 || generation <= 0 {
			t.Fatalf("owner lost %s without a role", permission)
		}
	}
	// Future Networks in the same Workspace inherit ownership automatically.
	setIntegrationScope(ctx, t, tx, 103, 204)
	count, generation := readOwnerPermission(ctx, t, tx, session, workspaceID.String(),
		"01890f00-0000-7000-8000-000000000204", "policy.publish")
	if count != 1 || generation <= 0 {
		t.Fatal("ownership did not cover the second Network")
	}
	setIntegrationScope(ctx, t, tx, 103, 203)
	for _, permission := range []string{"deployment.operate", "support.grant.use", "workspace.owner.transfer", "unknown.permission"} {
		count, _ := readOwnerPermission(ctx, t, tx, session, workspaceID.String(), networkID, permission)
		if count != 0 {
			t.Fatalf("Network owner resolver widened scope for %s", permission)
		}
	}
	count, _ = readOwnerPermission(ctx, t, tx, session, workspaceID.String(),
		"01890f00-0000-7000-8000-000000000201", "policy.publish")
	if count != 0 {
		t.Fatal("ownership crossed a Workspace/Network pair")
	}
	count, _ = readOwnerPermission(ctx, t, tx, authorityConfirmerAccountSessionFixture(t), workspaceID.String(), networkID, "policy.publish")
	if count != 0 {
		t.Fatal("an ordinary member inherited owner publication authority")
	}

	args := ownerSessionArguments(session, workspaceID.String())
	var encoded *string
	if err := tx.QueryRow(ctx, `SELECT mesh_ops.read_console_management_scopes_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,
    $10::UUID,$11::TIMESTAMPTZ,NULL::UUID,100)::TEXT`, args...).Scan(&encoded); err != nil || encoded == nil {
		t.Fatal("owner Console projection unavailable", err)
	}
	var projection struct {
		Scopes []struct {
			Permissions []string `json:"permissions"`
		} `json:"scopes"`
	}
	if err := json.Unmarshal([]byte(*encoded), &projection); err != nil {
		t.Fatal(err)
	}
	if len(projection.Scopes) != 2 {
		t.Fatal("owner Console projection hid a Network")
	}
	for _, scope := range projection.Scopes {
		if len(scope.Permissions) != 10 {
			t.Fatal("owner Console projection still depended on individual roles")
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE mesh.workspace_membership SET state='suspended',
    authority_generation=authority_generation+1,version=version+1,
    updated_at=pg_catalog.transaction_timestamp()
WHERE workspace_id=103 AND principal_id=11 AND state='active'`); err != nil {
		t.Fatal(err)
	}
	count, _ = readOwnerPermission(ctx, t, tx, session, workspaceID.String(), networkID, "policy.publish")
	if count != 0 {
		t.Fatal("ownership bypassed suspended Workspace membership")
	}
	if _, err := tx.Exec(ctx, `UPDATE mesh.workspace_membership SET state='active',
    authority_generation=authority_generation+1,version=version+1,
    updated_at=pg_catalog.transaction_timestamp()
WHERE workspace_id=103 AND principal_id=11 AND state='suspended'`); err != nil {
		t.Fatal(err)
	}
	// The owner row, rather than a cached role, is evaluated on every operation.
	if _, err := tx.Exec(ctx, `UPDATE mesh.workspace SET owner_principal_id=14,
    authority_generation=authority_generation+1,version=version+1,
    updated_at=pg_catalog.transaction_timestamp() WHERE id=103`); err != nil {
		t.Fatal(err)
	}
	count, _ = readOwnerPermission(ctx, t, tx, session, workspaceID.String(), networkID, "policy.publish")
	if count != 0 {
		t.Fatal("previous owner retained implicit authority after transfer")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
}

func ownerSessionArguments(session accountsession.Session, workspaceID string) []any {
	return []any{session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
		workspaceID, time.Now().UTC()}
}

func readOwnerPermission(ctx context.Context, t *testing.T, tx pgx.Tx, session accountsession.Session,
	workspaceID, networkID, permission string) (int64, int64) {
	t.Helper()
	args := ownerSessionArguments(session, workspaceID)
	args = append(args[:10], networkID, permission, args[10])
	var count, generation int64
	if err := tx.QueryRow(ctx, `SELECT count(*),COALESCE(max(workspace_owner_authority_generation),0)
FROM mesh_ops.resolve_network_permission_v2(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,
    $10::UUID,$11::UUID,$12::TEXT,$13::TIMESTAMPTZ)`, args...).Scan(&count, &generation); err != nil {
		t.Fatal("resolve owner authority", err)
	}
	return count, generation
}
