//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/identity/accountsession"
)

// assertBuiltinWorkspaceRoles qualifies schema 95 in a rollback-only fixture:
// catalog parity with Go, Workspace- and Network-scope resolution, expiry,
// revocation, immutability and the Console projection.
func assertBuiltinWorkspaceRoles(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	assertBuiltinRoleCatalogParity(ctx, t, admin)

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setIntegrationChange(ctx, t, tx, "01890f00-0000-7000-8000-000000013000")
	setIntegrationScope(ctx, t, tx, 103, 203)
	// Principal 11 holds no custom role and does not own the Workspace, so only
	// the assignments created below can explain a decision.
	if _, err := tx.Exec(ctx, `UPDATE mesh.role_binding SET state='suspended',
    authority_generation=authority_generation+1, version=version+1,
    updated_at=pg_catalog.transaction_timestamp()
WHERE workspace_id=103 AND principal_id=11 AND state<>'revoked';
UPDATE mesh.workspace SET owner_principal_id=14,
    authority_generation=authority_generation+1, version=version+1,
    updated_at=pg_catalog.transaction_timestamp() WHERE id=103 AND owner_principal_id<>14`); err != nil {
		t.Fatal(err)
	}
	session := managementRBACAccountSessionFixture(t)
	workspaceID, _ := session.LoginWorkspaceID()
	const firstNetwork = "01890f00-0000-7000-8000-000000000203"
	const secondNetwork = "01890f00-0000-7000-8000-000000000204"
	network := func(id string, permission string) builtinResolution {
		scope := int64(203)
		if id == secondNetwork {
			scope = 204
		}
		setIntegrationScope(ctx, t, tx, 103, scope)
		return resolveBuiltinNetworkPermission(ctx, t, tx, session, workspaceID.String(), id, permission)
	}
	workspace := func(permission string) builtinResolution {
		setIntegrationScope(ctx, t, tx, 103, 203)
		return resolveBuiltinWorkspacePermission(ctx, t, tx, session, workspaceID.String(), permission)
	}
	if network(firstNetwork, "policy.publish").found {
		t.Fatal("fixture principal already publishes policy")
	}

	assignment := insertBuiltinAssignment(ctx, t, tx, "01890f00-0000-7000-8000-000000013001",
		"network_admin", "NULL", "NULL")
	for _, id := range []string{firstNetwork, secondNetwork} {
		resolution := network(id, "policy.publish")
		if !resolution.found || resolution.bindingID != assignment ||
			resolution.roleID != "01a10e00-0000-7000-8000-000000000002" ||
			resolution.bindingGeneration != 1 || resolution.roleGeneration != 1 || resolution.ownerGeneration != 0 {
			t.Fatalf("Workspace-scope network_admin on %s = %+v", id, resolution)
		}
	}
	if network(firstNetwork, "device.manage").found {
		t.Fatal("network_admin widened to Device lifecycle")
	}
	if !workspace("member.read").found || workspace("role_binding.manage").found {
		t.Fatal("network_admin Workspace permissions are wrong")
	}
	assertBuiltinConsoleProjection(ctx, t, tx, session, workspaceID.String(), 2, 10)

	revokeBuiltinAssignment(ctx, t, tx, assignment)
	if network(firstNetwork, "policy.publish").found {
		t.Fatal("revoked assignment still authorizes")
	}

	scoped := insertBuiltinAssignment(ctx, t, tx, "01890f00-0000-7000-8000-000000013002",
		"it_admin", "203", "NULL")
	if resolution := network(firstNetwork, "device.manage"); !resolution.found || resolution.bindingID != scoped {
		t.Fatalf("Network-scope it_admin = %+v", resolution)
	}
	if network(secondNetwork, "device.manage").found {
		t.Fatal("Network-scope assignment crossed into another Network")
	}
	if workspace("role_binding.manage").found {
		t.Fatal("a Network-scope role administered the Workspace")
	}
	revokeBuiltinAssignment(ctx, t, tx, scoped)

	insertBuiltinAssignmentValidity(ctx, t, tx, "01890f00-0000-7000-8000-000000013003", "admin",
		"pg_catalog.transaction_timestamp() - INTERVAL '2 hours'",
		"pg_catalog.transaction_timestamp() - INTERVAL '1 hour'")
	if network(firstNetwork, "policy.publish").found || workspace("member.read").found {
		t.Fatal("expired assignment still authorizes")
	}

	expectBuiltinRejection(ctx, t, tx, "billing_admin cannot be Network-scoped", `INSERT INTO mesh.workspace_role_assignment (
    public_id, deployment_id, workspace_id, network_id, principal_id, workspace_membership_id, role_key,
    state, valid_from, created_at, updated_at)
SELECT '01890f00-0000-7000-8000-000000013004', membership.deployment_id, 103, 203, 11, membership.id,
    'billing_admin', 'active', pg_catalog.transaction_timestamp(),
    pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp()
FROM mesh.workspace_membership AS membership
WHERE membership.workspace_id=103 AND membership.principal_id=11 AND membership.state='active'`)
	immutable := insertBuiltinAssignment(ctx, t, tx, "01890f00-0000-7000-8000-000000013005", "auditor", "NULL", "NULL")
	expectBuiltinRejection(ctx, t, tx, "assignment role is immutable", `UPDATE mesh.workspace_role_assignment
SET role_key='admin', version=version+1, authority_generation=authority_generation+1
WHERE public_id='`+immutable+`'`)
	expectBuiltinRejection(ctx, t, tx, "assignments are retained", `DELETE FROM mesh.workspace_role_assignment
WHERE public_id='`+immutable+`'`)
	expectBuiltinRejection(ctx, t, tx, "role catalog is immutable", `UPDATE mesh.builtin_role
SET display_name='Root' WHERE role_key='auditor'`)
	expectBuiltinRejection(ctx, t, tx, "role permissions are immutable", `DELETE FROM mesh.builtin_role_permission
WHERE role_key='auditor'`)

	// Ownership still answers Workspace permissions without any assignment.
	if _, err := tx.Exec(ctx, `UPDATE mesh.workspace SET owner_principal_id=11,
    authority_generation=authority_generation+1, version=version+1,
    updated_at=pg_catalog.transaction_timestamp() WHERE id=103`); err != nil {
		t.Fatal(err)
	}
	if resolution := workspace("role_binding.manage"); !resolution.found || resolution.ownerGeneration <= 0 ||
		resolution.bindingID != "" {
		t.Fatalf("owner Workspace resolution = %+v", resolution)
	}
	if workspace("deployment.operate").found {
		t.Fatal("Workspace resolver granted a Deployment permission")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
}

type builtinResolution struct {
	found             bool
	bindingID         string
	roleID            string
	bindingGeneration int64
	roleGeneration    int64
	ownerGeneration   int64
}

func assertBuiltinRoleCatalogParity(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	for _, role := range authorization.BuiltinRoles() {
		rows, err := admin.Query(ctx, `SELECT permission.permission_key
FROM mesh.builtin_role_permission AS grant_row
JOIN mesh.permission AS permission ON permission.id = grant_row.permission_id
WHERE grant_row.role_key = $1 ORDER BY permission.permission_key COLLATE "C"`, string(role))
		if err != nil {
			t.Fatal(err)
		}
		var database []string
		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				t.Fatal(err)
			}
			database = append(database, key)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		var code []string
		for _, permission := range role.Permissions() {
			code = append(code, string(permission))
		}
		slices.Sort(code)
		if !slices.Equal(database, code) {
			t.Fatalf("%s permissions differ:\n database %v\n code     %v", role, database, code)
		}
		var networkScope bool
		var assignableBy []string
		if err := admin.QueryRow(ctx, `SELECT network_scope_allowed, assignable_by
FROM mesh.builtin_role WHERE role_key = $1`, string(role)).Scan(&networkScope, &assignableBy); err != nil {
			t.Fatal(err)
		}
		if networkScope != role.NetworkScopeAllowed() {
			t.Fatalf("%s Network scope differs", role)
		}
		for _, assigner := range []authorization.RoleAssigner{
			authorization.RoleAssignerOwner, authorization.RoleAssignerAdmin, authorization.RoleAssignerITAdmin,
		} {
			if slices.Contains(assignableBy, string(assigner)) != role.AssignableBy(assigner) {
				t.Fatalf("%s assigner %s differs", role, assigner)
			}
		}
	}
	var catalogSize int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh.builtin_role`).Scan(&catalogSize); err != nil ||
		catalogSize != len(authorization.BuiltinRoles()) {
		t.Fatalf("built-in role catalog size = %d, error = %v", catalogSize, err)
	}
}

func insertBuiltinAssignment(ctx context.Context, t *testing.T, tx pgx.Tx, publicID, role, network, expires string) string {
	t.Helper()
	return insertBuiltinAssignmentValidity(ctx, t, tx, publicID, role,
		"pg_catalog.transaction_timestamp() - INTERVAL '1 minute'", expires, network)
}

func insertBuiltinAssignmentValidity(
	ctx context.Context, t *testing.T, tx pgx.Tx, publicID, role, validFrom, expires string, network ...string,
) string {
	t.Helper()
	networkValue := "NULL"
	if len(network) == 1 {
		networkValue = network[0]
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mesh.workspace_role_assignment (
    public_id, deployment_id, workspace_id, network_id, principal_id, workspace_membership_id, role_key,
    state, valid_from, expires_at, created_at, updated_at)
SELECT $1::UUID, membership.deployment_id, 103, `+networkValue+`, 11, membership.id, $2,
    'active', `+validFrom+`, `+expires+`,
    pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp()
FROM mesh.workspace_membership AS membership
WHERE membership.workspace_id=103 AND membership.principal_id=11 AND membership.state='active'`,
		publicID, role); err != nil {
		t.Fatalf("insert %s assignment: %v", role, err)
	}
	return publicID
}

func revokeBuiltinAssignment(ctx context.Context, t *testing.T, tx pgx.Tx, publicID string) {
	t.Helper()
	if _, err := tx.Exec(ctx, `UPDATE mesh.workspace_role_assignment SET state='revoked',
    revoked_at=pg_catalog.transaction_timestamp(), updated_at=pg_catalog.transaction_timestamp(),
    version=version+1, authority_generation=authority_generation+1
WHERE public_id=$1::UUID`, publicID); err != nil {
		t.Fatalf("revoke assignment: %v", err)
	}
}

func expectBuiltinRejection(ctx context.Context, t *testing.T, tx pgx.Tx, name, statement string) {
	t.Helper()
	if _, err := tx.Exec(ctx, `SAVEPOINT builtin_rejection`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, statement); err == nil {
		t.Fatalf("%s: statement succeeded", name)
	}
	if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT builtin_rejection`); err != nil {
		t.Fatal(err)
	}
}

func resolveBuiltinNetworkPermission(ctx context.Context, t *testing.T, tx pgx.Tx, session accountsession.Session,
	workspaceID, networkID, permission string) builtinResolution {
	t.Helper()
	args := ownerSessionArguments(session, workspaceID)
	args = append(args[:10], networkID, permission, args[10])
	return scanBuiltinResolution(ctx, t, tx, `SELECT role_binding_public_id::TEXT, role_definition_public_id::TEXT,
    binding_authority_generation, role_authority_generation, workspace_owner_authority_generation
FROM mesh_ops.resolve_network_permission_v2(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,
    $10::UUID,$11::UUID,$12::TEXT,$13::TIMESTAMPTZ)`, args)
}

func resolveBuiltinWorkspacePermission(ctx context.Context, t *testing.T, tx pgx.Tx, session accountsession.Session,
	workspaceID, permission string) builtinResolution {
	t.Helper()
	args := ownerSessionArguments(session, workspaceID)
	args = append(args[:10], permission, args[10])
	return scanBuiltinResolution(ctx, t, tx, `SELECT role_binding_public_id::TEXT, role_definition_public_id::TEXT,
    binding_authority_generation, role_authority_generation, workspace_owner_authority_generation
FROM mesh_ops.resolve_workspace_permission_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,
    $10::UUID,$11::TEXT,$12::TIMESTAMPTZ)`, args)
}

func scanBuiltinResolution(ctx context.Context, t *testing.T, tx pgx.Tx, query string, args []any) builtinResolution {
	t.Helper()
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		t.Fatal("resolve built-in authority", err)
	}
	defer rows.Close()
	var result builtinResolution
	for rows.Next() {
		var bindingID, roleID *string
		if err := rows.Scan(&bindingID, &roleID, &result.bindingGeneration, &result.roleGeneration,
			&result.ownerGeneration); err != nil {
			t.Fatal(err)
		}
		result.found = true
		if bindingID != nil {
			result.bindingID = *bindingID
		}
		if roleID != nil {
			result.roleID = *roleID
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertBuiltinConsoleProjection(ctx context.Context, t *testing.T, tx pgx.Tx, session accountsession.Session,
	workspaceID string, networks, permissions int) {
	t.Helper()
	var encoded *string
	if err := tx.QueryRow(ctx, `SELECT mesh_ops.read_console_management_scopes_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,
    $10::UUID,$11::TIMESTAMPTZ,NULL::UUID,100)::TEXT`, ownerSessionArguments(session, workspaceID)...).Scan(&encoded); err != nil ||
		encoded == nil {
		t.Fatal("built-in Console projection unavailable", err)
	}
	var projection struct {
		Scopes []struct {
			Permissions []string `json:"permissions"`
		} `json:"scopes"`
	}
	if err := json.Unmarshal([]byte(*encoded), &projection); err != nil {
		t.Fatal(err)
	}
	if len(projection.Scopes) != networks {
		t.Fatalf("built-in Console projection Networks = %d, want %d", len(projection.Scopes), networks)
	}
	for _, scope := range projection.Scopes {
		if len(scope.Permissions) != permissions {
			t.Fatalf("built-in Console projection permissions = %v", scope.Permissions)
		}
	}
}
