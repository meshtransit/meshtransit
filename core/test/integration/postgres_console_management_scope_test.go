//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/authorization"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/sessioncontext"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
)

func assertPostgreSQLConsoleManagementScopes(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	store := newIntegrationAccountSessionStore(t, runtimePool)
	service, err := sessioncontext.NewService(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal("construct Console management-scope service", err)
	}
	session := authorityConfirmerAccountSessionFixture(t)
	workspaceID, hasWorkspace := session.LoginWorkspaceID()
	if !hasWorkspace {
		t.Fatal("authority confirmer fixture lost its login Workspace")
	}
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal("begin Console management-scope RLS restoration transaction", err)
	}
	defer func() {
		if transaction != nil {
			_ = transaction.Rollback(ctx)
		}
	}()
	setIntegrationChange(ctx, t, transaction, "01890f00-0000-7000-8000-000000011000")
	inserted, err := transaction.Exec(ctx, `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT addition.id, addition.public_id::UUID, 1, 103, 856, permission.id
FROM (VALUES
    (11001, '01890f00-0000-7000-8000-000000011001', 'share.accept'),
    (11002, '01890f00-0000-7000-8000-000000011002', 'share.read'),
    (11003, '01890f00-0000-7000-8000-000000011003', 'device.read'),
    (11004, '01890f00-0000-7000-8000-000000011004', 'network.read'),
    (11005, '01890f00-0000-7000-8000-000000011005', 'policy.publish'),
    (11006, '01890f00-0000-7000-8000-000000011006', 'policy.validate')
) AS addition(id, public_id, permission_key)
JOIN mesh.permission AS permission
  ON permission.permission_key = addition.permission_key`)
	if err != nil || inserted.RowsAffected() != 6 {
		t.Fatal("seed temporary sharing scope permissions", err)
	}
	if _, err := transaction.Exec(ctx, `SELECT
    pg_catalog.set_config('mesh.requested_workspace_public_id', 'prior-requested', TRUE),
    pg_catalog.set_config(
        'mesh.console_management_scope_workspace_public_id',
        'prior-projection',
        TRUE
    )`); err != nil {
		t.Fatal("seed Console management-scope RLS settings", err)
	}
	var directProjection *string
	if err := transaction.QueryRow(ctx, `SELECT mesh_ops.read_console_management_scopes_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::TIMESTAMPTZ, NULL::UUID, 101
)::TEXT`,
		session.ID().String(),
		session.DeploymentID().String(),
		session.PrincipalID().String(),
		session.IdentitySubjectID().String(),
		session.Version(),
		session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(),
		session.ProviderGeneration(),
		session.DeploymentRecoveryEpoch(),
		workspaceID.String(),
		time.Now().UTC(),
	).Scan(&directProjection); err != nil || directProjection == nil {
		t.Fatal("direct Console management-scope function concealed seeded authority", err)
	}
	var projected struct {
		Scopes []struct {
			Permissions []string `json:"permissions"`
		} `json:"scopes"`
	}
	if err := json.Unmarshal([]byte(*directProjection), &projected); err != nil ||
		len(projected.Scopes) != 1 || !slices.Equal(projected.Scopes[0].Permissions,
		[]string{"device.read", "network.read", "policy.approve", "policy.publish", "policy.validate", "share.accept", "share.read"}) {
		t.Fatal("Console sharing scope projection lost canonical current permissions", err)
	}
	var requestedSetting, projectionSetting string
	if err := transaction.QueryRow(ctx, `SELECT
    pg_catalog.current_setting('mesh.requested_workspace_public_id', TRUE),
    pg_catalog.current_setting('mesh.console_management_scope_workspace_public_id', TRUE)`).Scan(
		&requestedSetting,
		&projectionSetting,
	); err != nil {
		t.Fatal("read restored Console management-scope RLS settings", err)
	}
	if requestedSetting != "prior-requested" || projectionSetting != "prior-projection" {
		t.Fatal("Console management-scope function leaked transaction-local RLS capability")
	}
	if err := transaction.Rollback(ctx); err != nil {
		t.Fatal("rollback Console management-scope RLS restoration transaction", err)
	}
	transaction = nil

	page, err := service.List(ctx, session, 100, network.ID{})
	if err != nil {
		t.Fatal("read Console management scopes", err)
	}
	items := page.Items()
	if len(items) != 1 {
		t.Fatalf("Console management-scope item count = %d, want 1", len(items))
	}
	permissions := items[0].Permissions()
	if page.WorkspaceID().String() != "01890f00-0000-7000-8000-000000000103" ||
		page.WorkspaceDisplayName() == "" ||
		items[0].NetworkID().String() != "01890f00-0000-7000-8000-000000000203" ||
		items[0].DisplayName() == "" || len(permissions) != 1 ||
		permissions[0] != authorization.PermissionPolicyApprove {
		t.Fatal("Console management-scope projection changed exact authority or identity")
	}
	if _, hasNext := page.Next(); hasNext {
		t.Fatal("single Console management-scope page exposed a false cursor")
	}

	page, err = service.List(ctx, managementRBACAccountSessionFixture(t), 100, network.ID{})
	if err != nil {
		t.Fatal("read sharing-only Console management scopes", err)
	}
	sharingItems := page.Items()
	sharingNetworkIDs := []string{
		"01890f00-0000-7000-8000-000000000203",
		"01890f00-0000-7000-8000-000000000204",
	}
	sharingPermissions := []authorization.Permission{
		authorization.PermissionPolicyPublish,
		authorization.PermissionPolicyValidate,
		authorization.PermissionShareAccept,
		authorization.PermissionShareOffer,
		authorization.PermissionShareRead,
		authorization.PermissionShareRevoke,
	}
	if len(sharingItems) != len(sharingNetworkIDs) {
		t.Fatalf("sharing-only Console scope count = %d, want %d", len(sharingItems), len(sharingNetworkIDs))
	}
	for index, item := range sharingItems {
		if item.NetworkID().String() != sharingNetworkIDs[index] ||
			!slices.Equal(item.Permissions(), sharingPermissions) {
			t.Fatalf("Console scope %s permissions=%v, expected %v", item.NetworkID(), item.Permissions(), sharingPermissions)
		}
	}

	var functionCount int
	var runtimeExecute, foreignExecute, publicExecute, securityDefiner, volatile bool
	if err := admin.QueryRow(ctx, `SELECT
    pg_catalog.count(*),
    pg_catalog.bool_and(pg_catalog.has_function_privilege(
        'mesh_runtime', procedure.oid, 'EXECUTE'
    )),
    pg_catalog.bool_or(
        pg_catalog.has_function_privilege('mesh_worker', procedure.oid, 'EXECUTE')
        OR pg_catalog.has_function_privilege('mesh_observer', procedure.oid, 'EXECUTE')
        OR pg_catalog.has_function_privilege('mesh_audit_writer', procedure.oid, 'EXECUTE')
        OR pg_catalog.has_function_privilege('mesh_share_writer', procedure.oid, 'EXECUTE')
    ),
    pg_catalog.bool_or(EXISTS (
        SELECT 1
        FROM pg_catalog.aclexplode(COALESCE(
            procedure.proacl,
            pg_catalog.acldefault('f', procedure.proowner)
        )) AS privilege
        WHERE privilege.grantee = 0
          AND privilege.privilege_type = 'EXECUTE'
    )),
    pg_catalog.bool_and(procedure.prosecdef),
    pg_catalog.bool_and(procedure.provolatile = 'v')
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
WHERE namespace.nspname = 'mesh_ops'
  AND procedure.proname = 'read_console_management_scopes_v1'`).Scan(
		&functionCount,
		&runtimeExecute,
		&foreignExecute,
		&publicExecute,
		&securityDefiner,
		&volatile,
	); err != nil {
		t.Fatal("query Console management-scope function privileges", err)
	}
	if functionCount != 1 || !runtimeExecute || foreignExecute || publicExecute ||
		!securityDefiner || !volatile {
		t.Fatalf(
			"Console scope function count=%d runtime=%t foreign=%t public=%t definer=%t volatile=%t",
			functionCount,
			runtimeExecute,
			foreignExecute,
			publicExecute,
			securityDefiner,
			volatile,
		)
	}
}

func assertPostgreSQLRevokedConsoleManagementScopes(
	ctx context.Context,
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	store := newIntegrationAccountSessionStore(t, runtimePool)
	service, err := sessioncontext.NewService(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal("construct revoked Console management-scope service", err)
	}
	_, err = service.List(ctx, managementRBACAccountSessionFixture(t), 100, network.ID{})
	if !errors.Is(err, sessioncontext.ErrUnauthenticated) {
		t.Fatal("revoked Account Session retained management-scope authority", err)
	}
}

func newIntegrationAccountSessionStore(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *postgresadapter.AccountSessionStore {
	t.Helper()
	store, err := postgresadapter.NewAccountSessionStore(
		runtimePool,
		postgresadapter.AccountSessionOptions{
			StatementTimeout: 5 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatal("construct integration Account Session store", err)
	}
	return store
}
