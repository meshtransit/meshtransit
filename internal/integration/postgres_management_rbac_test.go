//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const (
	integrationManagementSessionPublicID   = "01890f00-0000-7000-8000-000000000812"
	integrationWorkspaceMembershipPublicID = "01890f00-0000-7000-8000-000000000841"
	integrationRoleDefinitionPublicID      = "01890f00-0000-7000-8000-000000000842"
	integrationRolePermissionPublicID      = "01890f00-0000-7000-8000-000000000843"
	integrationRoleBinding203PublicID      = "01890f00-0000-7000-8000-000000000844"
	integrationRoleBinding204PublicID      = "01890f00-0000-7000-8000-000000000845"
)

func assertNetworkManagementRBACAuthority(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
) {
	t.Helper()

	seedNetworkManagementRBACAuthority(ctx, t, adminConnection)
	assertNetworkManagementRBACRows(ctx, t, adminConnection)
	assertNetworkManagementRBACPrivileges(ctx, t, adminConnection)
	assertNetworkManagementPermissionResolution(ctx, t, runtimeConnection)
}

func assertNetworkManagementRBACRows(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()
	var sessionCount, grantCount, exactCount int64
	if err := connection.QueryRow(ctx, `SELECT
    (
        SELECT pg_catalog.count(*)
        FROM mesh.account_session AS session
        JOIN mesh.deployment AS deployment ON deployment.id = session.deployment_id
        JOIN mesh.principal AS principal
          ON principal.deployment_id = session.deployment_id
         AND principal.id = session.principal_id
        JOIN mesh.account AS account
          ON account.deployment_id = session.deployment_id
         AND account.principal_id = session.principal_id
        JOIN mesh.identity_subject AS subject
          ON subject.deployment_id = session.deployment_id
         AND subject.identity_provider_id = session.identity_provider_id
         AND subject.principal_id = session.principal_id
         AND subject.id = session.identity_subject_id
        JOIN mesh.identity_provider AS provider
          ON provider.deployment_id = session.deployment_id
         AND provider.id = session.identity_provider_id
        JOIN mesh.identity_provider_client AS client
          ON client.deployment_id = session.deployment_id
         AND client.identity_provider_id = session.identity_provider_id
         AND client.id = session.identity_provider_client_id
        WHERE session.public_id = $1::UUID
          AND session.state = 'active'
          AND deployment.state = 'active'
          AND deployment.recovery_state = 'verified'
          AND principal.state = 'active'
          AND principal.authority_generation = session.principal_authority_generation
          AND account.recovery_state = 'verified'
          AND account.session_generation = session.account_session_generation
          AND subject.state = 'active'
          AND provider.state = 'active'
          AND provider.recovery_state = 'verified'
          AND provider.current_generation = session.provider_generation
          AND client.state = 'active'
    ),
    (
        SELECT pg_catalog.count(*)
        FROM mesh.workspace_membership AS membership
        JOIN mesh.role_binding AS binding
          ON binding.deployment_id = membership.deployment_id
         AND binding.workspace_id = membership.workspace_id
         AND binding.principal_id = membership.principal_id
         AND binding.workspace_membership_id = membership.id
        JOIN mesh.role_definition AS role_definition
          ON role_definition.deployment_id = binding.deployment_id
         AND role_definition.workspace_id = binding.workspace_id
         AND role_definition.id = binding.role_definition_id
        JOIN mesh.role_permission AS role_permission
          ON role_permission.deployment_id = role_definition.deployment_id
         AND role_permission.workspace_id = role_definition.workspace_id
         AND role_permission.role_definition_id = role_definition.id
        JOIN mesh.permission AS permission ON permission.id = role_permission.permission_id
        WHERE membership.public_id = $2::UUID
          AND binding.public_id = $3::UUID
          AND role_definition.public_id = $4::UUID
          AND membership.state = 'active'
          AND binding.state = 'active'
          AND role_definition.state = 'active'
          AND permission.permission_key = 'device.manage'
    ),
    (
        SELECT pg_catalog.count(*)
        FROM mesh.account_session AS session
        JOIN mesh.deployment AS deployment ON deployment.id = session.deployment_id
        JOIN mesh.principal AS principal
          ON principal.deployment_id = session.deployment_id AND principal.id = session.principal_id
        JOIN mesh.account AS account
          ON account.deployment_id = session.deployment_id AND account.principal_id = session.principal_id
        JOIN mesh.identity_subject AS subject
          ON subject.deployment_id = session.deployment_id
         AND subject.identity_provider_id = session.identity_provider_id
         AND subject.principal_id = session.principal_id AND subject.id = session.identity_subject_id
        JOIN mesh.identity_provider AS provider
          ON provider.deployment_id = session.deployment_id AND provider.id = session.identity_provider_id
        JOIN mesh.identity_provider_client AS client
          ON client.deployment_id = session.deployment_id
         AND client.identity_provider_id = session.identity_provider_id
         AND client.id = session.identity_provider_client_id
        JOIN mesh.workspace AS workspace
          ON workspace.deployment_id = session.deployment_id AND workspace.id = 103
        JOIN mesh.network AS network ON network.workspace_id = workspace.id AND network.id = 203
        JOIN mesh.workspace_membership AS membership
          ON membership.deployment_id = session.deployment_id
         AND membership.workspace_id = workspace.id AND membership.principal_id = session.principal_id
        JOIN mesh.role_binding AS binding
          ON binding.deployment_id = session.deployment_id
         AND binding.workspace_id = workspace.id AND binding.network_id = network.id
         AND binding.principal_id = session.principal_id
         AND binding.workspace_membership_id = membership.id
        JOIN mesh.role_definition AS role_definition
          ON role_definition.deployment_id = session.deployment_id
         AND role_definition.workspace_id = workspace.id
         AND role_definition.id = binding.role_definition_id
        JOIN mesh.role_permission AS role_permission
          ON role_permission.deployment_id = session.deployment_id
         AND role_permission.workspace_id = workspace.id
         AND role_permission.role_definition_id = role_definition.id
        JOIN mesh.permission AS permission
          ON permission.id = role_permission.permission_id
         AND permission.permission_key = 'device.manage'
         AND 'network' = ANY(permission.allowed_scope_kinds)
        WHERE session.public_id = $1::UUID
          AND deployment.installation_public_id = '01890f00-0000-7000-8000-000000000001'
          AND principal.public_id = '01890f00-0000-7000-8000-000000000011'
          AND subject.public_id = '01890f00-0000-7000-8000-000000000711'
          AND session.version = 1
          AND session.principal_authority_generation = 1
          AND session.account_session_generation = 2
          AND session.provider_generation = 1
          AND session.deployment_recovery_epoch = 1
          AND session.state = 'active'
          AND session.authentication_time <= pg_catalog.transaction_timestamp()
          AND session.idle_expires_at > pg_catalog.transaction_timestamp()
          AND session.absolute_expires_at > pg_catalog.transaction_timestamp()
          AND deployment.state = 'active' AND deployment.recovery_state = 'verified'
          AND deployment.recovery_epoch = 1
          AND principal.state = 'active' AND principal.authority_generation = 1
          AND account.recovery_state = 'verified' AND account.session_generation = 2
          AND subject.state = 'active'
          AND provider.state = 'active' AND provider.recovery_state = 'verified'
          AND provider.current_generation = 1 AND client.state = 'active'
          AND workspace.state = 'active' AND network.state = 'active'
          AND membership.state = 'active'
          AND membership.valid_from <= pg_catalog.transaction_timestamp()
          AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
          AND binding.state = 'active'
          AND binding.valid_from <= pg_catalog.transaction_timestamp()
          AND (binding.expires_at IS NULL OR binding.expires_at > pg_catalog.transaction_timestamp())
          AND role_definition.state = 'active'
    )`,
		integrationManagementSessionPublicID,
		integrationWorkspaceMembershipPublicID,
		integrationRoleBinding203PublicID,
		integrationRoleDefinitionPublicID,
	).Scan(&sessionCount, &grantCount, &exactCount); err != nil {
		t.Fatalf("query management RBAC rows: %v", err)
	}
	if sessionCount != 1 || grantCount != 1 || exactCount != 1 {
		t.Fatalf(
			"management RBAC session/grant/exact rows = %d/%d/%d, want 1/1/1",
			sessionCount,
			grantCount,
			exactCount,
		)
	}
}

func seedNetworkManagementRBACAuthority(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()
	var networkRevision int64
	if err := connection.QueryRow(ctx, `SELECT network_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 203`).Scan(&networkRevision); err != nil {
		t.Fatalf("query RBAC fixture Network revision: %v", err)
	}
	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         "01890f01-0000-7000-8000-000000000841",
		eventPublicID:          "01890f02-0000-7000-8000-000000000841",
		outboxPublicID:         "01890f03-0000-7000-8000-000000000841",
		streamID:               203,
		aggregateKind:          "role_binding",
		aggregatePublicID:      integrationRoleBinding203PublicID,
		aggregateVersion:       1,
		networkRevision:        networkRevision,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "management_rbac.seeded",
		permission:             "system.bootstrap",
		outboxEventClass:       "management_rbac.seeded",
	}, func(transaction pgx.Tx) {
		statements := []struct {
			name  string
			query string
		}{
			{
				name: "management Account Session",
				query: `INSERT INTO mesh.account_session (
    id, public_id, deployment_id, principal_id, identity_provider_id,
    identity_subject_id, identity_provider_client_id, login_workspace_id,
    token_digest_algorithm, token_digest_key_id, token_digest,
    provider_generation, authentication_time, acr, amr,
    principal_authority_generation, account_session_generation,
    deployment_recovery_epoch, issued_at, last_used_at, idle_expires_at,
    absolute_expires_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    812, '01890f00-0000-7000-8000-000000000812', 1, 11, 601, 711, 621, 103,
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('ad', 32), 'hex'), 1,
    pg_catalog.transaction_timestamp() - INTERVAL '1 minute',
    'urn:meshtransit:assurance:mfa', ARRAY['pwd', 'mfa'], 1, 2, 1,
    pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp(),
    pg_catalog.transaction_timestamp() + INTERVAL '30 minutes',
    pg_catalog.transaction_timestamp() + INTERVAL '8 hours', 'active'
)`,
			},
			{
				name: "Workspace membership",
				query: `INSERT INTO mesh.workspace_membership (
    id, public_id, deployment_id, workspace_id, principal_id,
    state, authority_generation, valid_from
) OVERRIDING SYSTEM VALUE VALUES (
    841, '01890f00-0000-7000-8000-000000000841', 1, 103, 11,
    'active', 1, pg_catalog.transaction_timestamp() - INTERVAL '1 minute'
)`,
			},
			{
				name: "RoleDefinition",
				query: `INSERT INTO mesh.role_definition (
    id, public_id, deployment_id, workspace_id, role_key, display_name,
    kind, state, authority_generation
) OVERRIDING SYSTEM VALUE VALUES (
    842, '01890f00-0000-7000-8000-000000000842', 1, 103,
    'device_admin', 'Device Administrator', 'built_in', 'active', 1
)`,
			},
			{
				name: "RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 843, '01890f00-0000-7000-8000-000000000843', 1, 103, 842, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'device.manage'`,
			},
			{
				name: "Network 203 RoleBinding",
				query: `INSERT INTO mesh.role_binding (
    id, public_id, deployment_id, workspace_id, network_id, principal_id,
    workspace_membership_id, role_definition_id, state,
    authority_generation, valid_from
) OVERRIDING SYSTEM VALUE VALUES (
    844, '01890f00-0000-7000-8000-000000000844', 1, 103, 203, 11,
    841, 842, 'active', 1, pg_catalog.transaction_timestamp() - INTERVAL '1 minute'
)`,
			},
			{
				name: "Network 204 RoleBinding",
				query: `INSERT INTO mesh.role_binding (
    id, public_id, deployment_id, workspace_id, network_id, principal_id,
    workspace_membership_id, role_definition_id, state,
    authority_generation, valid_from
) OVERRIDING SYSTEM VALUE VALUES (
    845, '01890f00-0000-7000-8000-000000000845', 1, 103, 204, 11,
    841, 842, 'active', 1, pg_catalog.transaction_timestamp() - INTERVAL '1 minute'
)`,
			},
		}
		for _, statement := range statements {
			if _, err := transaction.Exec(ctx, statement.query); err != nil {
				t.Fatalf("insert integration %s: %v", statement.name, err)
			}
		}
	})
}

func assertNetworkManagementRBACPrivileges(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
) {
	t.Helper()
	var runtimeCanResolve, workerCanResolve, runtimeHasTableAccess bool
	if err := adminConnection.QueryRow(ctx, `SELECT
    pg_catalog.has_function_privilege(
        'mesh_runtime',
        'mesh_ops.resolve_network_permission_v1(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,uuid,uuid,text,timestamptz)',
        'EXECUTE'
    ),
    pg_catalog.has_function_privilege(
        'mesh_worker',
        'mesh_ops.resolve_network_permission_v1(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,uuid,uuid,text,timestamptz)',
        'EXECUTE'
    ),
    COALESCE(pg_catalog.bool_or(
        pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'SELECT')
        OR pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'INSERT')
        OR pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'UPDATE')
        OR pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'DELETE')
    ), FALSE)
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = 'mesh'
  AND relation.relname IN (
      'workspace_membership', 'role_definition', 'role_permission', 'role_binding'
  )`).Scan(&runtimeCanResolve, &workerCanResolve, &runtimeHasTableAccess); err != nil {
		t.Fatalf("query management RBAC privileges: %v", err)
	}
	if !runtimeCanResolve || workerCanResolve || runtimeHasTableAccess {
		t.Fatalf(
			"management RBAC privileges runtime-resolve=%t worker-resolve=%t runtime-table=%t",
			runtimeCanResolve,
			workerCanResolve,
			runtimeHasTableAccess,
		)
	}
}

func assertNetworkManagementPermissionResolution(
	ctx context.Context,
	t *testing.T,
	runtimeConnection *pgx.Conn,
) {
	t.Helper()
	transaction, err := runtimeConnection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin management RBAC resolution transaction: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, transaction)
	if _, err := transaction.Exec(ctx, `SELECT * FROM mesh_ops.set_network_scope(
    '01890f00-0000-7000-8000-000000000103',
    '01890f00-0000-7000-8000-000000000203'
)`); err != nil {
		t.Fatalf("set management RBAC Network scope: %v", err)
	}
	for permission, expectedCount := range map[string]int64{
		"device.manage":   1,
		"device.transfer": 0,
	} {
		var count int64
		if err := transaction.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.resolve_network_permission_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    1, 1, 2, 1, 1, $5::UUID, $6::UUID, $7::TEXT,
    pg_catalog.transaction_timestamp()
)`,
			integrationManagementSessionPublicID,
			"01890f00-0000-7000-8000-000000000001",
			"01890f00-0000-7000-8000-000000000011",
			integrationIdentitySubjectPublicID,
			"01890f00-0000-7000-8000-000000000103",
			"01890f00-0000-7000-8000-000000000203",
			permission,
		).Scan(&count); err != nil {
			t.Fatalf("resolve %s permission: %v", permission, err)
		}
		if count != expectedCount {
			t.Fatalf("resolved %s grants = %d, want %d", permission, count, expectedCount)
		}
	}
	if err := transaction.Rollback(ctx); err != nil {
		t.Fatalf("rollback management RBAC resolution transaction: %v", err)
	}
}

func managementRBACAccountSessionFixture(t *testing.T) accountsession.Session {
	t.Helper()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("parse management Deployment: %v", err)
	}
	principalID, err := identity.ParsePrincipalID(
		"01890f00-0000-7000-8000-000000000011",
	)
	if err != nil {
		t.Fatalf("parse management Principal: %v", err)
	}
	sessionID, err := accountsession.ParseID(integrationManagementSessionPublicID)
	if err != nil {
		t.Fatalf("parse management Account Session: %v", err)
	}
	subjectID, err := accountsession.ParseIdentitySubjectID(integrationIdentitySubjectPublicID)
	if err != nil {
		t.Fatalf("parse management identity subject: %v", err)
	}
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000103")
	if err != nil {
		t.Fatalf("parse management Workspace: %v", err)
	}
	now := time.Now().UTC()
	session, err := accountsession.NewSession(accountsession.Params{
		ID:                           sessionID,
		DeploymentID:                 deploymentID,
		PrincipalID:                  principalID,
		IdentitySubjectID:            subjectID,
		LoginWorkspaceID:             workspaceID,
		HasLoginWorkspace:            true,
		AuthenticationTime:           now.Add(-time.Minute),
		ACR:                          "urn:meshtransit:assurance:mfa",
		AMR:                          []string{"pwd", "mfa"},
		Version:                      1,
		PrincipalAuthorityGeneration: 1,
		AccountSessionGeneration:     2,
		ProviderGeneration:           1,
		DeploymentRecoveryEpoch:      1,
		IdleExpiresAt:                now.Add(20 * time.Minute),
		AbsoluteExpiresAt:            now.Add(7 * time.Hour),
	})
	if err != nil {
		t.Fatalf("construct management Account Session: %v", err)
	}
	return session
}
