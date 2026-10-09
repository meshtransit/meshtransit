//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

const (
	integrationManagementSessionPublicID    = "01890f00-0000-7000-8000-000000000812"
	integrationWorkspaceMembershipPublicID  = "01890f00-0000-7000-8000-000000000841"
	integrationRoleDefinitionPublicID       = "01890f00-0000-7000-8000-000000000842"
	integrationRolePermissionPublicID       = "01890f00-0000-7000-8000-000000000843"
	integrationPolicyPermissionPublicID     = "01890f00-0000-7000-8000-000000000846"
	integrationResourcePermissionPublicID   = "01890f00-0000-7000-8000-000000000847"
	integrationGroupPermissionPublicID      = "01890f00-0000-7000-8000-000000000848"
	integrationResourceReadPermissionID     = "01890f00-0000-7000-8000-000000000849"
	integrationGroupReadPermissionID        = "01890f00-0000-7000-8000-000000000850"
	integrationResourceTransferPermissionID = "01890f00-0000-7000-8000-000000000853"
	integrationGroupTransferPermissionID    = "01890f00-0000-7000-8000-000000000854"
	integrationPolicyExplainPermissionID    = "01890f00-0000-7000-8000-000000000855"
	integrationApproverRoleDefinitionID     = "01890f00-0000-7000-8000-000000000856"
	integrationPolicyApprovePermissionID    = "01890f00-0000-7000-8000-000000000857"
	integrationApproverTransferPermissionID = "01890f00-0000-7000-8000-000000000858"
	integrationPolicyValidatePermissionID   = "01890f00-0000-7000-8000-000000000859"
	integrationShareReadPermissionID        = "01890f00-0000-7000-8000-000000000860"
	integrationShareOfferPermissionID       = "01890f00-0000-7000-8000-000000000861"
	integrationShareAcceptPermissionID      = "01890f00-0000-7000-8000-000000000862"
	integrationShareRevokePermissionID      = "01890f00-0000-7000-8000-000000000863"
	integrationRoleBinding203PublicID       = "01890f00-0000-7000-8000-000000000844"
	integrationRoleBinding204PublicID       = "01890f00-0000-7000-8000-000000000845"
	integrationAuthorityConfirmerSessionID  = "01890f00-0000-7000-8000-000000000813"
	integrationAuthorityConfirmerID         = "01890f00-0000-7000-8000-000000000013"
	integrationAuthorityConfirmerSubjectID  = "01890f00-0000-7000-8000-000000000713"
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
	keyring, token, _ := integrationManagementAccountSessionSecurity(t)
	digests, err := keyring.Digests(token)
	if err != nil || len(digests) != 1 {
		t.Fatalf("derive management Account Session digest: %v", err)
	}
	tokenDigest := digests[0].Bytes()
	approverKeyring, approverToken, _ := integrationAuthorityConfirmerAccountSessionSecurity(t)
	approverDigests, err := approverKeyring.Digests(approverToken)
	if err != nil || len(approverDigests) != 1 {
		t.Fatalf("derive authority confirmer Account Session digest: %v", err)
	}
	approverTokenDigest := approverDigests[0].Bytes()
	touchKeyring, touchToken, _ := integrationActivityAccountSessionSecurity(t)
	touchDigests, err := touchKeyring.Digests(touchToken)
	if err != nil || len(touchDigests) != 1 {
		t.Fatal("derive activity Account Session digest", err)
	}
	touchTokenDigest := touchDigests[0].Bytes()
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
			name      string
			query     string
			arguments []any
		}{
			{
				name: "independent Workspace owner",
				query: `INSERT INTO mesh.principal (
    id, public_id, deployment_id, kind, state
) OVERRIDING SYSTEM VALUE VALUES (
    14, '01890f00-0000-7000-8000-000000000014', 1, 'account', 'active'
)`,
			},
			{
				// The management actors are members, so the existing negative
				// role tests continue to test delegated authority rather than owners.
				name: "member-only management fixture ownership",
				query: `UPDATE mesh.workspace SET owner_principal_id=14,
    authority_generation=authority_generation+1, version=version+1,
    updated_at=pg_catalog.transaction_timestamp() WHERE id IN (102,103)`,
			},
			{
				name: "authority confirmer Principal",
				query: `INSERT INTO mesh.principal (
    id, public_id, deployment_id, kind, state
) OVERRIDING SYSTEM VALUE VALUES (
    13, '01890f00-0000-7000-8000-000000000013', 1, 'account', 'active'
)`,
			},
			{
				name: "authority confirmer Account",
				query: `INSERT INTO mesh.account (
    id, public_id, deployment_id, principal_id, display_name,
    login_identifier_digest_algorithm, login_identifier_digest_key_id,
    login_identifier_digest, session_generation, recovery_state
) OVERRIDING SYSTEM VALUE VALUES (
    703, '01890f00-0000-7000-8000-000000000703', 1, 13, 'Authority Confirmer',
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('99', 32), 'hex'), 1, 'verified'
)`,
			},
			{
				name: "authority confirmer identity subject",
				query: `INSERT INTO mesh.identity_subject (
    id, public_id, deployment_id, identity_provider_id, principal_id,
    subject_digest_algorithm, subject_digest_key_id, subject_digest,
    claims_revision, last_seen_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    713, '01890f00-0000-7000-8000-000000000713', 1, 601, 13,
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('aa', 32), 'hex'),
    1, pg_catalog.transaction_timestamp(), 'active'
)`,
			},
			{
				name: "management Workspace identity provider",
				query: `INSERT INTO mesh.workspace_identity_provider (
    id, public_id, deployment_id, workspace_id, identity_provider_id,
    identity_provider_client_id, admission_mode, minimum_assurance,
    routing_priority, state
) OVERRIDING SYSTEM VALUE VALUES (
    633, '01890f00-0000-7000-8000-000000000633', 1, 103, 601, 621,
    'invitation_only', 'urn:meshtransit:assurance:mfa', 10, 'active'
)`,
			},
			{
				name: "authority confirmer Account Session",
				query: `INSERT INTO mesh.account_session (
    id, public_id, deployment_id, principal_id, identity_provider_id,
    identity_subject_id, identity_provider_client_id, login_workspace_id,
    token_digest_algorithm, token_digest_key_id, token_digest,
    provider_generation, authentication_time, acr, amr,
    principal_authority_generation, account_session_generation,
    deployment_recovery_epoch, issued_at, last_used_at, idle_expires_at,
    absolute_expires_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    813, '01890f00-0000-7000-8000-000000000813', 1, 13, 601, 713, 621, 103,
    'hmac-sha256-v1', 'integration-v1', $1::BYTEA, 1,
    pg_catalog.transaction_timestamp() - INTERVAL '1 minute',
    'urn:meshtransit:assurance:mfa', ARRAY['pwd', 'mfa'], 1, 1, 1,
    pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp(),
    pg_catalog.transaction_timestamp() + INTERVAL '30 minutes',
    pg_catalog.transaction_timestamp() + INTERVAL '8 hours', 'active'
)`,
				arguments: []any{approverTokenDigest[:]},
			},
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
    'hmac-sha256-v1', 'integration-v1', $1::BYTEA, 1,
    pg_catalog.transaction_timestamp() - INTERVAL '1 minute',
    'urn:meshtransit:assurance:mfa', ARRAY['pwd', 'mfa'], 1, 2, 1,
    pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp(),
    pg_catalog.transaction_timestamp() + INTERVAL '30 minutes',
    pg_catalog.transaction_timestamp() + INTERVAL '8 hours', 'active'
)`,
				arguments: []any{tokenDigest[:]},
			},
			{
				name: "activity Account Session",
				query: `INSERT INTO mesh.account_session (
    id, public_id, deployment_id, principal_id, identity_provider_id,
    identity_subject_id, identity_provider_client_id, login_workspace_id,
    token_digest_algorithm, token_digest_key_id, token_digest,
    provider_generation, authentication_time, acr, amr,
    principal_authority_generation, account_session_generation,
    deployment_recovery_epoch, issued_at, last_used_at, idle_expires_at,
    absolute_expires_at, state, created_at
) OVERRIDING SYSTEM VALUE VALUES (
    814, '01890f00-0000-7000-8000-000000000814', 1, 11, 601, 711, 621, 103,
    'hmac-sha256-v1', 'integration-v1', $1::BYTEA, 1,
    pg_catalog.transaction_timestamp() - INTERVAL '21 minutes',
    'urn:meshtransit:assurance:mfa', ARRAY['pwd', 'mfa'], 1, 2, 1,
    pg_catalog.transaction_timestamp() - INTERVAL '20 minutes',
    pg_catalog.transaction_timestamp() - INTERVAL '20 minutes',
    pg_catalog.transaction_timestamp() + INTERVAL '40 minutes',
    pg_catalog.transaction_timestamp() + INTERVAL '8 hours', 'active',
    pg_catalog.transaction_timestamp() - INTERVAL '20 minutes'
)`,
				arguments: []any{touchTokenDigest[:]},
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
				name: "Policy RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 846, $1::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'policy.publish'`,
				arguments: []any{integrationPolicyPermissionPublicID},
			},
			{
				name: "Resource RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 847, $1::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'resource.manage'`,
				arguments: []any{integrationResourcePermissionPublicID},
			},
			{
				name: "Resource Group RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 848, $1::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'resource_group.manage'`,
				arguments: []any{integrationGroupPermissionPublicID},
			},
			{
				name: "Resource Read RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 849, $1::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'resource.read'`,
				arguments: []any{integrationResourceReadPermissionID},
			},
			{
				name: "Resource Group Read RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 850, $1::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'resource_group.read'`,
				arguments: []any{integrationGroupReadPermissionID},
			},
			{
				name: "Resource Transfer RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 853, $1::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'resource.transfer'`,
				arguments: []any{integrationResourceTransferPermissionID},
			},
			{
				name: "Resource Group Transfer RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 854, $1::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'resource_group.transfer'`,
				arguments: []any{integrationGroupTransferPermissionID},
			},
			{
				name: "Policy Explain RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 855, $1::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'policy.explain'`,
				arguments: []any{integrationPolicyExplainPermissionID},
			},
			{
				name: "Policy Validate RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 859, $1::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'policy.validate'`,
				arguments: []any{integrationPolicyValidatePermissionID},
			},
			{
				name: "Share Read RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 860, $1::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'share.read'`,
				arguments: []any{integrationShareReadPermissionID},
			},
			{
				name: "Share Offer RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 861, $1::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'share.offer'`,
				arguments: []any{integrationShareOfferPermissionID},
			},
			{
				name: "Share Accept RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 862, $1::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'share.accept'`,
				arguments: []any{integrationShareAcceptPermissionID},
			},
			{
				name: "Share Revoke RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 863, $1::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'share.revoke'`,
				arguments: []any{integrationShareRevokePermissionID},
			},
			{
				name: "authority confirmer Workspace membership",
				query: `INSERT INTO mesh.workspace_membership (
    id, public_id, deployment_id, workspace_id, principal_id,
    state, authority_generation, valid_from
) OVERRIDING SYSTEM VALUE VALUES (
    851, '01890f00-0000-7000-8000-000000000851', 1, 103, 13,
    'active', 1, pg_catalog.transaction_timestamp() - INTERVAL '1 minute'
)`,
			},
			{
				name: "policy approver RoleDefinition",
				query: `INSERT INTO mesh.role_definition (
    id, public_id, deployment_id, workspace_id, role_key, display_name,
    kind, state, authority_generation
) OVERRIDING SYSTEM VALUE VALUES (
    856, $1::UUID, 1, 103,
    'policy_approver', 'Policy Approver', 'built_in', 'active', 1
)`,
				arguments: []any{integrationApproverRoleDefinitionID},
			},
			{
				name: "Policy Approve RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 857, $1::UUID, 1, 103, 856, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'policy.approve'`,
				arguments: []any{integrationPolicyApprovePermissionID},
			},
			{
				name: "policy approver Resource Transfer RolePermission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 858, $1::UUID, 1, 103, 856, permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key = 'resource.transfer'`,
				arguments: []any{integrationApproverTransferPermissionID},
			},
			{
				name: "authority confirmer Network 203 RoleBinding",
				query: `INSERT INTO mesh.role_binding (
    id, public_id, deployment_id, workspace_id, network_id, principal_id,
    workspace_membership_id, role_definition_id, state,
    authority_generation, valid_from
) OVERRIDING SYSTEM VALUE VALUES (
    852, '01890f00-0000-7000-8000-000000000852', 1, 103, 203, 13,
    851, 856, 'active', 1, pg_catalog.transaction_timestamp() - INTERVAL '1 minute'
)`,
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
			if _, err := transaction.Exec(ctx, statement.query, statement.arguments...); err != nil {
				t.Fatalf("insert integration %s: %v", statement.name, err)
			}
		}
	})
}

func integrationManagementAccountSessionSecurity(
	t *testing.T,
) (*accountsession.Keyring, accountsession.Token, string) {
	t.Helper()
	// #nosec G101 -- generated-format bearer fixture scoped to an ephemeral integration database.
	rawToken := "mtas1.01890f00-0000-7000-8000-000000000001.1.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"
	token, err := accountsession.ParseToken(rawToken)
	if err != nil {
		t.Fatalf("parse management Account Session token: %v", err)
	}
	keyID, err := accountsession.NewDigestKeyID("integration-v1")
	if err != nil {
		t.Fatalf("construct management Account Session key ID: %v", err)
	}
	key, err := accountsession.NewDigestKey(keyID, bytes.Repeat([]byte{0x77}, 32))
	if err != nil {
		t.Fatalf("construct management Account Session key: %v", err)
	}
	keyring, err := accountsession.NewKeyring(key)
	if err != nil {
		t.Fatalf("construct management Account Session keyring: %v", err)
	}
	return keyring, token, rawToken
}

func integrationActivityAccountSessionSecurity(
	t *testing.T,
) (*accountsession.Keyring, accountsession.Token, string) {
	t.Helper()
	rawToken := "mtas1.01890f00-0000-7000-8000-000000000001.1." +
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x03}, 32))
	token, err := accountsession.ParseToken(rawToken)
	if err != nil {
		t.Fatalf("parse activity Account Session token: %v", err)
	}
	keyID, err := accountsession.NewDigestKeyID("integration-v1")
	if err != nil {
		t.Fatal(err)
	}
	key, err := accountsession.NewDigestKey(keyID, bytes.Repeat([]byte{0x77}, 32))
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := accountsession.NewKeyring(key)
	if err != nil {
		t.Fatal(err)
	}
	return keyring, token, rawToken
}

func integrationAuthorityConfirmerAccountSessionSecurity(
	t *testing.T,
) (*accountsession.Keyring, accountsession.Token, string) {
	t.Helper()
	rawToken := "mtas1.01890f00-0000-7000-8000-000000000001.1." +
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x02}, 32))
	token, err := accountsession.ParseToken(rawToken)
	if err != nil {
		t.Fatalf("parse authority confirmer Account Session token: %v", err)
	}
	keyID, err := accountsession.NewDigestKeyID("integration-v1")
	if err != nil {
		t.Fatalf("construct authority confirmer Account Session key ID: %v", err)
	}
	key, err := accountsession.NewDigestKey(keyID, bytes.Repeat([]byte{0x77}, 32))
	if err != nil {
		t.Fatalf("construct authority confirmer Account Session key: %v", err)
	}
	keyring, err := accountsession.NewKeyring(key)
	if err != nil {
		t.Fatalf("construct authority confirmer Account Session keyring: %v", err)
	}
	return keyring, token, rawToken
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
		"device.manage":           1,
		"device.transfer":         0,
		"policy.publish":          1,
		"policy.approve":          0,
		"policy.validate":         1,
		"policy.explain":          1,
		"resource.manage":         1,
		"resource.read":           1,
		"resource_group.manage":   1,
		"resource_group.read":     1,
		"resource.transfer":       1,
		"resource_group.transfer": 1,
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
	for permission, expectedCount := range map[string]int64{
		"policy.approve":    1,
		"policy.publish":    0,
		"policy.validate":   0,
		"resource.transfer": 1,
	} {
		var count int64
		if err := transaction.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.resolve_network_permission_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    1, 1, 1, 1, 1, $5::UUID, $6::UUID, $7::TEXT,
    pg_catalog.transaction_timestamp()
)`,
			integrationAuthorityConfirmerSessionID,
			"01890f00-0000-7000-8000-000000000001",
			integrationAuthorityConfirmerID,
			integrationAuthorityConfirmerSubjectID,
			"01890f00-0000-7000-8000-000000000103",
			"01890f00-0000-7000-8000-000000000203",
			permission,
		).Scan(&count); err != nil {
			t.Fatalf("resolve authority confirmer %s permission: %v", permission, err)
		}
		if count != expectedCount {
			t.Fatalf(
				"resolved authority confirmer %s grants = %d, want %d",
				permission,
				count,
				expectedCount,
			)
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

func authorityConfirmerAccountSessionFixture(t *testing.T) accountsession.Session {
	t.Helper()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("parse authority confirmer Deployment: %v", err)
	}
	principalID, err := identity.ParsePrincipalID(integrationAuthorityConfirmerID)
	if err != nil {
		t.Fatalf("parse authority confirmer Principal: %v", err)
	}
	sessionID, err := accountsession.ParseID(integrationAuthorityConfirmerSessionID)
	if err != nil {
		t.Fatalf("parse authority confirmer Account Session: %v", err)
	}
	subjectID, err := accountsession.ParseIdentitySubjectID(
		integrationAuthorityConfirmerSubjectID,
	)
	if err != nil {
		t.Fatalf("parse authority confirmer identity subject: %v", err)
	}
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000103")
	if err != nil {
		t.Fatalf("parse authority confirmer Workspace: %v", err)
	}
	now := time.Now().UTC()
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID, LoginWorkspaceID: workspaceID,
		HasLoginWorkspace: true, AuthenticationTime: now.Add(-time.Minute),
		ACR: "urn:meshtransit:assurance:mfa", AMR: []string{"pwd", "mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(20 * time.Minute), AbsoluteExpiresAt: now.Add(7 * time.Hour),
	})
	if err != nil {
		t.Fatalf("construct authority confirmer Account Session: %v", err)
	}
	return session
}
