//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/resource"
	authority "github.com/meshtransit/meshtransit/internal/resource/authority"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func assertPostgreSQLResourceAuthority(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	workerConnection *pgx.Conn,
) {
	t.Helper()
	service := newIntegrationResourceAuthorityService(t, runtimePool)
	session := managementRBACAccountSessionFixture(t)
	scope203 := resourceAuthorityScope(t, 103, 203)
	actorID := session.PrincipalID()
	device930 := resourceAuthorityNodeID(t, 930)
	inventory203, group203 := resourceAuthorityRevisions(ctx, t, adminConnection, 103, 203)

	deviceDefinition := resourceAuthorityDeviceDefinition(
		t, scope203, actorID, device930, "Production database 01",
	)
	reason := resourceAuthorityReason(t, "create first Device Resource")
	deviceCommand, err := authority.NewCreateDeviceCommand(
		deviceDefinition, inventory203, session, reason,
	)
	if err != nil {
		t.Fatalf("construct Device Resource command: %v", err)
	}
	deviceResult, err := service.Create(ctx, deviceCommand)
	if err != nil {
		t.Fatalf("create Device Resource: %v", err)
	}
	if deviceResult.Operation() != authority.OperationCreateDevice ||
		deviceResult.SubsystemRevision() != inventory203+1 || deviceResult.Version() != 1 {
		t.Fatalf("Device Resource result = %+v", deviceResult)
	}
	assertCommittedDeviceResource(ctx, t, adminConnection, deviceCommand, deviceResult)

	staleDefinition := resourceAuthorityDeviceDefinition(
		t, scope203, actorID, resourceAuthorityNodeID(t, 910), "Stale Resource",
	)
	staleCommand, err := authority.NewCreateDeviceCommand(
		staleDefinition, inventory203, session, reason,
	)
	if err != nil {
		t.Fatalf("construct stale Resource command: %v", err)
	}
	if _, err := service.Create(ctx, staleCommand); !errors.Is(err, authority.ErrConflict) {
		t.Fatalf("stale Resource creation error = %v, want ErrConflict", err)
	}

	reference, err := resource.NewReference(scope203, deviceResult.ResourceID(), 1, 1)
	if err != nil {
		t.Fatalf("construct Resource reference: %v", err)
	}
	groupDefinition := resourceAuthorityGroupDefinition(
		t, scope203, actorID, "Production databases", []resource.Reference{reference},
	)
	groupCommand, err := authority.NewCreateGroupCommand(
		groupDefinition, group203, session,
		resourceAuthorityReason(t, "create first destination Resource Group"),
	)
	if err != nil {
		t.Fatalf("construct Resource Group command: %v", err)
	}
	groupResult, err := service.Create(ctx, groupCommand)
	if err != nil {
		t.Fatalf("create Resource Group: %v", err)
	}
	if groupResult.Operation() != authority.OperationCreateGroup ||
		groupResult.SubsystemRevision() != group203+1 || groupResult.Version() != 1 {
		t.Fatalf("Resource Group result = %+v", groupResult)
	}
	assertCommittedResourceGroup(ctx, t, adminConnection, groupCommand, groupResult)

	staleReference, err := resource.NewReference(scope203, deviceResult.ResourceID(), 1, 2)
	if err != nil {
		t.Fatalf("construct stale target-generation reference: %v", err)
	}
	staleGroup := resourceAuthorityGroupDefinition(
		t, scope203, actorID, "Stale generation", []resource.Reference{staleReference},
	)
	staleGroupCommand, err := authority.NewCreateGroupCommand(
		staleGroup, group203+1, session, resourceAuthorityReason(t, "reject stale generation"),
	)
	if err != nil {
		t.Fatalf("construct stale Resource Group command: %v", err)
	}
	if _, err := service.Create(ctx, staleGroupCommand); !errors.Is(err, authority.ErrConflict) {
		t.Fatalf("stale target generation error = %v, want ErrConflict", err)
	}

	scope204 := resourceAuthorityScope(t, 103, 204)
	_, group204 := resourceAuthorityRevisions(ctx, t, adminConnection, 103, 204)
	crossScopeReference, err := resource.NewReference(
		scope204, deviceResult.ResourceID(), 1, 1,
	)
	if err != nil {
		t.Fatalf("construct opaque cross-scope reference: %v", err)
	}
	crossScopeGroup := resourceAuthorityGroupDefinition(
		t, scope204, actorID, "Cross scope", []resource.Reference{crossScopeReference},
	)
	crossScopeCommand, err := authority.NewCreateGroupCommand(
		crossScopeGroup, group204, session, resourceAuthorityReason(t, "reject cross-scope member"),
	)
	if err != nil {
		t.Fatalf("construct cross-scope group command: %v", err)
	}
	if _, err := service.Create(ctx, crossScopeCommand); !errors.Is(err, authority.ErrConflict) {
		t.Fatalf("cross-scope Resource Group error = %v, want ErrConflict", err)
	}

	scope202 := resourceAuthorityScope(t, 102, 202)
	inventory202, _ := resourceAuthorityRevisions(ctx, t, adminConnection, 102, 202)
	unauthorizedDefinition := resourceAuthorityDeviceDefinition(
		t, scope202, actorID, device930, "Unauthorized Resource",
	)
	unauthorizedCommand, err := authority.NewCreateDeviceCommand(
		unauthorizedDefinition, inventory202, session,
		resourceAuthorityReason(t, "reject missing Workspace membership"),
	)
	if err != nil {
		t.Fatalf("construct unauthorized Resource command: %v", err)
	}
	if _, err := service.Create(ctx, unauthorizedCommand); !errors.Is(err, authority.ErrForbidden) {
		t.Fatalf("unauthorized Resource error = %v, want ErrForbidden", err)
	}

	assertResourceAuthorityEvidenceAtomicity(ctx, t, adminConnection, runtimeConnection)
	assertResourceAuthorityPrivilegeContract(ctx, t, adminConnection, runtimeConnection, workerConnection)
}

func newIntegrationResourceAuthorityService(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *authority.Service {
	t.Helper()
	store, err := postgresadapter.NewResourceAuthorityStore(
		runtimePool,
		postgresadapter.ResourceAuthorityOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewResourceAuthorityStore() error = %v", err)
	}
	retry, err := authority.NewExponentialBackoff(time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("authority.NewExponentialBackoff() error = %v", err)
	}
	service, err := authority.NewService(
		authority.Options{MaxAttempts: 3, RollbackTimeout: 2 * time.Second},
		authority.Dependencies{
			Transactions: store, CommittedResults: store,
			MutationIDs: authority.PublicMutationIDGenerator{},
			Clock:       authority.SystemClock{}, Retry: retry,
		},
	)
	if err != nil {
		t.Fatalf("authority.NewService() error = %v", err)
	}
	return service
}

func assertCommittedDeviceResource(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	command authority.Command,
	result authority.Result,
) {
	t.Helper()
	var resourceCount, targetCount, auditCount, outboxCount int
	hash := command.SemanticHash().Bytes()
	if err := connection.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource
     WHERE public_id = $1::UUID AND workspace_id = 103 AND network_id = 203
       AND version = 1 AND target_generation = 1 AND state = 'active'
       AND activated_network_revision = $2 AND inventory_revision = $3
       AND semantic_hash = $4::BYTEA),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_device_target AS target
     JOIN mesh.resource AS resource ON resource.id = target.resource_id
     WHERE resource.public_id = $1::UUID AND target.state = 'active'
       AND target.target_generation = 1 AND target.version = 1),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_audit.audit_event
     WHERE target_kind = 'resource' AND target_public_id = $1::UUID
       AND action = 'resource.created' AND permission = 'resource.manage'
       AND payload ->> 'account_session_id' = $5),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_ops.outbox_event
     WHERE aggregate_kind = 'resource' AND aggregate_public_id = $1::UUID
       AND aggregate_version = 1 AND network_revision = $2
       AND event_class = 'network.revision.advanced')`,
		result.ResourceID().String(),
		result.NetworkRevision(),
		result.SubsystemRevision(),
		hash[:],
		integrationManagementSessionPublicID,
	).Scan(&resourceCount, &targetCount, &auditCount, &outboxCount); err != nil {
		t.Fatalf("query committed Device Resource: %v", err)
	}
	if resourceCount != 1 || targetCount != 1 || auditCount != 1 || outboxCount != 1 {
		t.Fatalf(
			"Device Resource evidence resource/target/audit/outbox = %d/%d/%d/%d",
			resourceCount, targetCount, auditCount, outboxCount,
		)
	}
}

func assertCommittedResourceGroup(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	command authority.Command,
	result authority.Result,
) {
	t.Helper()
	var groupCount, versionCount, memberCount, auditCount, outboxCount int
	hash := command.SemanticHash().Bytes()
	if err := connection.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_group
     WHERE public_id = $1::UUID AND workspace_id = 103 AND network_id = 203
       AND version = 1 AND active_definition_version = 1 AND state = 'active'
       AND activated_network_revision = $2 AND group_revision = $3
       AND semantic_hash = $4::BYTEA),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_group_version AS version
     JOIN mesh.resource_group AS resource_group ON resource_group.id = version.resource_group_id
     WHERE resource_group.public_id = $1::UUID AND version.definition_version = 1
       AND version.member_count = 1 AND version.semantic_hash = $4::BYTEA),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh.resource_group_version_member AS member
     JOIN mesh.resource_group AS resource_group ON resource_group.id = member.resource_group_id
     WHERE resource_group.public_id = $1::UUID AND member.resource_version = 1
       AND member.target_generation = 1),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_audit.audit_event
     WHERE target_kind = 'resource_group' AND target_public_id = $1::UUID
       AND action = 'resource_group.created' AND permission = 'resource_group.manage'),
    (SELECT pg_catalog.count(*)::INTEGER FROM mesh_ops.outbox_event
     WHERE aggregate_kind = 'resource_group' AND aggregate_public_id = $1::UUID
       AND aggregate_version = 1 AND network_revision = $2
       AND event_class = 'network.revision.advanced')`,
		result.GroupID().String(), result.NetworkRevision(), result.SubsystemRevision(), hash[:],
	).Scan(&groupCount, &versionCount, &memberCount, &auditCount, &outboxCount); err != nil {
		t.Fatalf("query committed Resource Group: %v", err)
	}
	if groupCount != 1 || versionCount != 1 || memberCount != 1 ||
		auditCount != 1 || outboxCount != 1 {
		t.Fatalf(
			"Resource Group evidence group/version/member/audit/outbox = %d/%d/%d/%d/%d",
			groupCount, versionCount, memberCount, auditCount, outboxCount,
		)
	}
}

func assertResourceAuthorityEvidenceAtomicity(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
) {
	t.Helper()
	inventoryRevision, _ := resourceAuthorityRevisions(ctx, t, adminConnection, 103, 203)
	transaction, err := runtimeConnection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin incomplete Resource authority transaction: %v", err)
	}
	if _, err := transaction.Exec(ctx, `SELECT * FROM mesh_ops.set_network_scope(
    '01890f00-0000-7000-8000-000000000103',
    '01890f00-0000-7000-8000-000000000203'
)`); err != nil {
		t.Fatalf("set incomplete Resource authority scope: %v", err)
	}
	if _, err := transaction.Exec(ctx, `SELECT pg_catalog.set_config(
    'mesh.change_public_id', '01890f70-0000-7000-8000-000000000003', TRUE
)`); err != nil {
		t.Fatalf("set incomplete Resource authority change: %v", err)
	}
	if _, err := transaction.Exec(ctx, `SELECT * FROM mesh_ops.create_device_resource_v1(
    '01890f70-0000-7000-8000-000000000001',
    '01890f70-0000-7000-8000-000000000002',
    $1::BIGINT,
    '01890f31-0000-7000-8000-000000000910',
    '01890f00-0000-7000-8000-000000000011',
    'Incomplete evidence',
    pg_catalog.decode(pg_catalog.repeat('01', 32), 'hex'),
    pg_catalog.transaction_timestamp()
)`, inventoryRevision); err != nil {
		t.Fatalf("apply incomplete Resource authority: %v", err)
	}
	if err := transaction.Commit(ctx); err == nil {
		t.Fatal("incomplete Resource authority commit error = nil")
	}
	var count int
	if err := adminConnection.QueryRow(ctx, `SELECT pg_catalog.count(*)::INTEGER
FROM mesh.resource
WHERE public_id = '01890f70-0000-7000-8000-000000000001'`).Scan(&count); err != nil {
		t.Fatalf("query incomplete Resource rollback: %v", err)
	}
	if count != 0 {
		t.Fatalf("incomplete Resource count = %d, want 0", count)
	}
}

func assertResourceAuthorityPrivilegeContract(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
	workerConnection *pgx.Conn,
) {
	t.Helper()
	var runtimeCreate, workerCreate, runtimeTableAccess bool
	if err := adminConnection.QueryRow(ctx, `SELECT
    pg_catalog.has_function_privilege(
        'mesh_runtime',
        'mesh_ops.create_device_resource_v1(uuid,uuid,bigint,uuid,uuid,text,bytea,timestamptz)',
        'EXECUTE'
    ),
    pg_catalog.has_function_privilege(
        'mesh_worker',
        'mesh_ops.create_device_resource_v1(uuid,uuid,bigint,uuid,uuid,text,bytea,timestamptz)',
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
      'resource', 'resource_device_target', 'resource_group',
      'resource_group_version', 'resource_group_version_member'
  )`).Scan(&runtimeCreate, &workerCreate, &runtimeTableAccess); err != nil {
		t.Fatalf("query Resource authority privileges: %v", err)
	}
	if !runtimeCreate || workerCreate || runtimeTableAccess {
		t.Fatalf(
			"Resource privileges runtime-create=%t worker-create=%t runtime-table=%t",
			runtimeCreate, workerCreate, runtimeTableAccess,
		)
	}
	if err := runtimeConnection.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.resource`).Scan(new(int64)); err == nil {
		t.Fatal("runtime direct Resource table read unexpectedly succeeded")
	}
	if err := workerConnection.QueryRow(ctx, `SELECT * FROM mesh_ops.resolve_resource_v1(
    '01890f70-0000-7000-8000-000000000001'
)`).Scan(new(string)); err == nil {
		t.Fatal("worker Resource resolver execution unexpectedly succeeded")
	}
}

func resourceAuthorityRevisions(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	workspaceID, networkID int64,
) (int64, int64) {
	t.Helper()
	var inventoryRevision, groupRevision int64
	if err := connection.QueryRow(ctx, `SELECT inventory_revision, group_revision
FROM mesh_ops.network_revision
WHERE workspace_id = $1 AND network_id = $2`, workspaceID, networkID).Scan(
		&inventoryRevision, &groupRevision,
	); err != nil {
		t.Fatalf("query Resource authority revisions: %v", err)
	}
	return inventoryRevision, groupRevision
}

func resourceAuthorityScope(t *testing.T, workspaceSuffix, networkSuffix int) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID(integrationPublicID("01890f00-0000-7000-8000-", int64(workspaceSuffix)))
	if err != nil {
		t.Fatalf("parse Resource authority Workspace: %v", err)
	}
	networkID, err := network.ParseID(integrationPublicID("01890f00-0000-7000-8000-", int64(networkSuffix)))
	if err != nil {
		t.Fatalf("parse Resource authority Network: %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("construct Resource authority scope: %v", err)
	}
	return scope
}

func resourceAuthorityNodeID(t *testing.T, suffix int) node.ID {
	t.Helper()
	id, err := node.ParseID(integrationPublicID("01890f31-0000-7000-8000-", int64(suffix)))
	if err != nil {
		t.Fatalf("parse Resource authority Device: %v", err)
	}
	return id
}

func resourceAuthorityDeviceDefinition(
	t *testing.T,
	scope network.Scope,
	actorID identity.PrincipalID,
	deviceID node.ID,
	displayName string,
) resource.DeviceDefinition {
	t.Helper()
	name, err := resource.ParseDisplayName(displayName)
	if err != nil {
		t.Fatalf("parse Resource display name: %v", err)
	}
	definition, err := resource.NewDeviceDefinition(resource.DeviceDefinitionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: actorID,
		CustodianPrincipalID: actorID, DeviceID: deviceID,
	})
	if err != nil {
		t.Fatalf("construct Device Resource definition: %v", err)
	}
	return definition
}

func resourceAuthorityGroupDefinition(
	t *testing.T,
	scope network.Scope,
	actorID identity.PrincipalID,
	displayName string,
	members []resource.Reference,
) resource.GroupDefinition {
	t.Helper()
	name, err := resource.ParseDisplayName(displayName)
	if err != nil {
		t.Fatalf("parse Resource Group display name: %v", err)
	}
	definition, err := resource.NewGroupDefinition(resource.GroupDefinitionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: actorID,
		CustodianPrincipalID: actorID, Members: members,
	})
	if err != nil {
		t.Fatalf("construct Resource Group definition: %v", err)
	}
	return definition
}

func resourceAuthorityReason(t *testing.T, value string) authority.AuditReason {
	t.Helper()
	reason, err := authority.NewAuditReason(value)
	if err != nil {
		t.Fatalf("construct Resource authority reason: %v", err)
	}
	return reason
}
