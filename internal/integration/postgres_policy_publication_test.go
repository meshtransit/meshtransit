//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/compilation"
	publication "github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func assertPostgreSQLPolicyPublication(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	identityValue control.AuthenticatedNode,
) {
	t.Helper()
	command := policyPublicationIntegrationCommand(t)
	service := newIntegrationPolicyPublicationService(t, runtimePool)

	result, err := service.Publish(ctx, command)
	if err != nil {
		t.Fatalf("publish compiled packet policy: %v", err)
	}
	if !result.IsValid() || result.NetworkRevision() != 5 || result.PolicyRevision() != 3 ||
		result.Scope() != command.Candidate().Snapshot().Scope() ||
		result.SemanticHash() != command.Candidate().SemanticHash() {
		t.Fatalf("published policy result = %+v, want Network/policy revision 5/3", result)
	}

	assertCommittedPolicyPublication(ctx, t, adminConnection, command, result)
	assertPublishedPolicyVisibleInMap(ctx, t, runtimePool, identityValue, result)

	if _, err := service.Publish(ctx, command); !errors.Is(err, publication.ErrConflict) {
		t.Fatalf("stale policy publication error = %v, want ErrConflict", err)
	}
	assertCommittedPolicyPublication(ctx, t, adminConnection, command, result)
}

func assertPostgreSQLManagementPolicyPublication(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	identityValue control.AuthenticatedNode,
) {
	t.Helper()
	trusted := policyPublicationIntegrationCommand(t)
	transportRules := trusted.Candidate().Snapshot().Rules()
	if len(transportRules) != 1 {
		t.Fatalf("trusted transport rules = %d, want 1", len(transportRules))
	}
	session := managementRBACAccountSessionFixture(t)
	scope := trusted.Candidate().Snapshot().Scope()
	var baseNetworkRevision int64
	if err := adminConnection.QueryRow(ctx, `SELECT network_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 203`).Scan(&baseNetworkRevision); err != nil {
		t.Fatalf("query management publication base Network revision: %v", err)
	}
	resourceRuleID, err := policy.ParseRuleID(integrationPublicID("01890f60-0000-7000-8000-", 3))
	if err != nil {
		t.Fatalf("parse Resource policy rule ID: %v", err)
	}
	var resourcePublicID, destinationNodePublicID string
	var resourceVersion, targetGeneration, inventoryRevision int64
	var resourceHashBytes []byte
	if err := adminConnection.QueryRow(ctx, `SELECT
    resource.public_id::TEXT,
    resource.version,
    resource.target_generation,
    resource.inventory_revision,
    resource.semantic_hash,
    device.public_id::TEXT
FROM mesh.resource AS resource
JOIN mesh.resource_device_target AS target
  ON target.workspace_id = resource.workspace_id
 AND target.network_id = resource.network_id
 AND target.resource_id = resource.id
 AND target.target_generation = resource.target_generation
 AND target.state = 'active'
JOIN mesh.device AS device
  ON device.workspace_id = target.workspace_id
 AND device.network_id = target.network_id
 AND device.id = target.device_id
 AND device.state = 'active'
WHERE resource.workspace_id = 103
  AND resource.network_id = 203
  AND resource.state = 'active'
ORDER BY resource.id
LIMIT 1`).Scan(
		&resourcePublicID,
		&resourceVersion,
		&targetGeneration,
		&inventoryRevision,
		&resourceHashBytes,
		&destinationNodePublicID,
	); err != nil {
		t.Fatalf("query active policy destination Resource: %v", err)
	}
	resourceID, err := resource.ParseID(resourcePublicID)
	if err != nil {
		t.Fatalf("parse policy destination Resource ID: %v", err)
	}
	destinationNodeID, err := node.ParseID(destinationNodePublicID)
	if err != nil {
		t.Fatalf("parse policy destination Device ID: %v", err)
	}
	if len(resourceHashBytes) != 32 {
		t.Fatalf("Resource semantic hash length = %d, want 32", len(resourceHashBytes))
	}
	var resourceHashValue [32]byte
	copy(resourceHashValue[:], resourceHashBytes)
	resourceHash, err := resource.NewSemanticHash(resourceHashValue)
	if err != nil {
		t.Fatalf("parse policy destination Resource hash: %v", err)
	}
	resourceRule, err := policy.NewRule(policy.RuleParams{
		ID: resourceRuleID, Scope: scope,
		SourceNodeID:          transportRules[0].SourceNodeID(),
		DestinationNodeID:     destinationNodeID,
		Protocol:              transportRules[0].Protocol(),
		DestinationPortRanges: transportRules[0].DestinationPortRanges(),
	})
	if err != nil {
		t.Fatalf("construct Resource policy rule: %v", err)
	}
	resourceSnapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: scope, Revision: 4, Rules: []policy.Rule{resourceRule},
	})
	if err != nil {
		t.Fatalf("construct Resource policy snapshot: %v", err)
	}
	resourceDestination, err := publication.NewResourceDestination(
		publication.ResourceDestinationParams{
			RuleID: resourceRule.ID(), Scope: scope, ResourceID: resourceID,
			ResourceVersion: resourceVersion, TargetGeneration: targetGeneration,
			InventoryRevision:    inventoryRevision,
			DestinationNodeID:    resourceRule.DestinationNodeID(),
			ResourceSemanticHash: resourceHash,
		},
	)
	if err != nil {
		t.Fatalf("construct Resource destination provenance: %v", err)
	}
	resourceCandidate, err := publication.NewCandidateWithResourceDestinations(
		resourceSnapshot,
		[]publication.ResourceDestination{resourceDestination},
	)
	if err != nil {
		t.Fatalf("construct Resource policy candidate: %v", err)
	}
	resourceReason, err := publication.NewAuditReason("integration Resource policy activation")
	if err != nil {
		t.Fatalf("construct Resource policy reason: %v", err)
	}
	resourcePublication, err := publication.NewManagementCommand(publication.ManagementCommandParams{
		Candidate: resourceCandidate, BasePolicyRevision: 3,
		AccountSession: session, AuditReason: resourceReason,
	})
	if err != nil {
		t.Fatalf("construct Resource policy publication: %v", err)
	}
	service := newIntegrationManagementPolicyPublicationService(t, runtimePool)
	if _, err := service.Publish(ctx, trusted); !errors.Is(err, publication.ErrForbidden) {
		t.Fatalf("trusted command through management publisher error = %v, want ErrForbidden", err)
	}
	resourceIntent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: resourceRule.ID(), Scope: scope, SourceNodeID: resourceRule.SourceNodeID(),
		DestinationResourceID: resourceID, Protocol: resourceRule.Protocol(),
		DestinationPortRanges: resourceRule.DestinationPortRanges(),
	})
	if err != nil {
		t.Fatalf("construct Resource policy intent: %v", err)
	}
	resourceCompilation, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: 4, Rules: []compilation.RuleIntent{resourceIntent},
	})
	if err != nil {
		t.Fatalf("construct Resource compilation request: %v", err)
	}
	compiledResourceCandidate, err := newIntegrationPolicyCompiler(t, runtimePool).Compile(
		ctx,
		session,
		resourceCompilation,
	)
	if err != nil {
		t.Fatalf("compile Resource policy against PostgreSQL authority: %v", err)
	}
	if compiledResourceCandidate.SemanticHash() != resourceCandidate.SemanticHash() {
		t.Fatal("PostgreSQL Resource compilation changed exact pinned candidate")
	}
	resourcePublished := publishPolicyOverBrowserManagement(
		ctx,
		t,
		runtimePool,
		service,
		resourcePublication,
	)
	if resourcePublished.PolicyRevision() != 4 ||
		resourcePublished.NetworkRevision() != baseNetworkRevision+1 ||
		resourcePublished.SemanticHash() != resourceCandidate.SemanticHash() {
		t.Fatalf("Resource policy publication = %+v", resourcePublished)
	}
	assertCommittedPolicyResourceDestination(
		ctx,
		t,
		adminConnection,
		resourcePublished,
		resourceDestination,
	)

	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: scope, Revision: 5, Rules: []policy.Rule{},
	})
	if err != nil {
		t.Fatalf("construct management policy snapshot: %v", err)
	}
	candidate, err := publication.NewCandidate(snapshot, 1)
	if err != nil {
		t.Fatalf("construct management policy candidate: %v", err)
	}
	reason, err := publication.NewAuditReason("integration management deny-all activation")
	if err != nil {
		t.Fatalf("construct management policy audit reason: %v", err)
	}
	command, err := publication.NewManagementCommand(publication.ManagementCommandParams{
		Candidate: candidate, BasePolicyRevision: 4,
		AccountSession: session, AuditReason: reason,
	})
	if err != nil {
		t.Fatalf("construct management policy command: %v", err)
	}
	result := publishPolicyOverBrowserManagement(
		ctx,
		t,
		runtimePool,
		service,
		command,
	)
	if result.PolicyRevision() != 5 || result.NetworkRevision() != baseNetworkRevision+2 ||
		result.Scope() != snapshot.Scope() || result.SemanticHash() != candidate.SemanticHash() {
		t.Fatalf(
			"management publication result = %+v, want Network/policy revision %d/5",
			result,
			baseNetworkRevision+2,
		)
	}
	var evidenceCount int
	if err := adminConnection.QueryRow(ctx, `SELECT pg_catalog.count(*)::INTEGER
FROM mesh_audit.audit_event
WHERE workspace_id = 103 AND network_id = 203
  AND target_kind = 'policy_release' AND target_public_id = $1::UUID
  AND action = 'policy.published' AND permission = 'policy.publish'
  AND payload ->> 'account_session_id' = $2
  AND payload ->> 'role_binding_id' = $3
  AND payload ->> 'role_definition_id' = $4`,
		result.ReleaseID().String(),
		integrationManagementSessionPublicID,
		integrationRoleBinding203PublicID,
		integrationRoleDefinitionPublicID,
	).Scan(&evidenceCount); err != nil {
		t.Fatalf("query management policy authorization evidence: %v", err)
	}
	if evidenceCount != 1 {
		t.Fatalf("management policy authorization evidence count = %d, want 1", evidenceCount)
	}
	denySnapshot, err := newPeerCandidateStore(t, runtimePool, 8).Load(ctx, identityValue)
	if err != nil {
		t.Fatalf("load deny-all client projection: %v", err)
	}
	if denySnapshot.PacketPolicy().Revision() != 5 ||
		len(denySnapshot.PacketPolicy().Rules()) != 0 || len(denySnapshot.AuthorizedPeers()) != 0 {
		t.Fatalf(
			"deny-all projection = revision %d rules=%d peers=%d",
			denySnapshot.PacketPolicy().Revision(),
			len(denySnapshot.PacketPolicy().Rules()),
			len(denySnapshot.AuthorizedPeers()),
		)
	}

	restoreRuleID, err := policy.ParseRuleID(integrationPublicID("01890f60-0000-7000-8000-", 2))
	if err != nil {
		t.Fatalf("parse UDP restore rule ID: %v", err)
	}
	udpPort, err := policy.NewPortRange(53, 53)
	if err != nil {
		t.Fatalf("construct UDP restore range: %v", err)
	}
	udpRule, err := policy.NewRule(policy.RuleParams{
		ID:                    restoreRuleID,
		Scope:                 snapshot.Scope(),
		SourceNodeID:          transportRules[0].SourceNodeID(),
		DestinationNodeID:     transportRules[0].DestinationNodeID(),
		Protocol:              policy.ProtocolUDP,
		DestinationPortRanges: []policy.PortRange{udpPort},
	})
	if err != nil {
		t.Fatalf("construct UDP restore rule: %v", err)
	}
	restoreSnapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: snapshot.Scope(), Revision: 6,
		Rules: []policy.Rule{udpRule, transportRules[0]},
	})
	if err != nil {
		t.Fatalf("construct restore policy snapshot: %v", err)
	}
	restoreCandidate, err := publication.NewCandidate(restoreSnapshot, 1)
	if err != nil {
		t.Fatalf("construct restore policy candidate: %v", err)
	}
	restoreReason, err := publication.NewAuditReason("integration TCP and UDP restore activation")
	if err != nil {
		t.Fatalf("construct restore audit reason: %v", err)
	}
	restoreCommand, err := publication.NewManagementCommand(publication.ManagementCommandParams{
		Candidate: restoreCandidate, BasePolicyRevision: 5,
		AccountSession: session, AuditReason: restoreReason,
	})
	if err != nil {
		t.Fatalf("construct restore management command: %v", err)
	}
	restored := publishPolicyOverBrowserManagement(ctx, t, runtimePool, service, restoreCommand)
	if restored.PolicyRevision() != 6 || restored.NetworkRevision() != baseNetworkRevision+3 ||
		restored.SemanticHash() != restoreCandidate.SemanticHash() {
		t.Fatalf(
			"restore result = %+v, want Network/policy revision %d/6",
			restored,
			baseNetworkRevision+3,
		)
	}
	clientSnapshot, err := newPeerCandidateStore(t, runtimePool, 8).Load(ctx, identityValue)
	if err != nil {
		t.Fatalf("load restored client projection: %v", err)
	}
	rules := clientSnapshot.PacketPolicy().Rules()
	if clientSnapshot.PacketPolicy().Revision() != 6 || len(rules) != 2 ||
		len(clientSnapshot.AuthorizedPeers()) != 1 ||
		rules[0].Protocol() != policy.ProtocolTCP ||
		rules[1].Protocol() != policy.ProtocolUDP ||
		rules[1].DestinationPortRanges()[0].First() != 53 {
		t.Fatalf(
			"restored projection = revision %d rules=%+v peers=%d",
			clientSnapshot.PacketPolicy().Revision(),
			rules,
			len(clientSnapshot.AuthorizedPeers()),
		)
	}
	if _, err := service.Publish(ctx, command); !errors.Is(err, publication.ErrConflict) {
		t.Fatalf("stale deny-all publication error = %v, want ErrConflict", err)
	}
	var tcpCount, udpCount int
	if err := adminConnection.QueryRow(ctx, `SELECT
    pg_catalog.count(*) FILTER (WHERE rule.protocol = 'tcp')::INTEGER,
    pg_catalog.count(*) FILTER (WHERE rule.protocol = 'udp')::INTEGER
FROM mesh.compiled_policy_rule AS rule
JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
WHERE release.public_id = $1::UUID AND release.state = 'active'`,
		restored.ReleaseID().String(),
	).Scan(&tcpCount, &udpCount); err != nil {
		t.Fatalf("query restored transport policy: %v", err)
	}
	if tcpCount != 1 || udpCount != 1 {
		t.Fatalf("restored TCP/UDP rule counts = %d/%d, want 1/1", tcpCount, udpCount)
	}
}

func assertCommittedPolicyResourceDestination(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	result publication.Result,
	destination publication.ResourceDestination,
) {
	t.Helper()
	resourceHash := destination.ResourceSemanticHash().Bytes()
	var count int
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.count(*)::INTEGER
FROM mesh.compiled_policy_resource_destination AS provenance
JOIN mesh.compiled_policy_rule AS rule
  ON rule.id = provenance.compiled_policy_rule_id
JOIN mesh.policy_release AS release
  ON release.id = rule.policy_release_id
JOIN mesh.resource AS resource
  ON resource.id = provenance.destination_resource_id
WHERE release.public_id = $1::UUID
  AND release.policy_revision = $2::BIGINT
  AND rule.access_rule_public_id = $3::UUID
  AND resource.public_id = $4::UUID
  AND provenance.resource_version = $5::BIGINT
  AND provenance.target_generation = $6::BIGINT
  AND provenance.inventory_revision = $7::BIGINT
  AND provenance.resource_semantic_hash = $8::BYTEA`,
		result.ReleaseID().String(),
		result.PolicyRevision(),
		destination.RuleID().String(),
		destination.Reference().ResourceID().String(),
		destination.Reference().ResourceVersion(),
		destination.Reference().TargetGeneration(),
		destination.InventoryRevision(),
		resourceHash[:],
	).Scan(&count); err != nil {
		t.Fatalf("query committed Resource policy destination: %v", err)
	}
	if count != 1 {
		t.Fatalf("committed Resource policy destination count = %d, want 1", count)
	}
}

func policyPublicationIntegrationCommand(t *testing.T) publication.Command {
	t.Helper()
	workspaceID, err := workspace.ParseID(
		integrationPublicID("01890f00-0000-7000-8000-", 103),
	)
	if err != nil {
		t.Fatalf("parse policy publication Workspace ID: %v", err)
	}
	networkID, err := network.ParseID(integrationPublicID("01890f00-0000-7000-8000-", 203))
	if err != nil {
		t.Fatalf("parse policy publication Network ID: %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("construct policy publication scope: %v", err)
	}
	ruleID, err := policy.ParseRuleID(integrationPublicID("01890f60-0000-7000-8000-", 1))
	if err != nil {
		t.Fatalf("parse policy publication rule ID: %v", err)
	}
	sourceID, err := node.ParseID(integrationPublicID("01890f31-0000-7000-8000-", 910))
	if err != nil {
		t.Fatalf("parse policy publication source Node ID: %v", err)
	}
	destinationID, err := node.ParseID(integrationPublicID("01890f31-0000-7000-8000-", 930))
	if err != nil {
		t.Fatalf("parse policy publication destination Node ID: %v", err)
	}
	portRange, err := policy.NewPortRange(8443, 8443)
	if err != nil {
		t.Fatalf("construct policy publication port range: %v", err)
	}
	rule, err := policy.NewRule(policy.RuleParams{
		ID:                    ruleID,
		Scope:                 scope,
		SourceNodeID:          sourceID,
		DestinationNodeID:     destinationID,
		Protocol:              policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{portRange},
	})
	if err != nil {
		t.Fatalf("construct policy publication rule: %v", err)
	}
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    scope,
		Revision: 3,
		Rules:    []policy.Rule{rule},
	})
	if err != nil {
		t.Fatalf("construct policy publication snapshot: %v", err)
	}
	candidate, err := publication.NewCandidate(snapshot, 1)
	if err != nil {
		t.Fatalf("construct policy publication candidate: %v", err)
	}
	actorID, err := identity.ParsePrincipalID(
		integrationPublicID("01890f00-0000-7000-8000-", 11),
	)
	if err != nil {
		t.Fatalf("parse policy publication actor: %v", err)
	}
	reason, err := publication.NewAuditReason("integration policy activation")
	if err != nil {
		t.Fatalf("construct policy publication audit reason: %v", err)
	}
	command, err := publication.NewCommand(publication.CommandParams{
		Candidate:          candidate,
		BasePolicyRevision: 2,
		ActorPrincipalID:   actorID,
		AuditReason:        reason,
	})
	if err != nil {
		t.Fatalf("construct policy publication command: %v", err)
	}
	return command
}

func newIntegrationPolicyPublicationService(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *publication.Service {
	t.Helper()
	store, err := postgresadapter.NewPolicyPublicationStore(
		runtimePool,
		postgresadapter.PolicyPublicationOptions{
			StatementTimeout:  5 * time.Second,
			LockTimeout:       2 * time.Second,
			IdleTimeout:       10 * time.Second,
			AllowTrustedActor: true,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewPolicyPublicationStore() error = %v", err)
	}
	retry, err := publication.NewExponentialBackoff(time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("publication.NewExponentialBackoff() error = %v", err)
	}
	service, err := publication.NewService(
		publication.Options{MaxAttempts: 3, RollbackTimeout: 2 * time.Second},
		publication.Dependencies{
			Transactions:     store,
			CommittedResults: store,
			MutationIDs:      publication.PublicMutationIDGenerator{},
			Clock:            publication.SystemClock{},
			Retry:            retry,
		},
	)
	if err != nil {
		t.Fatalf("publication.NewService() error = %v", err)
	}
	return service
}

func newIntegrationManagementPolicyPublicationService(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *publication.Service {
	t.Helper()
	store, err := postgresadapter.NewPolicyPublicationStore(
		runtimePool,
		postgresadapter.PolicyPublicationOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewPolicyPublicationStore() error = %v", err)
	}
	retry, err := publication.NewExponentialBackoff(time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("publication.NewExponentialBackoff() error = %v", err)
	}
	service, err := publication.NewService(
		publication.Options{MaxAttempts: 3, RollbackTimeout: 2 * time.Second},
		publication.Dependencies{
			Transactions: store, CommittedResults: store,
			MutationIDs: publication.PublicMutationIDGenerator{},
			Clock:       publication.SystemClock{}, Retry: retry,
		},
	)
	if err != nil {
		t.Fatalf("publication.NewService() error = %v", err)
	}
	return service
}

func assertCommittedPolicyPublication(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	command publication.Command,
	result publication.Result,
) {
	t.Helper()
	semanticHash := command.Candidate().SemanticHash().Bytes()
	var activeCount, supersededCount, ruleCount, auditCount, outboxCount int
	if err := connection.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*)::INTEGER
     FROM mesh.policy_release
     WHERE workspace_id = 103 AND network_id = 203 AND state = 'active'),
    (SELECT pg_catalog.count(*)::INTEGER
     FROM mesh.policy_release
     WHERE workspace_id = 103 AND network_id = 203 AND state = 'superseded'),
    (SELECT pg_catalog.count(*)::INTEGER
     FROM mesh.compiled_policy_rule AS rule
     JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
     WHERE release.public_id = $1::UUID
       AND rule.policy_revision = $2::BIGINT
       AND rule.protocol = 'tcp'
       AND rule.destination_ports = '{[8443,8444)}'::INT4MULTIRANGE),
    (SELECT pg_catalog.count(*)::INTEGER
     FROM mesh_audit.audit_event
     WHERE workspace_id = 103 AND network_id = 203
       AND target_kind = 'policy_release' AND target_public_id = $1::UUID
       AND action = 'policy.published' AND permission = 'policy.publish'
       AND after_semantic_hash = $3::BYTEA),
    (SELECT pg_catalog.count(*)::INTEGER
     FROM mesh_ops.outbox_event
     WHERE workspace_id = 103 AND network_id = 203
       AND aggregate_kind = 'policy_release' AND aggregate_public_id = $1::UUID
       AND aggregate_version = 1 AND network_revision = $4::BIGINT
       AND event_class = 'network.revision.advanced'
       AND (payload ->> 'policy_revision')::BIGINT = $2::BIGINT)`,
		result.ReleaseID().String(),
		result.PolicyRevision(),
		semanticHash[:],
		result.NetworkRevision(),
	).Scan(&activeCount, &supersededCount, &ruleCount, &auditCount, &outboxCount); err != nil {
		t.Fatalf("query committed policy publication evidence: %v", err)
	}
	if activeCount != 1 || supersededCount != 1 || ruleCount != 1 || auditCount != 1 ||
		outboxCount != 1 {
		t.Fatalf(
			"publication evidence active/superseded/rules/audit/outbox = %d/%d/%d/%d/%d, want 1/1/1/1/1",
			activeCount,
			supersededCount,
			ruleCount,
			auditCount,
			outboxCount,
		)
	}
}

func assertPublishedPolicyVisibleInMap(
	ctx context.Context,
	t *testing.T,
	runtimePool *postgresadapter.Pool,
	identityValue control.AuthenticatedNode,
	result publication.Result,
) {
	t.Helper()
	snapshot, err := newPeerCandidateStore(t, runtimePool, 8).Load(ctx, identityValue)
	if err != nil {
		t.Fatalf("load map snapshot after policy publication: %v", err)
	}
	rules := snapshot.PacketPolicy().Rules()
	peers := snapshot.AuthorizedPeers()
	if snapshot.NetworkRevision() != result.NetworkRevision() ||
		snapshot.PacketPolicy().Revision() != result.PolicyRevision() || len(rules) != 1 ||
		len(peers) != 1 ||
		peers[0].NodeID().String() != integrationPublicID("01890f31-0000-7000-8000-", 930) ||
		rules[0].Protocol() != policy.ProtocolTCP ||
		len(rules[0].DestinationPortRanges()) != 1 ||
		rules[0].DestinationPortRanges()[0].First() != 8443 {
		t.Fatalf(
			"client-visible published map = revision %d/%d rules=%+v peers=%+v",
			snapshot.NetworkRevision(),
			snapshot.PacketPolicy().Revision(),
			rules,
			peers,
		)
	}
}
