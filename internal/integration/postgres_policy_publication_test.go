//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/accessgraph"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/approval"
	"github.com/meshtransit/meshtransit/internal/policy/compilation"
	publication "github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/resource"
	authority "github.com/meshtransit/meshtransit/internal/resource/authority"
	"github.com/meshtransit/meshtransit/internal/sharing"
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
	resourcePublication, err := publication.NewManagementCommand(publication.ManagementCommandParams{
		Candidate: resourceCandidate, BasePolicyRevision: 3, AccountSession: session, AuditReason: resourceReason,
	})
	if err != nil {
		t.Fatalf("construct direct authorized Resource publication: %v", err)
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
	var directAuditCount int
	if err := adminConnection.QueryRow(ctx, `SELECT count(*)::INTEGER
FROM mesh_audit.audit_event
WHERE workspace_id = 103 AND network_id = 203
  AND target_kind = 'policy_release' AND target_public_id = $1::UUID
  AND action = 'policy.published' AND permission = 'policy.publish'
  AND payload ->> 'account_session_id' = $2
  AND NOT (payload ? 'approval_evidence_id')`, resourcePublished.ReleaseID().String(), session.ID().String()).Scan(&directAuditCount); err != nil || directAuditCount != 1 {
		t.Fatalf("direct authorized publication audit count=%d error=%v", directAuditCount, err)
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
	denyCompilation, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: 5, Rules: []compilation.RuleIntent{},
	})
	if err != nil {
		t.Fatalf("construct deny-all compilation request: %v", err)
	}
	denyApproval := approveEmptyPolicyOverBrowserManagement(ctx, t, runtimePool, denyCompilation)
	command := newApprovedIntegrationManagementCommand(
		t, candidate, 4, session, reason, denyApproval,
	)
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
	assertConsumedPolicyApproval(ctx, t, adminConnection, denyApproval, result)
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
	restoreIntents := make([]compilation.RuleIntent, 0, len(restoreSnapshot.Rules()))
	for _, restoreRule := range restoreSnapshot.Rules() {
		intent, intentErr := compilation.NewRuleIntent(compilation.RuleIntentParams{
			ID: restoreRule.ID(), Scope: scope,
			SourceNodeID:          restoreRule.SourceNodeID(),
			DestinationNodeID:     restoreRule.DestinationNodeID(),
			Protocol:              restoreRule.Protocol(),
			DestinationPortRanges: restoreRule.DestinationPortRanges(),
		})
		if intentErr != nil {
			t.Fatalf("construct restore Policy intent: %v", intentErr)
		}
		restoreIntents = append(restoreIntents, intent)
	}
	restoreCompilation, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: 6, Rules: restoreIntents,
	})
	if err != nil {
		t.Fatalf("construct restore Policy compilation request: %v", err)
	}
	restoreApproval := approveIntegrationPolicyCandidate(
		ctx, t, runtimePool, restoreCompilation, session, 205,
	)
	restoreCommand := newApprovedIntegrationManagementCommand(
		t, restoreCandidate, 5, session, restoreReason, restoreApproval,
	)
	restored := publishPolicyOverBrowserManagement(ctx, t, runtimePool, service, restoreCommand)
	if restored.PolicyRevision() != 6 || restored.NetworkRevision() != baseNetworkRevision+3 ||
		restored.SemanticHash() != restoreCandidate.SemanticHash() {
		t.Fatalf(
			"restore result = %+v, want Network/policy revision %d/6",
			restored,
			baseNetworkRevision+3,
		)
	}
	assertConsumedPolicyApproval(ctx, t, adminConnection, restoreApproval, restored)
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
	if _, err := service.Publish(ctx, command); !errors.Is(
		err, publication.ErrApprovalUnavailable,
	) {
		t.Fatalf(
			"consumed deny-all approval reuse error = %v, want ErrApprovalUnavailable",
			err,
		)
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
	assertPostgreSQLResourceGroupPolicyPublication(
		ctx,
		t,
		adminConnection,
		runtimePool,
		service,
		session,
		scope,
		restored,
		transportRules[0],
		resourceID,
		resourceVersion,
		targetGeneration,
		identityValue,
	)
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

func assertPostgreSQLResourceGroupPolicyPublication(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	service *publication.Service,
	session accountsession.Session,
	scope network.Scope,
	active publication.Result,
	template policy.Rule,
	resourceID resource.ID,
	resourceVersion int64,
	targetGeneration int64,
	identityValue control.AuthenticatedNode,
) {
	t.Helper()
	_, groupRevision := resourceAuthorityRevisions(ctx, t, adminConnection, 103, 203)
	reference, err := resource.NewReference(
		scope, resourceID, resourceVersion, targetGeneration,
	)
	if err != nil {
		t.Fatalf("construct Resource Group policy member: %v", err)
	}
	definition := resourceAuthorityGroupDefinition(
		t, scope, session.PrincipalID(), "Policy production services", []resource.Reference{reference},
	)
	create, err := authority.NewCreateGroupCommand(
		definition,
		groupRevision,
		session,
		resourceAuthorityReason(t, "create policy destination Resource Group"),
		resourceAuthorityProof(t, 101),
	)
	if err != nil {
		t.Fatalf("construct policy Resource Group creation: %v", err)
	}
	created, err := newIntegrationResourceAuthorityService(t, runtimePool).Create(ctx, create)
	if err != nil {
		t.Fatalf("create policy Resource Group: %v", err)
	}

	ruleID, err := policy.ParseRuleID(integrationPublicID("01890f60-0000-7000-8000-", 4))
	if err != nil {
		t.Fatalf("parse Resource Group policy rule ID: %v", err)
	}
	intent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: ruleID, Scope: scope, SourceNodeID: template.SourceNodeID(),
		DestinationGroupID: created.GroupID(), Protocol: template.Protocol(),
		DestinationPortRanges: template.DestinationPortRanges(),
	})
	if err != nil {
		t.Fatalf("construct Resource Group policy intent: %v", err)
	}
	request, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: active.PolicyRevision() + 1,
		Rules: []compilation.RuleIntent{intent},
	})
	if err != nil {
		t.Fatalf("construct Resource Group compilation request: %v", err)
	}
	compiler := newIntegrationPolicyCompiler(t, runtimePool)
	staleCandidate, err := compiler.Compile(ctx, session, request)
	if err != nil {
		t.Fatalf("compile Resource Group policy: %v", err)
	}
	if staleCandidate.CompilerFormatVersion() != 3 ||
		len(staleCandidate.ResourceGroupDestinations()) != 1 ||
		len(staleCandidate.Snapshot().Rules()) != 1 {
		t.Fatalf("compiled Resource Group candidate = %+v", staleCandidate)
	}
	staleApproval := approveIntegrationPolicyCandidate(
		ctx, t, runtimePool, request, session, 207,
	)

	lifecycle := newIntegrationResourceLifecycleService(t, runtimePool)
	suspend, err := authority.NewGroupLifecycleCommand(
		authority.LifecycleSuspendGroup,
		scope,
		created.GroupID(),
		created.Version(),
		session,
		resourceAuthorityReason(t, "race policy compilation with Resource Group suspension"),
		resourceAuthorityProof(t, 102),
	)
	if err != nil {
		t.Fatalf("construct policy Resource Group suspension: %v", err)
	}
	suspended, err := lifecycle.Transition(ctx, suspend)
	if err != nil {
		t.Fatalf("suspend policy Resource Group: %v", err)
	}
	staleReason, err := publication.NewAuditReason("reject stale Resource Group policy activation")
	if err != nil {
		t.Fatalf("construct stale Resource Group reason: %v", err)
	}
	staleCommand := newApprovedIntegrationManagementCommand(
		t, staleCandidate, active.PolicyRevision(), session, staleReason, staleApproval,
	)
	if _, err := service.Publish(ctx, staleCommand); !errors.Is(
		err, publication.ErrApprovalUnavailable,
	) {
		t.Fatalf(
			"stale Resource Group publication error = %v, want ErrApprovalUnavailable",
			err,
		)
	}
	assertUnconsumedPolicyApproval(ctx, t, adminConnection, staleApproval)
	var activeReleaseID string
	var activePolicyRevision int64
	if err := adminConnection.QueryRow(ctx, `SELECT public_id::TEXT, policy_revision
FROM mesh.policy_release
WHERE workspace_id = 103 AND network_id = 203 AND state = 'active'`).Scan(
		&activeReleaseID,
		&activePolicyRevision,
	); err != nil {
		t.Fatalf("query active release after stale Resource Group publication: %v", err)
	}
	if activeReleaseID != active.ReleaseID().String() || activePolicyRevision != active.PolicyRevision() {
		t.Fatalf(
			"active release after stale Resource Group publication = %s/%d, want %s/%d",
			activeReleaseID,
			activePolicyRevision,
			active.ReleaseID().String(),
			active.PolicyRevision(),
		)
	}

	resume, err := authority.NewGroupLifecycleCommand(
		authority.LifecycleResumeGroup,
		scope,
		created.GroupID(),
		suspended.Version(),
		session,
		resourceAuthorityReason(t, "resume policy destination Resource Group"),
		resourceAuthorityProof(t, 103),
	)
	if err != nil {
		t.Fatalf("construct policy Resource Group resume: %v", err)
	}
	if _, err := lifecycle.Transition(ctx, resume); err != nil {
		t.Fatalf("resume policy Resource Group: %v", err)
	}
	candidate, err := compiler.Compile(ctx, session, request)
	if err != nil {
		t.Fatalf("recompile resumed Resource Group policy: %v", err)
	}
	if candidate.SemanticHash() == staleCandidate.SemanticHash() {
		t.Fatal("Resource Group lifecycle revision did not change the compiled candidate")
	}
	reason, err := publication.NewAuditReason("integration Resource Group policy activation")
	if err != nil {
		t.Fatalf("construct Resource Group policy reason: %v", err)
	}
	approvalEvidence := approveIntegrationPolicyCandidate(
		ctx, t, runtimePool, request, session, 209,
	)
	command := newApprovedIntegrationManagementCommand(
		t, candidate, active.PolicyRevision(), session, reason, approvalEvidence,
	)
	var networkRevision int64
	if err := adminConnection.QueryRow(ctx, `SELECT network_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 203`).Scan(&networkRevision); err != nil {
		t.Fatalf("query Resource Group publication base Network revision: %v", err)
	}
	published := publishPolicyOverBrowserManagement(ctx, t, runtimePool, service, command)
	if published.PolicyRevision() != active.PolicyRevision()+1 ||
		published.NetworkRevision() != networkRevision+1 ||
		published.SemanticHash() != candidate.SemanticHash() {
		t.Fatalf("Resource Group policy publication = %+v", published)
	}
	assertConsumedPolicyApproval(ctx, t, adminConnection, approvalEvidence, published)
	assertCommittedPolicyResourceGroupDestination(
		ctx, t, adminConnection, published, candidate.ResourceGroupDestinations()[0],
	)
	snapshot, err := newPeerCandidateStore(t, runtimePool, 8).Load(ctx, identityValue)
	if err != nil {
		t.Fatalf("load Resource Group client projection: %v", err)
	}
	if snapshot.PacketPolicy().Revision() != published.PolicyRevision() ||
		len(snapshot.PacketPolicy().Rules()) != len(candidate.Snapshot().Rules()) {
		t.Fatalf(
			"Resource Group projection = revision %d rules=%d, want %d/%d",
			snapshot.PacketPolicy().Revision(),
			len(snapshot.PacketPolicy().Rules()),
			published.PolicyRevision(),
			len(candidate.Snapshot().Rules()),
		)
	}
	assertPostgreSQLActivePolicyExplanation(
		ctx, t, runtimePool, session, scope, template, resourceID, created.GroupID(), published,
	)
}

func assertPostgreSQLActivePolicyExplanation(
	ctx context.Context,
	t *testing.T,
	runtimePool *postgresadapter.Pool,
	session accountsession.Session,
	scope network.Scope,
	template policy.Rule,
	resourceID resource.ID,
	groupID resource.GroupID,
	published publication.Result,
) {
	t.Helper()
	ranges := template.DestinationPortRanges()
	if len(ranges) != 1 {
		t.Fatalf("Access Graph fixture port ranges = %d, want 1", len(ranges))
	}
	query, err := accessgraph.NewQuery(accessgraph.QueryParams{
		Scope: scope, SourceNodeID: template.SourceNodeID(), DestinationResourceID: resourceID,
		Protocol: template.Protocol(), DestinationPort: ranges[0].First(),
	})
	if err != nil {
		t.Fatalf("construct Access Graph allow query: %v", err)
	}
	explainer := newIntegrationPolicyExplainer(t, runtimePool)
	result, err := explainer.Explain(ctx, session, query)
	if err != nil {
		t.Fatalf("explain active Resource Group policy: %v", err)
	}
	paths := result.Paths()
	releaseID, compilerFormat, semanticHash, hasRelease := result.Snapshot().ActiveRelease()
	if !result.IsValid() || result.Decision() != accessgraph.DecisionAllow || result.Truncated() ||
		len(paths) != 1 || paths[0].SelectorKind() != accessgraph.SelectorKindResourceGroup ||
		paths[0].DestinationResourceID() != resourceID || paths[0].DestinationGroupID() != groupID ||
		!hasRelease || releaseID != published.ReleaseID() || compilerFormat != 3 ||
		semanticHash != published.SemanticHash() || result.Snapshot().PolicyRevision() != published.PolicyRevision() {
		t.Fatalf("active policy explanation = %+v, paths=%+v", result, paths)
	}
	if _, denied := result.DenyReason(); denied ||
		result.Snapshot().Source().State() != accessgraph.ParticipantStateActive ||
		result.Snapshot().TargetKind() != accessgraph.TargetKindResource ||
		result.Snapshot().Target().State() != accessgraph.ParticipantStateActive ||
		result.Snapshot().Target().Name() == "" {
		t.Fatalf("active policy explanation context = %+v", result.Snapshot())
	}

	denyQuery, err := accessgraph.NewQuery(accessgraph.QueryParams{
		Scope: scope, SourceNodeID: template.SourceNodeID(), DestinationResourceID: resourceID,
		Protocol: policy.ProtocolUDP, DestinationPort: ranges[0].First(),
	})
	if err != nil {
		t.Fatalf("construct Access Graph deny query: %v", err)
	}
	denied, err := explainer.Explain(ctx, session, denyQuery)
	if err != nil {
		t.Fatalf("explain default-deny policy: %v", err)
	}
	if !denied.IsValid() || denied.Decision() != accessgraph.DecisionDeny ||
		denied.Reason() != accessgraph.ReasonNoMatchingActiveRule || len(denied.Paths()) != 0 {
		t.Fatalf("default-deny explanation = %+v", denied)
	}
	if reason, isDenied := denied.DenyReason(); !isDenied || reason != accessgraph.DenyReasonNoMatchingActiveRule {
		t.Fatalf("default-deny reason = %v, denied = %t", reason, isDenied)
	}

	importedID, err := sharing.ParseImportedResourceID(
		"01890f00-0000-7000-8000-000000000981",
	)
	if err != nil {
		t.Fatalf("parse Imported Resource explanation fixture: %v", err)
	}
	importedQuery, err := accessgraph.NewQuery(accessgraph.QueryParams{
		Scope: scope, SourceNodeID: template.SourceNodeID(),
		DestinationImportedResourceID: importedID,
		Protocol:                      template.Protocol(), DestinationPort: ranges[0].First(),
	})
	if err != nil {
		t.Fatalf("construct Imported Resource Access Graph query: %v", err)
	}
	importedDenied, err := explainer.Explain(ctx, session, importedQuery)
	if err != nil {
		t.Fatalf("explain fail-closed Imported Resource policy: %v", err)
	}
	importedReleaseID, importedFormat, importedHash, importedHasRelease :=
		importedDenied.Snapshot().ActiveRelease()
	if !importedDenied.IsValid() || importedDenied.Decision() != accessgraph.DecisionDeny ||
		importedDenied.Reason() != accessgraph.ReasonNoMatchingActiveRule ||
		len(importedDenied.Paths()) != 0 || importedDenied.Snapshot().TargetNodeID().IsValid() ||
		!importedHasRelease || importedReleaseID != published.ReleaseID() || importedFormat != 3 ||
		importedHash != published.SemanticHash() {
		t.Fatalf("Imported Resource fail-closed explanation = %+v", importedDenied)
	}
	_, hasShare := importedDenied.Snapshot().Share()
	if reason, isDenied := importedDenied.DenyReason(); !isDenied || reason != accessgraph.DenyReasonTargetInactive ||
		hasShare || importedDenied.Snapshot().TargetKind() != accessgraph.TargetKindImportedResource ||
		importedDenied.Snapshot().Target().State() != accessgraph.ParticipantStateMissing {
		t.Fatalf("unknown Imported Resource explanation context = %+v", importedDenied.Snapshot())
	}
}

func assertCommittedPolicyResourceGroupDestination(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	result publication.Result,
	destination publication.ResourceGroupDestination,
) {
	t.Helper()
	groupHash := destination.GroupSemanticHash().Bytes()
	members := destination.Members()
	var count int
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.count(*)::INTEGER
FROM mesh.compiled_policy_resource_group_destination AS provenance
JOIN mesh.compiled_policy_rule AS rule
  ON rule.id = provenance.compiled_policy_rule_id
JOIN mesh.policy_release AS release
  ON release.id = rule.policy_release_id
JOIN mesh.resource_group AS resource_group
  ON resource_group.id = provenance.destination_resource_group_id
WHERE release.public_id = $1::UUID
  AND release.policy_revision = $2::BIGINT
  AND rule.access_rule_public_id = $3::UUID
  AND resource_group.public_id = $4::UUID
  AND provenance.resource_group_version = $5::BIGINT
  AND provenance.definition_version = $6::BIGINT
  AND provenance.group_revision = $7::BIGINT
  AND provenance.resource_group_semantic_hash = $8::BYTEA`,
		result.ReleaseID().String(),
		result.PolicyRevision(),
		destination.RuleID().String(),
		destination.ResourceGroupID().String(),
		destination.GroupVersion(),
		destination.DefinitionVersion(),
		destination.GroupRevision(),
		groupHash[:],
	).Scan(&count); err != nil {
		t.Fatalf("query committed Resource Group policy destination: %v", err)
	}
	if count != len(members) {
		t.Fatalf("committed Resource Group member count = %d, want %d", count, len(members))
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
			ApprovalMode:      postgresadapter.PolicyPublicationApprovalModeQualificationBypass,
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
			ApprovalMode:     postgresadapter.PolicyPublicationApprovalModePublisherAuthorized,
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

func newIntegrationPolicyApprovalService(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *approval.Service {
	t.Helper()
	service, _ := newIntegrationPolicyApprovalWorkflow(t, runtimePool)
	return service
}

func newIntegrationPolicyApprovalWorkflow(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) (*approval.Service, *approval.CatalogService) {
	t.Helper()
	store, err := postgresadapter.NewPolicyApprovalStore(
		runtimePool,
		postgresadapter.PolicyApprovalOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewPolicyApprovalStore() error = %v", err)
	}
	retry, err := publication.NewExponentialBackoff(time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("publication.NewExponentialBackoff() error = %v", err)
	}
	service, err := approval.NewService(
		approval.Options{
			MaxAttempts: 3, RollbackTimeout: 2 * time.Second,
			IdempotencyWindow: time.Hour,
		},
		approval.Dependencies{
			Simulator:           newIntegrationPolicySimulator(t, runtimePool),
			RequestTransactions: store, CommittedRequests: store,
			ApprovalTransactions: store, CommittedApprovals: store,
			MutationIDs: approval.PublicMutationIDGenerator{},
			Clock:       approval.SystemClock{}, Retry: retry,
		},
	)
	if err != nil {
		t.Fatalf("approval.NewService() error = %v", err)
	}
	catalog, err := approval.NewCatalogService(store, approval.SystemClock{})
	if err != nil {
		t.Fatalf("approval.NewCatalogService() error = %v", err)
	}
	return service, catalog
}

func approveIntegrationPolicyCandidate(
	ctx context.Context,
	t *testing.T,
	runtimePool *postgresadapter.Pool,
	request compilation.Request,
	proposer accountsession.Session,
	proofSuffix byte,
) approval.Result {
	t.Helper()
	simulator := newIntegrationPolicySimulator(t, runtimePool)
	simulated, err := simulator.Simulate(ctx, proposer, request)
	if err != nil {
		t.Fatalf("simulate Policy approval candidate: %v", err)
	}
	requestReason, err := approval.NewAuditReason("request independent integration policy approval")
	if err != nil {
		t.Fatalf("construct Policy approval request reason: %v", err)
	}
	intent, err := approval.NewRequestIntent(approval.RequestIntentParams{
		CompilationRequest:    request,
		CandidateSemanticHash: simulated.ProposedCandidate().SemanticHash(),
		ImpactHash:            simulated.ImpactHash(), AccountSession: proposer,
		AuditReason:         requestReason,
		IdempotencyEvidence: resourceAuthorityProof(t, proofSuffix),
	})
	if err != nil {
		t.Fatalf("construct Policy approval request intent: %v", err)
	}
	service := newIntegrationPolicyApprovalService(t, runtimePool)
	requested, err := service.Request(ctx, intent)
	if err != nil {
		t.Fatalf("request independent Policy approval: %v", err)
	}
	decisionReason, err := approval.NewAuditReason("approve unchanged integration policy impact")
	if err != nil {
		t.Fatalf("construct Policy approval decision reason: %v", err)
	}
	command, err := approval.NewCommand(approval.CommandParams{
		Scope: requested.Scope(), RequestID: requested.RequestID(),
		ExpectedRequestVersion: requested.RequestVersion(),
		CandidateSemanticHash:  requested.Binding().CandidateSemanticHash(),
		ImpactHash:             requested.Binding().ImpactHash(),
		AccountSession:         authorityConfirmerAccountSessionFixture(t),
		AuditReason:            decisionReason,
		IdempotencyEvidence:    resourceAuthorityProof(t, proofSuffix+1),
	})
	if err != nil {
		t.Fatalf("construct independent Policy approval command: %v", err)
	}
	approved, err := service.Approve(ctx, command)
	if err != nil {
		t.Fatalf("approve unchanged Policy candidate: %v", err)
	}
	if !approved.IsValid() || approved.RequestID() != requested.RequestID() ||
		approved.Binding().CandidateSemanticHash() != simulated.ProposedCandidate().SemanticHash() {
		t.Fatalf("Policy approval evidence = %+v", approved)
	}
	return approved
}

func newApprovedIntegrationManagementCommand(
	t *testing.T,
	candidate publication.Candidate,
	basePolicyRevision int64,
	session accountsession.Session,
	reason publication.AuditReason,
	evidence approval.Result,
) publication.Command {
	t.Helper()
	evidenceID, err := publication.ParseApprovalEvidenceID(evidence.EvidenceID().String())
	if err != nil {
		t.Fatalf("parse publication approval evidence ID: %v", err)
	}
	command, err := publication.NewApprovedManagementCommand(publication.ManagementCommandParams{
		Candidate: candidate, BasePolicyRevision: basePolicyRevision,
		AccountSession: session, ApprovalEvidenceID: evidenceID, AuditReason: reason,
	})
	if err != nil {
		t.Fatalf("construct approved management Policy command: %v", err)
	}
	return command
}

func assertConsumedPolicyApproval(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	evidence approval.Result,
	published publication.Result,
) {
	t.Helper()
	var count int
	if err := adminConnection.QueryRow(ctx, `SELECT pg_catalog.count(*)::INTEGER
FROM mesh.policy_approval_request AS request
JOIN mesh.policy_approval_evidence AS evidence
  ON evidence.workspace_id = request.workspace_id
 AND evidence.network_id = request.network_id
 AND evidence.request_id = request.id
JOIN mesh.policy_release AS release
  ON release.workspace_id = request.workspace_id
 AND release.network_id = request.network_id
 AND release.id = request.consumed_policy_release_id
 AND release.policy_revision = request.consumed_policy_revision
JOIN mesh.principal AS proposer
  ON proposer.deployment_id = request.deployment_id
 AND proposer.id = request.proposer_principal_id
JOIN mesh.principal AS approver
  ON approver.deployment_id = evidence.deployment_id
 AND approver.id = evidence.approver_principal_id
WHERE request.public_id = $1::UUID
  AND evidence.public_id = $2::UUID
  AND release.public_id = $3::UUID
  AND request.state = 'consumed'
  AND request.version = 3
  AND request.approval_count = 1
  AND request.consumed_policy_revision = $4::BIGINT
  AND request.consumed_at >= evidence.approved_at
  AND evidence.request_version = 2
  AND evidence.version = 1
  AND proposer.public_id = '01890f00-0000-7000-8000-000000000011'::UUID
  AND approver.public_id = $5::UUID`,
		evidence.RequestID().String(),
		evidence.EvidenceID().String(),
		published.ReleaseID().String(),
		published.PolicyRevision(),
		integrationAuthorityConfirmerID,
	).Scan(&count); err != nil {
		t.Fatalf("query consumed Policy approval evidence: %v", err)
	}
	if count != 1 {
		t.Fatalf(
			"consumed Policy approval evidence %s count = %d, want 1",
			evidence.EvidenceID().String(),
			count,
		)
	}
}

func assertUnconsumedPolicyApproval(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	evidence approval.Result,
) {
	t.Helper()
	var count int
	if err := adminConnection.QueryRow(ctx, `SELECT pg_catalog.count(*)::INTEGER
FROM mesh.policy_approval_request AS request
JOIN mesh.policy_approval_evidence AS evidence
  ON evidence.workspace_id = request.workspace_id
 AND evidence.network_id = request.network_id
 AND evidence.request_id = request.id
WHERE request.public_id = $1::UUID
  AND evidence.public_id = $2::UUID
  AND request.state = 'approved'
  AND request.version = 2
  AND request.approval_count = 1
  AND request.consumed_at IS NULL
  AND request.consumed_policy_release_id IS NULL
  AND request.consumed_policy_revision IS NULL`,
		evidence.RequestID().String(),
		evidence.EvidenceID().String(),
	).Scan(&count); err != nil {
		t.Fatalf("query unconsumed Policy approval evidence: %v", err)
	}
	if count != 1 {
		t.Fatalf(
			"unconsumed Policy approval evidence %s count = %d, want 1",
			evidence.EvidenceID().String(),
			count,
		)
	}
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
