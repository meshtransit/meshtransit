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
	publication "github.com/meshtransit/meshtransit/internal/policy/publication"
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
) {
	t.Helper()
	var baseNetworkRevision int64
	if err := adminConnection.QueryRow(ctx, `SELECT network_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 203`).Scan(&baseNetworkRevision); err != nil {
		t.Fatalf("query management publication base Network revision: %v", err)
	}
	trusted := policyPublicationIntegrationCommand(t)
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: trusted.Candidate().Snapshot().Scope(), Revision: 4, Rules: []policy.Rule{},
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
		Candidate: candidate, BasePolicyRevision: 3,
		AccountSession: managementRBACAccountSessionFixture(t), AuditReason: reason,
	})
	if err != nil {
		t.Fatalf("construct management policy command: %v", err)
	}
	service := newIntegrationManagementPolicyPublicationService(t, runtimePool)
	if _, err := service.Publish(ctx, trusted); !errors.Is(err, publication.ErrForbidden) {
		t.Fatalf("trusted command through management publisher error = %v, want ErrForbidden", err)
	}
	result := publishPolicyOverBrowserManagement(
		ctx,
		t,
		runtimePool,
		service,
		command,
	)
	if result.PolicyRevision() != 4 || result.NetworkRevision() != baseNetworkRevision+1 ||
		result.Scope() != snapshot.Scope() || result.SemanticHash() != candidate.SemanticHash() {
		t.Fatalf(
			"management publication result = %+v, want Network/policy revision %d/4",
			result,
			baseNetworkRevision+1,
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
