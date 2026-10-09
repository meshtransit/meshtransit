//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/sharing"
)

func assertImportedPolicySimulation(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, imported compilation.ImportedDestinationResolver,
	session accountsession.Session, destination sharing.PolicyDestination,
) {
	t.Helper()
	scope := destination.ConsumerScope()
	store, err := postgresadapter.NewPolicySimulationStore(runtimePool, postgresadapter.PolicySimulationOptions{
		StatementTimeout: 5 * time.Second, LockTimeout: 2 * time.Second, IdleTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := store.ReadSimulationBaseline(ctx, session, scope, time.Now().UTC())
	if err != nil {
		t.Fatalf("read runtime-scoped imported simulation baseline: %v", err)
	}
	if len(baseline.Candidate().Snapshot().Rules()) != 0 || len(baseline.Candidate().ImportedResourceDestinations()) != 0 {
		t.Fatal("imported simulation fixture requires an initially empty Consumer policy")
	}
	var sourcePublicID string
	if err := admin.QueryRow(ctx, `SELECT device.public_id::TEXT
FROM mesh.device AS device
JOIN mesh.workspace AS workspace ON workspace.id = device.workspace_id
JOIN mesh.network AS network ON network.id = device.network_id AND network.workspace_id = workspace.id
WHERE workspace.public_id = $1::UUID AND network.public_id = $2::UUID
  AND device.state = 'active' AND pg_catalog.transaction_timestamp() < device.expires_at
ORDER BY device.id LIMIT 1`, scope.WorkspaceID().String(), scope.NetworkID().String()).Scan(&sourcePublicID); err != nil {
		t.Fatalf("select exact Consumer source Device: %v", err)
	}
	sourceID, err := node.ParseID(sourcePublicID)
	if err != nil {
		t.Fatal(err)
	}
	ruleID, err := policy.ParseRuleID("01890f93-0000-7000-8000-000000000006")
	if err != nil {
		t.Fatal(err)
	}
	port, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: ruleID, Scope: scope, SourceNodeID: sourceID, DestinationImportedResourceID: destination.ImportedResourceID(),
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{port},
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: baseline.RevisionVector().PolicyRevision() + 1, Rules: []compilation.RuleIntent{intent},
	})
	if err != nil {
		t.Fatal(err)
	}
	compiler := newIntegrationPolicyCompiler(t, runtimePool, imported)
	simulator, err := simulation.NewService(simulation.Dependencies{Baselines: store, Compiler: compiler, Clock: simulation.SystemClock{}})
	if err != nil {
		t.Fatal(err)
	}
	added, err := simulator.Simulate(ctx, session, request)
	if err != nil {
		t.Fatalf("simulate actual Imported Resource resolution: %v", err)
	}
	if added.AddedImportedIntentCount() != 1 || added.AddedRelationshipCount() != 0 ||
		added.RemovedImportedIntentCount() != 0 || added.AffectedDeviceCount() != 1 ||
		added.AddedImportedIntents()[0].Resolution().Contract().ID() != destination.Contract().ID() {
		t.Fatal("runtime simulation omitted Imported Resource intent or invented local packet authority")
	}
	afterPreview, err := store.ReadSimulationBaseline(ctx, session, scope, time.Now().UTC())
	if err != nil || !baseline.Equal(afterPreview) {
		t.Fatal("read-only imported preview changed authority", err)
	}
	if _, err := store.ReadSimulationBaseline(ctx, session, destination.ProviderScope(), time.Now().UTC()); err != nil {
		t.Fatalf("owner provider baseline became unavailable: %v", err)
	}
	publisher := newIntegrationManagementPolicyPublicationService(t, runtimePool)
	reason, err := publication.NewAuditReason("qualify persisted Imported Resource simulation through runtime authority")
	if err != nil {
		t.Fatal(err)
	}
	command, err := publication.NewManagementCommand(publication.ManagementCommandParams{
		Candidate: added.ProposedCandidate(), BasePolicyRevision: baseline.RevisionVector().PolicyRevision(), AccountSession: session, AuditReason: reason,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, command); err != nil {
		t.Fatalf("publish runtime format-4 candidate: %v", err)
	}
	persisted, err := store.ReadSimulationBaseline(ctx, session, scope, time.Now().UTC())
	if err != nil {
		t.Fatalf("reconstruct actual persisted format-4 baseline: %v", err)
	}
	if persisted.Candidate().CompilerFormatVersion() != 4 ||
		persisted.Candidate().SemanticHash() != added.ProposedCandidate().SemanticHash() ||
		len(persisted.Candidate().ImportedResourceDestinations()) != 1 || len(persisted.Candidate().Snapshot().Rules()) != 0 {
		t.Fatal("PostgreSQL format-4 baseline lost compiler-identical bilateral provenance")
	}
	assertImportedBaselineReaderConfinement(ctx, t, admin, persisted)
	removeRequest, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: persisted.RevisionVector().PolicyRevision() + 1, Rules: []compilation.RuleIntent{},
	})
	if err != nil {
		t.Fatal(err)
	}
	removed, err := simulator.Simulate(ctx, session, removeRequest)
	if err != nil {
		t.Fatalf("simulate persisted Imported Resource removal: %v", err)
	}
	if removed.RemovedImportedIntentCount() != 1 || removed.AddedImportedIntentCount() != 0 ||
		removed.RemovedRelationshipCount() != 0 || removed.RemovedImportedIntents()[0].RuleID() != ruleID {
		t.Fatal("persisted Imported Resource removal omitted exact old intent")
	}
	restore, err := publication.NewManagementCommand(publication.ManagementCommandParams{
		Candidate: removed.ProposedCandidate(), BasePolicyRevision: persisted.RevisionVector().PolicyRevision(), AccountSession: session, AuditReason: reason,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Publish(ctx, restore); err != nil {
		t.Fatalf("restore empty Consumer policy through publication: %v", err)
	}
}
