package publication_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
	publication "github.com/meshtransit/meshtransit/core/internal/domain/policy/publication"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

var (
	errPublicationControlled = errors.New("controlled publication failure")
	publicationFixtureTime   = time.Date(2026, time.September, 15, 8, 0, 0, 0, time.UTC)
)

type publicationTransactionQueue struct {
	transactions []*publicationTransactionFixture
	beginScopes  []network.Scope
}

func (queue *publicationTransactionQueue) Begin(
	_ context.Context,
	scope network.Scope,
) (publication.Transaction, error) {
	queue.beginScopes = append(queue.beginScopes, scope)
	if len(queue.transactions) == 0 {
		return nil, errPublicationControlled
	}
	transaction := queue.transactions[0]
	queue.transactions = queue.transactions[1:]
	return transaction, nil
}

type publicationTransactionFixture struct {
	resolution    publication.Resolution
	applyErr      error
	commitErr     error
	rollbackErr   error
	calls         []string
	changes       []publication.Change
	rollbackCalls int
}

func (transaction *publicationTransactionFixture) Resolve(
	context.Context,
	publication.Command,
	time.Time,
) (publication.Resolution, error) {
	transaction.calls = append(transaction.calls, "resolve")
	return transaction.resolution, nil
}

func (transaction *publicationTransactionFixture) Apply(
	_ context.Context,
	change publication.Change,
) (publication.Result, error) {
	transaction.calls = append(transaction.calls, "apply")
	transaction.changes = append(transaction.changes, change)
	if transaction.applyErr != nil {
		return publication.Result{}, transaction.applyErr
	}
	return publication.NewResult(publication.ResultParams{
		ReleaseID:       change.MutationIDs().ReleaseID(),
		Scope:           change.Command().Candidate().Snapshot().Scope(),
		NetworkRevision: change.Resolution().NetworkRevision() + 1,
		PolicyRevision:  change.Command().Candidate().Snapshot().Revision(),
		SemanticHash:    change.Command().Candidate().SemanticHash(),
	})
}

func (transaction *publicationTransactionFixture) Commit(context.Context) error {
	transaction.calls = append(transaction.calls, "commit")
	return transaction.commitErr
}

func (transaction *publicationTransactionFixture) Rollback(context.Context) error {
	transaction.calls = append(transaction.calls, "rollback")
	transaction.rollbackCalls++
	return transaction.rollbackErr
}

type fixedPublicationMutationIDs struct {
	ids       publication.MutationIDs
	calls     int
	ruleCount int
}

func (generator *fixedPublicationMutationIDs) NewMutationIDs(
	ruleCount int,
) (publication.MutationIDs, error) {
	generator.calls++
	generator.ruleCount = ruleCount
	return generator.ids, nil
}

type publicationClockFixture struct{}

func (publicationClockFixture) Now() time.Time { return publicationFixtureTime }

type publicationRetryFixture struct{ calls []int }

func (retry *publicationRetryFixture) Wait(_ context.Context, attempt int) error {
	retry.calls = append(retry.calls, attempt)
	return nil
}

type publicationCommittedFixture struct {
	result    publication.Result
	found     bool
	err       error
	calls     int
	releaseID publication.ReleaseID
}

func (resolver *publicationCommittedFixture) ResolveCommitted(
	_ context.Context,
	_ publication.Command,
	releaseID publication.ReleaseID,
) (publication.Result, bool, error) {
	resolver.calls++
	resolver.releaseID = releaseID
	return resolver.result, resolver.found, resolver.err
}

type publicationTestHandle interface {
	Helper()
	Fatalf(string, ...any)
}

func publicationServiceFixture(
	t *testing.T,
	transactions publication.Transactions,
	ids publication.MutationIDGenerator,
	retry publication.RetryWaiter,
	committed publication.CommittedResultResolver,
) *publication.Service {
	t.Helper()
	if committed == nil {
		committed = &publicationCommittedFixture{}
	}
	service, err := publication.NewService(publication.Options{
		MaxAttempts:     3,
		RollbackTimeout: time.Second,
	}, publication.Dependencies{
		Transactions:     transactions,
		CommittedResults: committed,
		MutationIDs:      ids,
		Clock:            publicationClockFixture{},
		Retry:            retry,
	})
	if err != nil {
		t.Fatalf("publication.NewService() error = %v", err)
	}
	return service
}

func publicationCommandFixture(t *testing.T) publication.Command {
	t.Helper()
	candidate := publicationCandidateFixture(t, 2, []policy.Rule{
		publicationRuleFixture(t, "000000000801", "000000000701", "000000000702", 443),
	})
	reason, err := publication.NewAuditReason("phase 1 policy")
	if err != nil {
		t.Fatalf("publication.NewAuditReason() error = %v", err)
	}
	actor, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatalf("identity.ParsePrincipalID() error = %v", err)
	}
	command, err := publication.NewCommand(publication.CommandParams{
		Candidate:          candidate,
		BasePolicyRevision: 1,
		ActorPrincipalID:   actor,
		AuditReason:        reason,
	})
	if err != nil {
		t.Fatalf("publication.NewCommand() error = %v", err)
	}
	return command
}

func publicationCandidateFixture(
	t *testing.T,
	revision int64,
	rules []policy.Rule,
) publication.Candidate {
	t.Helper()
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    publicationScopeFixture(t),
		Revision: revision,
		Rules:    rules,
	})
	if err != nil {
		t.Fatalf("policy.NewSnapshot() error = %v", err)
	}
	candidate, err := publication.NewCandidate(snapshot, 1)
	if err != nil {
		t.Fatalf("publication.NewCandidate() error = %v", err)
	}
	return candidate
}

func publicationRuleFixture(
	t *testing.T,
	ruleSuffix string,
	sourceSuffix string,
	destinationSuffix string,
	port uint16,
) policy.Rule {
	t.Helper()
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-" + ruleSuffix)
	if err != nil {
		t.Fatalf("policy.ParseRuleID() error = %v", err)
	}
	sourceID, err := node.ParseID("01890f00-0000-7000-8000-" + sourceSuffix)
	if err != nil {
		t.Fatalf("node.ParseID(source) error = %v", err)
	}
	destinationID, err := node.ParseID("01890f00-0000-7000-8000-" + destinationSuffix)
	if err != nil {
		t.Fatalf("node.ParseID(destination) error = %v", err)
	}
	portRange, err := policy.NewPortRange(port, port)
	if err != nil {
		t.Fatalf("policy.NewPortRange() error = %v", err)
	}
	rule, err := policy.NewRule(policy.RuleParams{
		ID:                    ruleID,
		Scope:                 publicationScopeFixture(t),
		SourceNodeID:          sourceID,
		DestinationNodeID:     destinationID,
		Protocol:              policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{portRange},
	})
	if err != nil {
		t.Fatalf("policy.NewRule() error = %v", err)
	}
	return rule
}

func publicationScopeFixture(t publicationTestHandle) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	return scope
}

func publicationResolutionFixture(
	t *testing.T,
	command publication.Command,
	networkRevision int64,
	policyRevision int64,
) publication.Resolution {
	t.Helper()
	vector, err := publication.NewAuthorityVector(publication.AuthorityVectorParams{
		NetworkRevision: networkRevision, InventoryRevision: 1, GroupRevision: 1,
		PolicyRevision: policyRevision, DNSRevision: 1, RouteRevision: 1,
		SharingRevision: 1, IsolationGeneration: 1,
	})
	if err != nil {
		t.Fatalf("publication.NewAuthorityVector() error = %v", err)
	}
	params := publication.ResolutionParams{
		Scope:           command.Candidate().Snapshot().Scope(),
		AuthorityVector: vector,
	}
	if policyRevision > 1 {
		params.ActiveReleaseID = publicationReleaseIDFixture(t, "000000000901")
		params.ActiveSemanticHash = command.Candidate().SemanticHash()
	}
	resolution, err := publication.NewResolution(params)
	if err != nil {
		t.Fatalf("publication.NewResolution() error = %v", err)
	}
	return resolution
}

func publicationResultFixture(
	t publicationTestHandle,
	command publication.Command,
	releaseID publication.ReleaseID,
	networkRevision int64,
) publication.Result {
	t.Helper()
	result, err := publication.NewResult(publication.ResultParams{
		ReleaseID:       releaseID,
		Scope:           command.Candidate().Snapshot().Scope(),
		NetworkRevision: networkRevision,
		PolicyRevision:  command.Candidate().Snapshot().Revision(),
		SemanticHash:    command.Candidate().SemanticHash(),
	})
	if err != nil {
		t.Fatalf("publication.NewResult() error = %v", err)
	}
	return result
}

func publicationMutationIDsFixture(t *testing.T, ruleCount int) publication.MutationIDs {
	t.Helper()
	projectionIDs := make([]publication.ProjectionID, ruleCount)
	for index := range projectionIDs {
		projectionIDs[index] = publicationProjectionIDFixture(
			t,
			fmt.Sprintf("%012d", 914+index),
		)
	}
	ids, err := publication.NewMutationIDs(publication.MutationIDParams{
		ChangeID:      publicationPublicIDFixture(t, "000000000910"),
		AuditEventID:  publicationPublicIDFixture(t, "000000000911"),
		OutboxEventID: publicationPublicIDFixture(t, "000000000912"),
		ReleaseID:     publicationReleaseIDFixture(t, "000000000913"),
		ProjectionIDs: projectionIDs,
	})
	if err != nil {
		t.Fatalf("publication.NewMutationIDs() error = %v", err)
	}
	return ids
}

func publicationPublicIDFixture(t *testing.T, suffix string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse("01890f00-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatalf("publicid.Parse() error = %v", err)
	}
	return id
}

func publicationReleaseIDFixture(t *testing.T, suffix string) publication.ReleaseID {
	t.Helper()
	id, err := publication.ParseReleaseID("01890f00-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatalf("publication.ParseReleaseID() error = %v", err)
	}
	return id
}

func publicationProjectionIDFixture(t *testing.T, suffix string) publication.ProjectionID {
	t.Helper()
	id, err := publication.ParseProjectionID("01890f00-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatalf("publication.ParseProjectionID() error = %v", err)
	}
	return id
}
