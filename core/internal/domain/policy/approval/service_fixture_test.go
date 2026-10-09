package approval_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/approval"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/platform/idempotency"
)

type approvalSimulatorFixture struct {
	result simulation.Result
	err    error
	calls  int
}

func (fixture *approvalSimulatorFixture) Simulate(
	context.Context,
	accountsession.Session,
	compilation.Request,
) (simulation.Result, error) {
	fixture.calls++
	return fixture.result, fixture.err
}

type approvalClockFixture struct {
	now   time.Time
	calls int
}

func (fixture *approvalClockFixture) Now() time.Time {
	fixture.calls++
	return fixture.now
}

type approvalRetryFixture struct {
	calls int
	err   error
}

func (fixture *approvalRetryFixture) Wait(context.Context, int) error {
	fixture.calls++
	return fixture.err
}

type approvalIDGeneratorFixture struct {
	requestIDs    approval.RequestMutationIDs
	approvalIDs   approval.MutationIDs
	requestCalls  int
	approvalCalls int
	err           error
}

func (fixture *approvalIDGeneratorFixture) NewApprovalRequestMutationIDs(
	approval.RequestCommand,
) (approval.RequestMutationIDs, error) {
	fixture.requestCalls++
	return fixture.requestIDs, fixture.err
}

func (fixture *approvalIDGeneratorFixture) NewPolicyApprovalMutationIDs(
	approval.Command,
) (approval.MutationIDs, error) {
	fixture.approvalCalls++
	return fixture.approvalIDs, fixture.err
}

type requestTransactionsFixture struct {
	transactions []*requestTransactionFixture
	calls        int
}

func (fixture *requestTransactionsFixture) BeginApprovalRequest(
	context.Context,
	network.Scope,
) (approval.RequestTransaction, error) {
	index := fixture.calls
	fixture.calls++
	if index >= len(fixture.transactions) {
		return nil, errors.New("unexpected request transaction")
	}
	return fixture.transactions[index], fixture.transactions[index].beginErr
}

type requestTransactionFixture struct {
	beginErr       error
	resolveErr     error
	applyErr       error
	commitErr      error
	rollbackErr    error
	baselineVector accessgraph.RevisionVector
	completed      approval.RequestResult
	resolveCalls   int
	applyCalls     int
	commitCalls    int
	rollbackCalls  int
}

func (fixture *requestTransactionFixture) Resolve(
	_ context.Context,
	command approval.RequestCommand,
	ids approval.RequestMutationIDs,
	_ time.Time,
	_ time.Time,
) (approval.RequestResolution, error) {
	fixture.resolveCalls++
	if fixture.resolveErr != nil {
		return approval.RequestResolution{}, fixture.resolveErr
	}
	hash, err := command.RequestHash()
	if err != nil {
		return approval.RequestResolution{}, err
	}
	if fixture.completed.IsValid() {
		return approval.NewCompletedRequestResolution(
			fixture.completed,
			ids.IdempotencyRecordID(),
			hash,
		)
	}
	vector := fixture.baselineVector
	if !vector.IsValid() {
		vector = command.Binding().BaselineVector()
	}
	return approval.NewRequestResolution(
		command.Scope(),
		vector,
		ids.IdempotencyRecordID(),
		hash,
	)
}

func (fixture *requestTransactionFixture) Apply(
	_ context.Context,
	change approval.RequestChange,
) (approval.RequestResult, error) {
	fixture.applyCalls++
	if fixture.applyErr != nil {
		return approval.RequestResult{}, fixture.applyErr
	}
	command := change.Command()
	return approval.NewRequestResult(approval.RequestResultParams{
		RequestID: change.MutationIDs().RequestID(), Binding: command.Binding(),
		ProposerPrincipalID: command.AccountSession().PrincipalID(),
		ProposerSessionID:   command.AccountSession().ID(), RequestVersion: 1,
		CreatedAt: change.OccurredAt(), ExpiresAt: change.RequestExpiresAt(),
	})
}

func (fixture *requestTransactionFixture) Commit(context.Context) error {
	fixture.commitCalls++
	return fixture.commitErr
}

func (fixture *requestTransactionFixture) Rollback(context.Context) error {
	fixture.rollbackCalls++
	return fixture.rollbackErr
}

type approvalTransactionsFixture struct {
	transactions []*approvalTransactionFixture
	calls        int
}

func (fixture *approvalTransactionsFixture) BeginPolicyApproval(
	context.Context,
	network.Scope,
) (approval.Transaction, error) {
	index := fixture.calls
	fixture.calls++
	if index >= len(fixture.transactions) {
		return nil, errors.New("unexpected approval transaction")
	}
	return fixture.transactions[index], fixture.transactions[index].beginErr
}

type approvalTransactionFixture struct {
	beginErr       error
	resolveErr     error
	applyErr       error
	commitErr      error
	rollbackErr    error
	binding        approval.Binding
	proposer       accountsession.Session
	requestExpires time.Time
	completed      approval.Result
	resolveCalls   int
	applyCalls     int
	commitCalls    int
	rollbackCalls  int
}

func (fixture *approvalTransactionFixture) Resolve(
	_ context.Context,
	command approval.Command,
	ids approval.MutationIDs,
	_ time.Time,
	_ time.Time,
) (approval.Resolution, error) {
	fixture.resolveCalls++
	if fixture.resolveErr != nil {
		return approval.Resolution{}, fixture.resolveErr
	}
	hash, err := command.DecisionHash()
	if err != nil {
		return approval.Resolution{}, err
	}
	if fixture.completed.IsValid() {
		return approval.NewCompletedResolution(
			fixture.completed,
			ids.IdempotencyRecordID(),
			hash,
		)
	}
	return approval.NewResolution(approval.ResolutionParams{
		Scope: command.Scope(), RequestID: command.RequestID(),
		RequestVersion: 1, State: approval.StatePending, Binding: fixture.binding,
		ProposerPrincipalID: fixture.proposer.PrincipalID(),
		ProposerSessionID:   fixture.proposer.ID(), RequestExpiresAt: fixture.requestExpires,
		IdempotencyRecordID: ids.IdempotencyRecordID(), DecisionHash: hash,
	})
}

func (fixture *approvalTransactionFixture) Apply(
	_ context.Context,
	change approval.Change,
) (approval.Result, error) {
	fixture.applyCalls++
	if fixture.applyErr != nil {
		return approval.Result{}, fixture.applyErr
	}
	command := change.Command()
	resolution := change.Resolution()
	return approval.NewResult(approval.ResultParams{
		EvidenceID: change.MutationIDs().EvidenceID(), RequestID: command.RequestID(),
		Binding:             resolution.Binding(),
		ProposerPrincipalID: resolution.ProposerPrincipalID(),
		ProposerSessionID:   resolution.ProposerSessionID(),
		ApproverPrincipalID: command.AccountSession().PrincipalID(),
		ApproverSessionID:   command.AccountSession().ID(),
		RequestVersion:      2, EvidenceVersion: 1,
		ApprovedAt: change.OccurredAt(), ExpiresAt: resolution.RequestExpiresAt(),
	})
}

func (fixture *approvalTransactionFixture) Commit(context.Context) error {
	fixture.commitCalls++
	return fixture.commitErr
}

func (fixture *approvalTransactionFixture) Rollback(context.Context) error {
	fixture.rollbackCalls++
	return fixture.rollbackErr
}

type committedRequestFixture struct {
	result approval.RequestResult
	found  bool
	err    error
	calls  int
}

func (fixture *committedRequestFixture) ResolveCommittedApprovalRequest(
	context.Context,
	approval.RequestCommand,
	approval.RequestMutationIDs,
) (approval.RequestResult, bool, error) {
	fixture.calls++
	return fixture.result, fixture.found, fixture.err
}

type committedApprovalFixture struct {
	result approval.Result
	found  bool
	err    error
	calls  int
}

func (fixture *committedApprovalFixture) ResolveCommittedPolicyApproval(
	context.Context,
	approval.Command,
	approval.MutationIDs,
) (approval.Result, bool, error) {
	fixture.calls++
	return fixture.result, fixture.found, fixture.err
}

type simulationBaselineFixture struct{ baseline simulation.Baseline }

func (fixture simulationBaselineFixture) ReadSimulationBaseline(
	context.Context,
	accountsession.Session,
	network.Scope,
	time.Time,
) (simulation.Baseline, error) {
	return fixture.baseline, nil
}

type simulationCompilerFixture struct{ candidate publication.Candidate }

func (fixture simulationCompilerFixture) Compile(
	context.Context,
	accountsession.Session,
	compilation.Request,
) (publication.Candidate, error) {
	return fixture.candidate, nil
}

type simulationClockFixture struct{ now time.Time }

func (fixture simulationClockFixture) Now() time.Time { return fixture.now }

func approvalServiceFixture(
	t *testing.T,
	simulator approval.Simulator,
	requests approval.RequestTransactions,
	approvals approval.Transactions,
	ids approval.MutationIDGenerator,
	clock approval.Clock,
	retry approval.RetryWaiter,
	committedRequests approval.CommittedRequestResolver,
	committedApprovals approval.CommittedApprovalResolver,
) *approval.Service {
	t.Helper()
	if committedRequests == nil {
		committedRequests = &committedRequestFixture{}
	}
	if committedApprovals == nil {
		committedApprovals = &committedApprovalFixture{}
	}
	service, err := approval.NewService(approval.Options{
		MaxAttempts: 3, RollbackTimeout: time.Second, IdempotencyWindow: time.Hour,
	}, approval.Dependencies{
		Simulator: simulator, RequestTransactions: requests,
		CommittedRequests: committedRequests, ApprovalTransactions: approvals,
		CommittedApprovals: committedApprovals, MutationIDs: ids,
		Clock: clock, Retry: retry,
	})
	if err != nil {
		t.Fatalf("approval.NewService() error = %v", err)
	}
	return service
}

func approvalSimulationFixture(
	t *testing.T,
	session accountsession.Session,
) (simulation.Result, compilation.Request) {
	t.Helper()
	scope := approvalScopeFixture(t)
	baselineSnapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: scope, Revision: 1, Rules: []policy.Rule{},
	})
	if err != nil {
		t.Fatal(err)
	}
	baselineCandidate, err := publication.NewCandidate(baselineSnapshot, 1)
	if err != nil {
		t.Fatal(err)
	}
	vector := approvalVectorFixture(t, 11, 7, 8, 1)
	baseline, err := simulation.NewBaseline(simulation.BaselineParams{
		Scope: scope, RevisionVector: vector, Candidate: baselineCandidate,
	})
	if err != nil {
		t.Fatal(err)
	}
	proposedSnapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: scope, Revision: 2, Rules: []policy.Rule{},
	})
	if err != nil {
		t.Fatal(err)
	}
	proposedCandidate, err := publication.NewCandidate(proposedSnapshot, 1)
	if err != nil {
		t.Fatal(err)
	}
	request, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: 2, Rules: []compilation.RuleIntent{},
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := simulation.NewService(simulation.Dependencies{
		Baselines: simulationBaselineFixture{baseline: baseline},
		Compiler:  simulationCompilerFixture{candidate: proposedCandidate},
		Clock:     simulationClockFixture{now: approvalTestTime()},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Simulate(t.Context(), session, request)
	if err != nil {
		t.Fatal(err)
	}
	return result, request
}

func approvalRequestIntentFixture(
	t *testing.T,
	session accountsession.Session,
	result simulation.Result,
	request compilation.Request,
) approval.RequestIntent {
	t.Helper()
	intent, err := approval.NewRequestIntent(approval.RequestIntentParams{
		CompilationRequest:    request,
		CandidateSemanticHash: result.ProposedCandidate().SemanticHash(),
		ImpactHash:            result.ImpactHash(), AccountSession: session,
		AuditReason:         approvalReasonFixture(t, "request independent policy approval"),
		IdempotencyEvidence: approvalProofFixture(t, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func approvalCommandFixture(
	t *testing.T,
	binding approval.Binding,
	session accountsession.Session,
) approval.Command {
	t.Helper()
	command, err := approval.NewCommand(approval.CommandParams{
		Scope: binding.Scope(), RequestID: approvalRequestIDFixture(t, 920),
		ExpectedRequestVersion: 1,
		CandidateSemanticHash:  binding.CandidateSemanticHash(),
		ImpactHash:             binding.ImpactHash(), AccountSession: session,
		AuditReason:         approvalReasonFixture(t, "approve unchanged policy impact"),
		IdempotencyEvidence: approvalProofFixture(t, 2),
	})
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func approvalResolutionFixture(
	t *testing.T,
	binding approval.Binding,
	proposer accountsession.Session,
	now time.Time,
) approval.Resolution {
	t.Helper()
	command := approvalCommandFixture(t, binding, approvalSessionFixture(t, 402, 812))
	hash, err := command.DecisionHash()
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := approval.NewResolution(approval.ResolutionParams{
		Scope: binding.Scope(), RequestID: command.RequestID(), RequestVersion: 1,
		State: approval.StatePending, Binding: binding,
		ProposerPrincipalID: proposer.PrincipalID(), ProposerSessionID: proposer.ID(),
		RequestExpiresAt:    now.Add(approval.RequestLifetime),
		IdempotencyRecordID: approvalPublicIDFixture(t, 942), DecisionHash: hash,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resolution
}

func approvalRequestMutationIDsFixture(t *testing.T) approval.RequestMutationIDs {
	t.Helper()
	ids, err := approval.NewRequestMutationIDs(approval.RequestMutationIDParams{
		RequestID:           approvalRequestIDFixture(t, 920),
		ChangeID:            approvalPublicIDFixture(t, 921),
		IdempotencyRecordID: approvalPublicIDFixture(t, 922),
		AuditEventID:        approvalPublicIDFixture(t, 923),
		OutboxEventID:       approvalPublicIDFixture(t, 924),
	})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func approvalMutationIDsFixture(t *testing.T) approval.MutationIDs {
	t.Helper()
	ids, err := approval.NewMutationIDs(approval.MutationIDParams{
		EvidenceID:          approvalEvidenceIDFixture(t, 930),
		ChangeID:            approvalPublicIDFixture(t, 931),
		IdempotencyRecordID: approvalPublicIDFixture(t, 932),
		AuditEventID:        approvalPublicIDFixture(t, 933),
		OutboxEventID:       approvalPublicIDFixture(t, 934),
	})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func approvalScopeFixture(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatal(err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func approvalVectorFixture(
	t *testing.T,
	networkRevision int64,
	inventoryRevision int64,
	groupRevision int64,
	policyRevision int64,
) accessgraph.RevisionVector {
	t.Helper()
	vector, err := accessgraph.NewRevisionVector(accessgraph.RevisionVectorParams{
		NetworkRevision: networkRevision, InventoryRevision: inventoryRevision,
		GroupRevision: groupRevision, PolicyRevision: policyRevision,
		DNSRevision: 2, RouteRevision: 3, SharingRevision: 4, IsolationGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return vector
}

func approvalSessionFixture(
	t *testing.T,
	principalSequence int,
	sessionSequence int,
) accountsession.Session {
	t.Helper()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	principalID, err := identity.ParsePrincipalID(
		fmt.Sprintf("01890f00-0000-7000-8000-%012d", principalSequence),
	)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := accountsession.ParseID(
		fmt.Sprintf("01890f00-0000-7000-8000-%012d", sessionSequence),
	)
	if err != nil {
		t.Fatal(err)
	}
	subjectID, err := accountsession.ParseIdentitySubjectID(
		fmt.Sprintf("01890f00-0000-7000-8000-%012d", principalSequence+200),
	)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID := approvalScopeFixture(t).WorkspaceID()
	now := approvalTestTime()
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID, LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: now.Add(-time.Minute), ACR: "urn:meshtransit:test",
		AMR: []string{"mfa"}, Version: 1, PrincipalAuthorityGeneration: 1,
		AccountSessionGeneration: 1, ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func approvalProofFixture(t *testing.T, marker byte) idempotency.Proof {
	t.Helper()
	var digest [32]byte
	digest[0] = marker
	proof, err := idempotency.NewProof("approval-key-v1", digest)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func approvalReasonFixture(t *testing.T, value string) approval.AuditReason {
	t.Helper()
	reason, err := approval.NewAuditReason(value)
	if err != nil {
		t.Fatal(err)
	}
	return reason
}

func approvalRequestIDFixture(t *testing.T, sequence int) approval.RequestID {
	t.Helper()
	id, err := approval.ParseRequestID(
		fmt.Sprintf("01890f00-0000-7000-8000-%012d", sequence),
	)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func approvalEvidenceIDFixture(t *testing.T, sequence int) approval.EvidenceID {
	t.Helper()
	id, err := approval.ParseEvidenceID(
		fmt.Sprintf("01890f00-0000-7000-8000-%012d", sequence),
	)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func approvalPublicIDFixture(t *testing.T, sequence int) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(fmt.Sprintf("01890f00-0000-7000-8000-%012d", sequence))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func approvalTestTime() time.Time {
	return time.Date(2026, time.September, 29, 15, 0, 0, 0, time.UTC)
}
