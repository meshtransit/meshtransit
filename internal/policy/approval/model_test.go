package approval_test

import (
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/internal/policy/approval"
	"github.com/meshtransit/meshtransit/internal/policy/publication"
)

func TestBindingRequiresExactlyOnePolicyAuthorityAdvance(t *testing.T) {
	t.Parallel()

	binding := approvalBindingFixture(t)
	if !binding.IsValid() || binding.Scope() != approvalScopeFixture(t) ||
		binding.ProposedVector().NetworkRevision() != binding.BaselineVector().NetworkRevision()+1 ||
		binding.ProposedVector().PolicyRevision() != binding.BaselineVector().PolicyRevision()+1 ||
		binding.ProposedVector().InventoryRevision() != binding.BaselineVector().InventoryRevision() {
		t.Fatalf("binding = %+v", binding)
	}

	baseline := binding.BaselineVector()
	changedInventory, err := accessgraph.NewRevisionVector(accessgraph.RevisionVectorParams{
		NetworkRevision:   baseline.NetworkRevision() + 1,
		InventoryRevision: baseline.InventoryRevision() + 1,
		GroupRevision:     baseline.GroupRevision(), PolicyRevision: baseline.PolicyRevision() + 1,
		DNSRevision: baseline.DNSRevision(), RouteRevision: baseline.RouteRevision(),
		SharingRevision:     baseline.SharingRevision(),
		IsolationGeneration: baseline.IsolationGeneration(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = approval.NewBinding(approval.BindingParams{
		Scope: approvalScopeFixture(t), BaselineVector: baseline,
		ProposedVector:        changedInventory,
		CandidateSemanticHash: binding.CandidateSemanticHash(),
		CompilerFormatVersion: binding.CompilerFormatVersion(),
		ImpactHash:            binding.ImpactHash(),
	})
	if !errors.Is(err, approval.ErrInvalidBinding) {
		t.Fatalf("NewBinding() error = %v, want ErrInvalidBinding", err)
	}
}

func TestRequestAndDecisionHashesBindHumanEvidence(t *testing.T) {
	t.Parallel()

	binding := approvalBindingFixture(t)
	proposer := approvalSessionFixture(t, 401, 811)
	reason := approvalReasonFixture(t, "propose constrained production access")
	proof := approvalProofFixture(t, 1)
	command, err := approval.NewRequestCommand(binding, proposer, reason, proof)
	if err != nil {
		t.Fatal(err)
	}
	first, err := command.RequestHash()
	if err != nil {
		t.Fatal(err)
	}
	changed, err := approval.NewRequestCommand(
		binding,
		proposer,
		approvalReasonFixture(t, "propose different production access"),
		proof,
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := changed.RequestHash()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("RequestHash() ignored the human audit reason")
	}

	approvalCommand := approvalCommandFixture(t, binding, approvalSessionFixture(t, 402, 812))
	decision, err := approvalCommand.DecisionHash()
	if err != nil {
		t.Fatal(err)
	}
	if !decision.IsValid() {
		t.Fatal("DecisionHash() returned invalid evidence")
	}
}

func TestApprovalChangeRequiresIndependentPrincipalAndSession(t *testing.T) {
	t.Parallel()

	binding := approvalBindingFixture(t)
	proposer := approvalSessionFixture(t, 401, 811)
	now := approvalTestTime()
	resolution := approvalResolutionFixture(t, binding, proposer, now)
	ids := approvalMutationIDsFixture(t)

	for _, test := range []struct {
		name             string
		sessionPrincipal int
		sessionID        int
		wantErr          bool
	}{
		{name: "distinct human", sessionPrincipal: 402, sessionID: 812},
		{name: "same principal", sessionPrincipal: 401, sessionID: 813, wantErr: true},
		{name: "same session", sessionPrincipal: 402, sessionID: 811, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			command := approvalCommandFixture(
				t,
				binding,
				approvalSessionFixture(t, test.sessionPrincipal, test.sessionID),
			)
			_, err := approval.NewChange(approval.ChangeParams{
				Command: command, Resolution: resolution, MutationIDs: ids,
				OccurredAt: now, IdempotencyExpiresAt: now.Add(time.Hour),
			})
			if test.wantErr && !errors.Is(err, approval.ErrInvalidApprovalChange) {
				t.Fatalf("NewApprovalChange() error = %v, want ErrInvalidApprovalChange", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("NewApprovalChange() error = %v", err)
			}
		})
	}
}

func TestApprovalResultRejectsExpiredOrSelfApprovedEvidence(t *testing.T) {
	t.Parallel()

	binding := approvalBindingFixture(t)
	proposer := approvalSessionFixture(t, 401, 811)
	approver := approvalSessionFixture(t, 402, 812)
	now := approvalTestTime()
	params := approval.ResultParams{
		EvidenceID: approvalEvidenceIDFixture(t, 930),
		RequestID:  approvalRequestIDFixture(t, 920), Binding: binding,
		ProposerPrincipalID: proposer.PrincipalID(), ProposerSessionID: proposer.ID(),
		ApproverPrincipalID: approver.PrincipalID(), ApproverSessionID: approver.ID(),
		RequestVersion: 2, EvidenceVersion: 1,
		ApprovedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	if _, err := approval.NewResult(params); err != nil {
		t.Fatalf("NewResult() error = %v", err)
	}
	params.ApproverPrincipalID = proposer.PrincipalID()
	if _, err := approval.NewResult(params); !errors.Is(err, approval.ErrInvalidApprovalResult) {
		t.Fatalf("self-approved error = %v, want ErrInvalidApprovalResult", err)
	}
	params.ApproverPrincipalID = approver.PrincipalID()
	params.ExpiresAt = now
	if _, err := approval.NewResult(params); !errors.Is(err, approval.ErrInvalidApprovalResult) {
		t.Fatalf("expired error = %v, want ErrInvalidApprovalResult", err)
	}
}

func TestApprovalStateParsingIsClosed(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"pending", "approved", "consumed"} {
		state, err := approval.ParseState(value)
		if err != nil || state.String() != value {
			t.Fatalf("ParseState(%q) = (%q, %v)", value, state.String(), err)
		}
	}
	if _, err := approval.ParseState("expired"); !errors.Is(err, approval.ErrInvalidState) {
		t.Fatalf("ParseState(expired) error = %v, want ErrInvalidState", err)
	}
}

func approvalBindingFixture(t *testing.T) approval.Binding {
	t.Helper()
	baseline := approvalVectorFixture(t, 11, 7, 8, 6)
	proposed, err := baseline.NextPolicy()
	if err != nil {
		t.Fatal(err)
	}
	var semanticBytes [32]byte
	semanticBytes[0] = 1
	semanticHash, err := publication.NewSemanticHash(semanticBytes)
	if err != nil {
		t.Fatal(err)
	}
	var impactBytes [32]byte
	impactBytes[0] = 2
	impactHash, err := simulation.NewImpactHash(impactBytes)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := approval.NewBinding(approval.BindingParams{
		Scope: approvalScopeFixture(t), BaselineVector: baseline, ProposedVector: proposed,
		CandidateSemanticHash: semanticHash, CompilerFormatVersion: 3,
		ImpactHash: impactHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	return binding
}
