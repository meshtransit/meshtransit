package publication_test

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	publication "github.com/meshtransit/meshtransit/core/internal/domain/policy/publication"
)

func TestApprovalGateBindsCompleteSinglePolicyAdvance(t *testing.T) {
	t.Parallel()

	baseline := approvalAuthorityVectorFixture(t, 7, 4)
	proposed, err := baseline.NextPolicy()
	if err != nil {
		t.Fatalf("AuthorityVector.NextPolicy() error = %v", err)
	}
	requestID, err := publication.ParseApprovalRequestID(
		"01890f00-0000-7000-8000-000000000911",
	)
	if err != nil {
		t.Fatalf("ParseApprovalRequestID() error = %v", err)
	}
	evidenceID, err := publication.ParseApprovalEvidenceID(
		"01890f00-0000-7000-8000-000000000912",
	)
	if err != nil {
		t.Fatalf("ParseApprovalEvidenceID() error = %v", err)
	}
	impactHash, err := publication.NewApprovalImpactHash(sha256.Sum256([]byte("complete impact")))
	if err != nil {
		t.Fatalf("NewApprovalImpactHash() error = %v", err)
	}
	candidate := publicationCandidateFixture(t, 5, nil)
	approvedAt := publicationFixtureTime.Add(-time.Minute)
	gate, err := publication.NewApprovalGate(publication.ApprovalGateParams{
		Scope: publicationScopeFixture(t), RequestID: requestID, EvidenceID: evidenceID,
		BaselineVector: baseline, ProposedVector: proposed,
		CandidateSemanticHash: candidate.SemanticHash(), CompilerFormatVersion: 1,
		ImpactHash: impactHash, RequestVersion: 2, EvidenceVersion: 1,
		ApprovedAt: approvedAt, ExpiresAt: approvedAt.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("NewApprovalGate() error = %v", err)
	}
	if !gate.IsValid() || gate.RequestID() != requestID || gate.EvidenceID() != evidenceID ||
		!gate.BaselineVector().Equal(baseline) || !gate.ProposedVector().Equal(proposed) ||
		gate.CandidateSemanticHash() != candidate.SemanticHash() || gate.ImpactHash() != impactHash {
		t.Fatalf("ApprovalGate = %+v, want exact complete binding", gate)
	}
}

func TestApprovalGateRejectsIncompleteOrNonPolicyVector(t *testing.T) {
	t.Parallel()

	if _, err := publication.NewAuthorityVector(publication.AuthorityVectorParams{}); !errors.Is(
		err,
		publication.ErrInvalidAuthorityVector,
	) {
		t.Fatalf("NewAuthorityVector() error = %v, want ErrInvalidAuthorityVector", err)
	}
	baseline := approvalAuthorityVectorFixture(t, 7, 4)
	changed, err := publication.NewAuthorityVector(publication.AuthorityVectorParams{
		NetworkRevision: 8, InventoryRevision: 3, GroupRevision: 2, PolicyRevision: 5,
		DNSRevision: 1, RouteRevision: 1, SharingRevision: 1, IsolationGeneration: 1,
	})
	if err != nil {
		t.Fatalf("NewAuthorityVector(changed) error = %v", err)
	}
	requestID, _ := publication.ParseApprovalRequestID("01890f00-0000-7000-8000-000000000911")
	evidenceID, _ := publication.ParseApprovalEvidenceID("01890f00-0000-7000-8000-000000000912")
	impactHash, _ := publication.NewApprovalImpactHash(sha256.Sum256([]byte("complete impact")))
	candidate := publicationCandidateFixture(t, 5, nil)
	_, err = publication.NewApprovalGate(publication.ApprovalGateParams{
		Scope: publicationScopeFixture(t), RequestID: requestID, EvidenceID: evidenceID,
		BaselineVector: baseline, ProposedVector: changed,
		CandidateSemanticHash: candidate.SemanticHash(), CompilerFormatVersion: 1,
		ImpactHash: impactHash, RequestVersion: 2, EvidenceVersion: 1,
		ApprovedAt: publicationFixtureTime.Add(-time.Minute),
		ExpiresAt:  publicationFixtureTime.Add(time.Minute),
	})
	if !errors.Is(err, publication.ErrInvalidApprovalGate) {
		t.Fatalf("NewApprovalGate() error = %v, want ErrInvalidApprovalGate", err)
	}
}

func TestServiceRequiresExactLiveApprovalGate(t *testing.T) {
	t.Parallel()

	command := approvedPublicationCommandFixture(t)
	for _, test := range []struct {
		name       string
		evidenceID string
		expiresAt  time.Time
		wantErr    bool
	}{
		{
			name: "exact live evidence", evidenceID: command.ApprovalEvidenceID().String(),
			expiresAt: publicationFixtureTime.Add(time.Minute),
		},
		{
			name:       "different evidence",
			evidenceID: "01890f00-0000-7000-8000-000000000552",
			expiresAt:  publicationFixtureTime.Add(time.Minute), wantErr: true,
		},
		{
			name: "expired evidence", evidenceID: command.ApprovalEvidenceID().String(),
			expiresAt: publicationFixtureTime, wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			resolution := approvedPublicationResolutionFixture(
				t,
				command,
				test.evidenceID,
				test.expiresAt,
			)
			transaction := &publicationTransactionFixture{resolution: resolution}
			_, err := publicationServiceFixture(
				t,
				&publicationTransactionQueue{transactions: []*publicationTransactionFixture{
					transaction,
				}},
				&fixedPublicationMutationIDs{ids: publicationMutationIDsFixture(t, 0)},
				&publicationRetryFixture{},
				nil,
			).Publish(t.Context(), command)
			if test.wantErr {
				if !errors.Is(err, publication.ErrApprovalUnavailable) {
					t.Fatalf("Service.Publish() error = %v, want ErrApprovalUnavailable", err)
				}
				if len(transaction.changes) != 0 {
					t.Fatal("unavailable approval reached publication apply")
				}
				return
			}
			if err != nil {
				t.Fatalf("Service.Publish() error = %v", err)
			}
			if len(transaction.changes) != 1 ||
				transaction.changes[0].Resolution().ApprovalGate().EvidenceID() !=
					command.ApprovalEvidenceID() {
				t.Fatal("exact approval gate was not preserved into publication apply")
			}
		})
	}
}

func approvedPublicationCommandFixture(t *testing.T) publication.Command {
	t.Helper()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	principalID, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := accountsession.ParseID("01890f00-0000-7000-8000-000000000611")
	if err != nil {
		t.Fatal(err)
	}
	subjectID, err := accountsession.ParseIdentitySubjectID(
		"01890f00-0000-7000-8000-000000000711",
	)
	if err != nil {
		t.Fatal(err)
	}
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID,
		LoginWorkspaceID:  publicationScopeFixture(t).WorkspaceID(), HasLoginWorkspace: true,
		AuthenticationTime: publicationFixtureTime.Add(-time.Minute),
		ACR:                "urn:meshtransit:assurance:mfa", AMR: []string{"pwd", "mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt:     publicationFixtureTime.Add(time.Hour),
		AbsoluteExpiresAt: publicationFixtureTime.Add(8 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	evidenceID, err := publication.ParseApprovalEvidenceID(
		"01890f00-0000-7000-8000-000000000551",
	)
	if err != nil {
		t.Fatal(err)
	}
	reason, err := publication.NewAuditReason("publish independently approved policy")
	if err != nil {
		t.Fatal(err)
	}
	command, err := publication.NewApprovedManagementCommand(publication.ManagementCommandParams{
		Candidate: publicationCandidateFixture(t, 2, nil), BasePolicyRevision: 1,
		AccountSession: session, ApprovalEvidenceID: evidenceID, AuditReason: reason,
	})
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func approvedPublicationResolutionFixture(
	t *testing.T,
	command publication.Command,
	evidenceIDValue string,
	expiresAt time.Time,
) publication.Resolution {
	t.Helper()
	baseline := approvalAuthorityVectorFixture(t, 5, 1)
	proposed, err := baseline.NextPolicy()
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := publication.ParseApprovalRequestID(
		"01890f00-0000-7000-8000-000000000550",
	)
	if err != nil {
		t.Fatal(err)
	}
	evidenceID, err := publication.ParseApprovalEvidenceID(evidenceIDValue)
	if err != nil {
		t.Fatal(err)
	}
	impactHash, err := publication.NewApprovalImpactHash(sha256.Sum256([]byte("complete impact")))
	if err != nil {
		t.Fatal(err)
	}
	gate, err := publication.NewApprovalGate(publication.ApprovalGateParams{
		Scope: command.Candidate().Snapshot().Scope(), RequestID: requestID,
		EvidenceID: evidenceID, BaselineVector: baseline, ProposedVector: proposed,
		CandidateSemanticHash: command.Candidate().SemanticHash(),
		CompilerFormatVersion: command.Candidate().CompilerFormatVersion(),
		ImpactHash:            impactHash, RequestVersion: 2, EvidenceVersion: 1,
		ApprovedAt: publicationFixtureTime.Add(-time.Minute), ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := publication.NewResolution(publication.ResolutionParams{
		Scope: command.Candidate().Snapshot().Scope(), AuthorityVector: baseline,
		ApprovalGate: gate,
	})
	if err != nil {
		t.Fatal(err)
	}
	return resolution
}

func approvalAuthorityVectorFixture(
	t *testing.T,
	networkRevision int64,
	policyRevision int64,
) publication.AuthorityVector {
	t.Helper()
	vector, err := publication.NewAuthorityVector(publication.AuthorityVectorParams{
		NetworkRevision: networkRevision, InventoryRevision: 2, GroupRevision: 2,
		PolicyRevision: policyRevision, DNSRevision: 1, RouteRevision: 1,
		SharingRevision: 1, IsolationGeneration: 1,
	})
	if err != nil {
		t.Fatalf("NewAuthorityVector() error = %v", err)
	}
	return vector
}
