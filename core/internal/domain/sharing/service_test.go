package sharing

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/platform/idempotency"
)

func TestServiceCreatesExactOfferAndPreservesRepositoryError(t *testing.T) {
	t.Parallel()

	command, result := sharingServiceCreateFixture(t)
	repository := &sharingRepositoryFixture{createResult: result}
	service := sharingServiceFixture(t, repository)
	got, err := service.CreateOffer(context.Background(), command)
	if err != nil || !got.IsValid() || !repository.createCalled {
		t.Fatalf("CreateOffer() = %+v, %v; reached repository=%v", got, err, repository.createCalled)
	}

	repository.createErr = ErrConflict
	if _, err := service.CreateOffer(context.Background(), command); !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateOffer() error = %v, want ErrConflict", err)
	}
}

func TestServiceRejectsMismatchedCommittedOffer(t *testing.T) {
	t.Parallel()

	command, result := sharingServiceCreateFixture(t)
	params := command.params
	params.ExpiresAt = params.ExpiresAt.Add(-time.Hour)
	command, err := NewCreateOffer(params)
	if err != nil {
		t.Fatal(err)
	}
	service := sharingServiceFixture(t, &sharingRepositoryFixture{createResult: result})
	if _, err := service.CreateOffer(context.Background(), command); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CreateOffer() error = %v, want fail-closed ErrUnavailable", err)
	}
}

func TestCreateOfferExpiryMatchesPostgreSQLPrecision(t *testing.T) {
	t.Parallel()

	command, result := sharingServiceCreateFixture(t)
	params := command.params
	params.ExpiresAt = params.ExpiresAt.Add(789 * time.Nanosecond)
	canonical, err := NewCreateOffer(params)
	if err != nil {
		t.Fatal(err)
	}
	if !canonical.ExpiresAt().Equal(command.ExpiresAt()) ||
		canonical.ExpiresAt().After(params.ExpiresAt) {
		t.Fatalf("CreateOffer expiry = %s, input = %s", canonical.ExpiresAt(), params.ExpiresAt)
	}
	service := sharingServiceFixture(t, &sharingRepositoryFixture{createResult: result})
	if _, err := service.CreateOffer(context.Background(), canonical); err != nil {
		t.Fatalf("microsecond committed offer rejected: %v", err)
	}
}

func TestCreateOfferNeverExpiresKeepsDecisionDeadlineBounded(t *testing.T) {
	t.Parallel()
	command, result := sharingServiceCreateFixture(t)
	command.params.ExpiresAt = NoExpiryTime()
	previous, _ := result.Offer()
	offerParams := previous.Offer().params
	offerParams.ExpiresAt = previous.CreatedAt().Add(7 * 24 * time.Hour)
	offer, err := NewOffer(offerParams)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewOfferSnapshot(offer, previous.Resource(), NoExpiryTime(), previous.CreatedAt())
	if err != nil {
		t.Fatal(err)
	}
	result.offer = snapshot
	if !createOfferResultMatches(result, command) {
		t.Fatal("bounded offer and no-expiry share did not match")
	}
	offerParams.ExpiresAt = offerParams.ExpiresAt.Add(time.Microsecond)
	offer, err = NewOffer(offerParams)
	if err != nil {
		t.Fatal(err)
	}
	result.offer, err = NewOfferSnapshot(offer, previous.Resource(), NoExpiryTime(), previous.CreatedAt())
	if err != nil {
		t.Fatal(err)
	}
	if createOfferResultMatches(result, command) {
		t.Fatal("offer bearer deadline beyond seven days was accepted")
	}
}

func TestServiceRejectsListItemFromWrongDirection(t *testing.T) {
	t.Parallel()

	command, result := sharingServiceCreateFixture(t)
	snapshot, _ := result.Offer()
	page, err := NewOfferPage([]OfferSnapshot{snapshot}, 2, EmptyPageCursor())
	if err != nil {
		t.Fatal(err)
	}
	service := sharingServiceFixture(t, &sharingRepositoryFixture{listResult: page})
	_, err = service.ListOffers(
		context.Background(), command.AccountSession(), command.ConsumerScope(),
		DirectionOutgoing, OfferStateOffered, 50, EmptyPageCursor(),
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ListOffers() error = %v, want wrong-side ErrUnavailable", err)
	}
}

func TestServiceStopsBeforeRepositoryOnCancelledContext(t *testing.T) {
	t.Parallel()

	command, _ := sharingServiceCreateFixture(t)
	repository := &sharingRepositoryFixture{}
	service := sharingServiceFixture(t, repository)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.CreateOffer(ctx, command); !errors.Is(err, context.Canceled) {
		t.Fatalf("CreateOffer() error = %v, want context cancellation", err)
	}
	if repository.createCalled {
		t.Fatal("cancelled request reached repository")
	}
}

type sharingRepositoryFixture struct {
	contractResult ContractSnapshot
	contractErr    error
	contractCalled bool
	createResult   MutationResult
	createErr      error
	createCalled   bool
	listResult     OfferPage
}

func (fixture *sharingRepositoryFixture) CreateOffer(
	_ context.Context,
	_ CreateOffer,
) (MutationResult, error) {
	fixture.createCalled = true
	return fixture.createResult, fixture.createErr
}

func (*sharingRepositoryFixture) DecideOffer(
	context.Context,
	DecideOffer,
) (MutationResult, error) {
	return MutationResult{}, ErrUnavailable
}

func (*sharingRepositoryFixture) ActivateContract(
	context.Context, ActivateContract,
) (MutationResult, error) {
	return MutationResult{}, ErrUnavailable
}

func (*sharingRepositoryFixture) RevokeContract(
	context.Context,
	RevokeContract,
) (MutationResult, error) {
	return MutationResult{}, ErrUnavailable
}

func (*sharingRepositoryFixture) GetOffer(
	context.Context,
	accountsession.Session,
	network.Scope,
	OfferID,
) (OfferSnapshot, error) {
	return OfferSnapshot{}, ErrUnavailable
}

func (fixture *sharingRepositoryFixture) ListOffers(
	_ context.Context,
	_ accountsession.Session,
	_ network.Scope,
	_ Direction,
	_ OfferState,
	_ int,
	_ PageCursor,
) (OfferPage, error) {
	return fixture.listResult, nil
}

func sharingServiceFixture(t *testing.T, repository Repository) *Service {
	t.Helper()
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func sharingServiceCreateFixture(t *testing.T) (CreateOffer, MutationResult) {
	t.Helper()
	offer := mustOffer(t)
	binding := mustResourceBinding(t, offer.ProviderScope())
	snapshot, err := NewOfferSnapshot(offer, binding, offer.ExpiresAt(), sharingServiceNow().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	token, err := NewOfferToken([32]byte{31: 1})
	if err != nil {
		t.Fatal(err)
	}
	result, err := NewMutationResult(MutationResultParams{
		Offer: snapshot, Token: token, HasOffer: true, HasToken: true,
		ProviderNetworkRevision: 2, ProviderSharingRevision: 2,
		ConsumerNetworkRevision: 2, ConsumerSharingRevision: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	reason, _ := NewAuditReason("share reviewed Resource")
	proof, _ := idempotency.NewProof("test-key", [32]byte{31: 2})
	command, err := NewCreateOffer(CreateOfferParams{
		ProviderScope: offer.ProviderScope(), ConsumerScope: offer.ConsumerScope(),
		ResourceID: binding.ResourceID(), MaximumTraffic: offer.MaximumTraffic(),
		ExpiresAt: offer.ExpiresAt(), AccountSession: sharingSessionFixture(t),
		Reason: reason, Idempotency: proof,
	})
	if err != nil {
		t.Fatal(err)
	}
	return command, result
}

func sharingSessionFixture(t *testing.T) accountsession.Session {
	t.Helper()
	deploymentID, _ := deployment.ParseID(uuidWithSuffix(20))
	principalID, _ := identity.ParsePrincipalID(uuidWithSuffix(21))
	sessionID, _ := accountsession.ParseID(uuidWithSuffix(22))
	subjectID, _ := accountsession.ParseIdentitySubjectID(uuidWithSuffix(23))
	workspaceID, _ := workspace.ParseID(uuidWithSuffix(1))
	now := sharingServiceNow()
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID, LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: now.Add(-time.Hour), ACR: "urn:meshtransit:test", AMR: []string{"mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func sharingServiceNow() time.Time {
	return time.Date(2026, time.September, 29, 1, 0, 0, 0, time.UTC)
}

func (fixture *sharingRepositoryFixture) GetContract(_ context.Context, _ accountsession.Session, _ network.Scope, _ ContractID) (ContractSnapshot, error) {
	fixture.contractCalled = true
	return fixture.contractResult, fixture.contractErr
}

func TestGetContractRejectsMismatchedRepositoryEvidence(t *testing.T) {
	t.Parallel()
	contract := mustContract(t)
	name, err := resource.ParseDisplayName("database")
	if err != nil {
		t.Fatal(err)
	}
	accessName, err := ParseAccessName("database.shared.consumer.example")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewContractSnapshot(ContractSnapshotParams{Contract: contract, ImportedDisplayName: name, ImportedResourceVersion: 2, AccessName: accessName})
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := ParseContractID(uuidWithSuffix(10))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		scope  network.Scope
		id     ContractID
		result ContractSnapshot
		want   error
	}{
		{name: "current consumer", scope: contract.ConsumerScope(), id: contract.ID(), result: snapshot},
		{name: "foreign consumer", scope: contract.ProviderScope(), id: contract.ID(), result: snapshot, want: ErrUnavailable},
		{name: "wrong identity", scope: contract.ConsumerScope(), id: otherID, result: snapshot, want: ErrUnavailable},
		{name: "empty snapshot", scope: contract.ConsumerScope(), id: contract.ID(), want: ErrUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := &sharingRepositoryFixture{contractResult: test.result}
			service := sharingServiceFixture(t, repository)
			result, err := service.GetContract(context.Background(), sharingSessionFixture(t), test.scope, test.id)
			if !errors.Is(err, test.want) || !repository.contractCalled {
				t.Fatal("contract result or evaluation instant", err)
			}
			if test.want == nil && result.Contract().ID() != contract.ID() {
				t.Fatal("current identity changed")
			}
		})
	}
	repository := &sharingRepositoryFixture{contractResult: snapshot}
	service := sharingServiceFixture(t, repository)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.GetContract(ctx, sharingSessionFixture(t), contract.ConsumerScope(), contract.ID()); !errors.Is(err, context.Canceled) || repository.contractCalled {
		t.Fatal("cancelled read reached authority repository", err)
	}
}
