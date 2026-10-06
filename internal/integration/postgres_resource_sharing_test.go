//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/sharing"
	"github.com/meshtransit/meshtransit/internal/sharing/endpointpublication"
)

func assertCurrentConsumerContractRead(ctx context.Context, t *testing.T, service *sharing.Service, session accountsession.Session, contract sharing.Contract, accessName sharing.AccessName, importedVersion int64) {
	t.Helper()
	current, err := service.GetContract(ctx, session, contract.ConsumerScope(), contract.ID())
	if err != nil || !current.IsValid() || current.Contract().ID() != contract.ID() || current.Contract().Version() != contract.Version() ||
		current.Contract().State() != contract.State() || current.ImportedResourceVersion() != importedVersion || current.AccessName() != accessName {
		t.Fatal("consumer read lost current lifecycle, version or naming intent", err)
	}
	if _, err := service.GetContract(ctx, session, contract.ProviderScope(), contract.ID()); !errors.Is(err, sharing.ErrNotFound) {
		t.Fatal("provider scope exposed consumer-local imported metadata", err)
	}
}

func assertPostgreSQLResourceSharing(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	worker *pgx.Conn,
	workerPool *postgresadapter.Pool,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	store := newIntegrationResourceSharingStore(t, runtimePool)
	service, err := sharing.NewService(store, sharing.SystemClock{})
	if err != nil {
		t.Fatalf("sharing.NewService() error = %v", err)
	}
	session := managementRBACAccountSessionFixture(t)
	providerScope := resourceAuthorityScope(t, 103, 203)
	consumerScope := resourceAuthorityScope(t, 103, 204)
	resourceID := createDirectDeviceResourceFixture(ctx, t, admin, runtimePool)
	maximumTraffic := integrationSharingTraffic(t)
	reason, err := sharing.NewAuditReason("share production Resource with an exact consumer Network")
	if err != nil {
		t.Fatalf("sharing.NewAuditReason() error = %v", err)
	}
	createCommand, err := sharing.NewCreateOffer(sharing.CreateOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ResourceID: resourceID, MaximumTraffic: maximumTraffic,
		ExpiresAt: time.Now().UTC().Add(time.Hour), AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 111),
	})
	if err != nil {
		t.Fatalf("sharing.NewCreateOffer() error = %v", err)
	}
	created, err := service.CreateOffer(ctx, createCommand)
	if err != nil {
		t.Fatalf("Resource Sharing CreateOffer() error = %v", err)
	}
	createdOffer, hasOffer := created.Offer()
	token, hasToken := created.Token()
	if !hasOffer || !hasToken || !token.IsValid() ||
		createdOffer.Offer().State() != sharing.OfferStateOffered ||
		createdOffer.Resource().ResourceID() != resourceID {
		t.Fatalf("Resource Sharing create result = %+v", created)
	}
	replayedCreate, err := service.CreateOffer(ctx, createCommand)
	if err != nil {
		t.Fatalf("Resource Sharing CreateOffer() replay error = %v", err)
	}
	replayedToken, replayedHasToken := replayedCreate.Token()
	if !replayedHasToken || replayedToken != token ||
		replayedCreate.ProviderSharingRevision() != created.ProviderSharingRevision() ||
		replayedCreate.ConsumerSharingRevision() != created.ConsumerSharingRevision() {
		t.Fatalf("Resource Sharing create replay = %+v", replayedCreate)
	}
	outgoing, err := service.ListOffers(
		ctx, session, providerScope, sharing.DirectionOutgoing,
		sharing.OfferStateOffered, 10, sharing.EmptyPageCursor(),
	)
	if err != nil || len(outgoing.Items()) != 1 ||
		outgoing.Items()[0].Offer().ID() != createdOffer.Offer().ID() {
		t.Fatalf("Resource Sharing outgoing page = %+v, error = %v", outgoing, err)
	}
	incoming, err := service.ListOffers(
		ctx, session, consumerScope, sharing.DirectionIncoming,
		sharing.OfferStateOffered, 10, sharing.EmptyPageCursor(),
	)
	if err != nil || len(incoming.Items()) != 1 ||
		incoming.Items()[0].Offer().ID() != createdOffer.Offer().ID() {
		t.Fatalf("Resource Sharing incoming page = %+v, error = %v", incoming, err)
	}
	importedName, err := resource.ParseDisplayName("Imported production Resource")
	if err != nil {
		t.Fatalf("resource.ParseDisplayName() error = %v", err)
	}
	// The offer carries the default label and the Core-derived name; the
	// consumer accepts without typing one.
	accessName := createdOffer.AccessName()
	assertDerivedAccessName(t, createdOffer)
	acceptCommand, err := sharing.NewDecideOffer(sharing.DecideOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		OfferID: createdOffer.Offer().ID(), ExpectedOfferVersion: 1,
		Token: token, Action: sharing.DecisionActionAccept,
		ImportedDisplayName: importedName, AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 112),
	})
	if err != nil {
		t.Fatalf("sharing.NewDecideOffer() error = %v", err)
	}
	accepted, err := service.DecideOffer(ctx, acceptCommand)
	if err != nil {
		t.Fatalf("Resource Sharing DecideOffer() error = %v", err)
	}
	acceptedOffer, hasOffer := accepted.Offer()
	contract, hasContract := accepted.Contract()
	if !hasOffer || !hasContract || acceptedOffer.Offer().State() != sharing.OfferStateAccepted ||
		contract.State() != sharing.ContractStateActivating ||
		contract.ProviderScope() != providerScope || contract.ConsumerScope() != consumerScope {
		t.Fatalf("Resource Sharing accept result = %+v", accepted)
	}
	assertImportedResourceAccessName(
		ctx, t, admin, contract.ImportedResourceID(), accessName, "reserved", 1,
	)
	assertCurrentConsumerContractRead(ctx, t, service, session, contract, accessName, 1)
	replayedAccept, err := service.DecideOffer(ctx, acceptCommand)
	if err != nil {
		t.Fatalf("Resource Sharing DecideOffer() replay error = %v", err)
	}
	replayedContract, replayedHasContract := replayedAccept.Contract()
	if !replayedHasContract || replayedContract.ID() != contract.ID() ||
		replayedAccept.ConsumerSharingRevision() != accepted.ConsumerSharingRevision() {
		t.Fatalf("Resource Sharing accept replay = %+v", replayedAccept)
	}
	assertAccessNameCollisionRollsBack(
		ctx,
		t,
		admin,
		service,
		session,
		providerScope,
		consumerScope,
		resourceID,
		maximumTraffic,
		reason,
		accessName,
	)
	activateCommand, err := sharing.NewActivateContract(sharing.ActivateContractParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ContractID: contract.ID(), ExpectedContractVersion: contract.Version(),
		AccountSession: session, Reason: reason, Idempotency: resourceAuthorityProof(t, 113),
	})
	if err != nil {
		t.Fatalf("sharing.NewActivateContract() error = %v", err)
	}
	assertShareTargetFailures(ctx, t, admin, service, activateCommand)
	activated, err := service.ActivateContract(ctx, activateCommand)
	if err != nil {
		t.Fatalf("Resource Sharing ActivateContract() error = %v", err)
	}
	activeContract, hasContract := activated.Contract()
	if !hasContract || activeContract.State() != sharing.ContractStateActive ||
		activeContract.Version() != contract.Version()+1 || activated.ImportedResourceVersion() != 2 {
		t.Fatalf("Resource Sharing activate result = %+v", activated)
	}
	assertSameWorkspaceAliasEndpoint(ctx, t, admin, activeContract.ImportedResourceID(), "provisioning", 1, "reserved")
	assertCurrentConsumerContractRead(ctx, t, service, session, activeContract, accessName, 2)
	replayedActivation, err := service.ActivateContract(ctx, activateCommand)
	if err != nil {
		t.Fatalf("Resource Sharing ActivateContract() replay error = %v", err)
	}
	replayedActiveContract, replayedHasContract := replayedActivation.Contract()
	if !replayedHasContract || replayedActiveContract.ID() != activeContract.ID() ||
		replayedActiveContract.Version() != activeContract.Version() ||
		replayedActivation.ConsumerSharingRevision() != activated.ConsumerSharingRevision() {
		t.Fatalf("Resource Sharing activate replay = %+v", replayedActivation)
	}
	resolved, err := store.ResolveImportedPolicyDestinations(
		ctx,
		session,
		consumerScope,
		[]sharing.ImportedResourceID{activeContract.ImportedResourceID()},
	)
	if err != nil || len(resolved) != 1 ||
		resolved[0].ImportedResourceID() != activeContract.ImportedResourceID() ||
		resolved[0].ImportedResourceVersion() != 2 ||
		resolved[0].Contract().ID() != activeContract.ID() ||
		resolved[0].Contract().State() != sharing.ContractStateActive {
		t.Fatalf("ResolveImportedPolicyDestinations() = %+v, error = %v", resolved, err)
	}
	assertAtomicImportedPolicyPublication(ctx, t, admin, session, resolved[0])
	assertImportedPolicySimulation(ctx, t, admin, runtimePool, store, session, resolved[0])
	crossWorkspaceImport := assertCrossWorkspaceResourceSharingConsent(
		ctx, t, admin, workerPool, runtimePool, service, providerScope, resourceID, maximumTraffic, reason,
	)
	assertLegacyRevokeWithdrawsSameWorkspaceAlias(ctx, t, admin, activeContract)
	revokeCommand, err := sharing.NewRevokeContract(sharing.RevokeContractParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ContractID: activeContract.ID(), ExpectedContractVersion: activeContract.Version(),
		LocalScope: consumerScope, AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 114),
	})
	if err != nil {
		t.Fatalf("sharing.NewRevokeContract() error = %v", err)
	}
	revoked, err := service.RevokeContract(ctx, revokeCommand)
	if err != nil {
		t.Fatalf("Resource Sharing RevokeContract() error = %v", err)
	}
	revokedContract, hasContract := revoked.Contract()
	if !hasContract || revokedContract.State() != sharing.ContractStateRevoked ||
		revokedContract.Version() != activeContract.Version()+1 ||
		revoked.ImportedResourceVersion() != 3 {
		t.Fatalf("Resource Sharing revoke result = %+v", revoked)
	}
	assertImportedResourceAccessName(
		ctx, t, admin, contract.ImportedResourceID(), accessName, "withdrawn", 2,
	)
	assertCurrentConsumerContractRead(ctx, t, service, session, revokedContract, accessName, 3)
	assertRevokedShareExplained(ctx, t, admin, runtimePool, session, consumerScope, revokedContract)
	assertSameWorkspaceAliasEndpoint(ctx, t, admin, activeContract.ImportedResourceID(), "revoked", 2, "withdrawn")
	foreignConsumerScope := resourceAuthorityScope(t, 102, 202)
	foreignConsumerSession := authorityConfirmerAccountSessionFixture(t)
	sqlPublicationContract, aliasAccessName := createUnstagedPrivateEndpointFixture(
		ctx, t, service, session, foreignConsumerSession, providerScope, foreignConsumerScope,
		resourceID, maximumTraffic, reason, 128,
	)
	// The revoked same-Workspace share released fd00:feed::1 (no client lease
	// ever held it); the active cross-Workspace share still retains ::2.
	assertPrivateEndpointPublication(ctx, t, admin, worker,
		sqlPublicationContract.ImportedResourceID(), aliasAccessName, "fd00:feed::1/128")
	aliasRevoke, err := sharing.NewRevokeContract(sharing.RevokeContractParams{
		ProviderScope: providerScope, ConsumerScope: foreignConsumerScope,
		ContractID: sqlPublicationContract.ID(), ExpectedContractVersion: sqlPublicationContract.Version(),
		LocalScope: foreignConsumerScope, AccountSession: foreignConsumerSession,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 131),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RevokeContract(ctx, aliasRevoke); err != nil {
		t.Fatal(err)
	}
	assertPrivateEndpointPublicationWithdrawn(ctx, t, admin,
		sqlPublicationContract.ImportedResourceID(), aliasAccessName)
	unstagedContract, _ := createUnstagedPrivateEndpointFixture(
		ctx, t, service, session, foreignConsumerSession, providerScope, foreignConsumerScope,
		resourceID, maximumTraffic, reason, 125,
	)
	unstagedImport := unstagedContract.ImportedResourceID()
	assertAutomaticPrivateEndpointInvalidation(
		ctx, t, admin, worker, workerPool, crossWorkspaceImport, unstagedImport,
	)
	if _, err := store.ResolveImportedPolicyDestinations(
		ctx,
		session,
		consumerScope,
		[]sharing.ImportedResourceID{activeContract.ImportedResourceID()},
	); !errors.Is(err, sharing.ErrConflict) {
		t.Fatalf("ResolveImportedPolicyDestinations() after revoke error = %v, want conflict", err)
	}
	readBack, err := service.GetOffer(ctx, session, providerScope, createdOffer.Offer().ID())
	if err != nil || readBack.Offer().State() != sharing.OfferStateAccepted {
		t.Fatalf("Resource Sharing GetOffer() = %+v, error = %v", readBack, err)
	}
	foreignScope := resourceAuthorityScope(t, 102, 202)
	if _, err := service.ListOffers(
		ctx, session, foreignScope, sharing.DirectionOutgoing,
		sharing.OfferStateUnknown, 10, sharing.EmptyPageCursor(),
	); !errors.Is(err, sharing.ErrForbidden) {
		t.Fatalf("cross-Workspace Resource Sharing list error = %v, want forbidden", err)
	}
	assertCommittedResourceSharingEvidence(ctx, t, admin, createdOffer.Offer().ID(), contract.ID())
	assertExpiredUnprovisionedContractCleanup(
		ctx, t, admin, store, session, providerScope, consumerScope, resourceID, maximumTraffic, reason,
	)
	// Alias pools for both roles exist from the cross-Workspace qualification;
	// a fresh same-Workspace share now exercises the complete alias path.
	sameWorkspaceShare, _ := createUnstagedPrivateEndpointFixture(
		ctx, t, service, session, session, providerScope, consumerScope,
		resourceID, maximumTraffic, reason, 160,
	)
	assertSameWorkspaceAliasAllocation(ctx, t, admin, sameWorkspaceShare)
	assertSameWorkspaceAliasMapProjection(ctx, t, admin, sameWorkspaceShare)
	assertShareAccessLabelRules(
		ctx, t, admin, service, session, providerScope, consumerScope, foreignScope,
		resourceID, maximumTraffic, reason,
	)
}

func assertExpiredUnprovisionedContractCleanup(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	store *postgresadapter.ResourceSharingStore,
	session accountsession.Session,
	providerScope, consumerScope network.Scope,
	resourceID resource.ID,
	maximumTraffic sharing.TrafficSet,
	reason sharing.AuditReason,
) {
	t.Helper()
	base := time.Now().UTC()
	firstExpiry := base.Add(2 * time.Minute)
	firstCommand, err := sharing.NewCreateOffer(sharing.CreateOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ResourceID: resourceID, MaximumTraffic: maximumTraffic,
		ExpiresAt: firstExpiry, AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 140),
	})
	if err != nil {
		t.Fatal(err)
	}
	firstCreated, err := store.CreateOffer(ctx, firstCommand, base)
	if err != nil {
		t.Fatalf("create expiring unprovisioned Share Offer: %v", err)
	}
	firstOffer, hasOffer := firstCreated.Offer()
	firstToken, hasToken := firstCreated.Token()
	if !hasOffer || !hasToken {
		t.Fatalf("expiring unprovisioned Share Offer = %+v", firstCreated)
	}
	importedName, err := resource.ParseDisplayName("Reusable expired Resource")
	if err != nil {
		t.Fatal(err)
	}
	// A consumer may still send the derived name; it must match exactly.
	accessName := firstOffer.AccessName()
	firstDecision, err := sharing.NewDecideOffer(sharing.DecideOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		OfferID: firstOffer.Offer().ID(), ExpectedOfferVersion: firstOffer.Offer().Version(),
		Token: firstToken, Action: sharing.DecisionActionAccept,
		ImportedDisplayName: importedName, AccessName: accessName, AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 141),
	})
	if err != nil {
		t.Fatal(err)
	}
	firstAccepted, err := store.DecideOffer(ctx, firstDecision, base.Add(time.Second))
	if err != nil {
		t.Fatalf("accept expiring unprovisioned Share Offer: %v", err)
	}
	firstContract, hasContract := firstAccepted.Contract()
	if !hasContract || firstContract.State() != sharing.ContractStateActivating {
		t.Fatalf("expiring unprovisioned Contract = %+v", firstAccepted)
	}
	firstRevoke, err := sharing.NewRevokeContract(sharing.RevokeContractParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ContractID: firstContract.ID(), ExpectedContractVersion: firstContract.Version(),
		LocalScope: consumerScope, AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 142),
	})
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := store.RevokeContract(
		ctx,
		firstRevoke,
		firstContract.ExpiresAt().Add(time.Nanosecond),
	)
	if err != nil {
		t.Fatalf("clean expired unprovisioned Trust Contract: %v", err)
	}
	revokedContract, hasContract := revoked.Contract()
	if !hasContract || revokedContract.State() != sharing.ContractStateRevoked {
		t.Fatalf("expired unprovisioned cleanup = %+v", revoked)
	}
	assertImportedResourceAccessName(
		ctx, t, admin, firstContract.ImportedResourceID(), accessName, "withdrawn", 2,
	)

	secondAt := firstContract.ExpiresAt().Add(time.Second)
	secondCommand, err := sharing.NewCreateOffer(sharing.CreateOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ResourceID: resourceID, MaximumTraffic: maximumTraffic,
		ExpiresAt: secondAt.Add(time.Hour), AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 143),
	})
	if err != nil {
		t.Fatal(err)
	}
	secondCreated, err := store.CreateOffer(ctx, secondCommand, secondAt)
	if err != nil {
		t.Fatalf("create replacement Share Offer: %v", err)
	}
	secondOffer, hasOffer := secondCreated.Offer()
	secondToken, hasToken := secondCreated.Token()
	if !hasOffer || !hasToken {
		t.Fatalf("replacement Share Offer = %+v", secondCreated)
	}
	secondDecision, err := sharing.NewDecideOffer(sharing.DecideOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		OfferID: secondOffer.Offer().ID(), ExpectedOfferVersion: secondOffer.Offer().Version(),
		Token: secondToken, Action: sharing.DecisionActionAccept,
		ImportedDisplayName: importedName, AccessName: accessName, AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 144),
	})
	if err != nil {
		t.Fatal(err)
	}
	secondAccepted, err := store.DecideOffer(ctx, secondDecision, secondAt.Add(time.Second))
	if err != nil {
		t.Fatalf("reuse withdrawn access name: %v", err)
	}
	secondContract, hasContract := secondAccepted.Contract()
	if !hasContract || secondContract.State() != sharing.ContractStateActivating ||
		secondContract.ImportedResourceID() == firstContract.ImportedResourceID() {
		t.Fatalf("replacement accepted Contract = %+v", secondAccepted)
	}
	assertImportedResourceAccessName(
		ctx, t, admin, secondContract.ImportedResourceID(), accessName, "reserved", 1,
	)
}

func createUnstagedPrivateEndpointFixture(
	ctx context.Context,
	t *testing.T,
	service *sharing.Service,
	providerSession, consumerSession accountsession.Session,
	providerScope, consumerScope network.Scope,
	resourceID resource.ID,
	maximumTraffic sharing.TrafficSet,
	reason sharing.AuditReason,
	proofMarker byte,
) (sharing.Contract, sharing.AccessName) {
	t.Helper()
	created, err := service.CreateOffer(ctx, mustCreateSharingOffer(
		t, providerScope, consumerScope, resourceID, maximumTraffic, providerSession, reason, proofMarker, "unstaged",
	))
	if err != nil {
		t.Fatalf("create unstaged Private Endpoint offer: %v", err)
	}
	offer, hasOffer := created.Offer()
	token, hasToken := created.Token()
	if !hasOffer || !hasToken {
		t.Fatalf("unstaged Private Endpoint offer result = %+v", created)
	}
	name, err := resource.ParseDisplayName("Unstaged production Resource")
	if err != nil {
		t.Fatal(err)
	}
	accessName := offer.AccessName()
	decision, err := sharing.NewDecideOffer(sharing.DecideOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		OfferID: offer.Offer().ID(), ExpectedOfferVersion: offer.Offer().Version(),
		Token: token, Action: sharing.DecisionActionAccept,
		ImportedDisplayName: name, AccessName: accessName, AccountSession: consumerSession,
		Reason: reason, Idempotency: resourceAuthorityProof(t, proofMarker+1),
	})
	if err != nil {
		t.Fatalf("construct unstaged Private Endpoint acceptance: %v", err)
	}
	accepted, err := service.DecideOffer(ctx, decision)
	if err != nil {
		t.Fatalf("accept unstaged Private Endpoint offer: %v", err)
	}
	contract, hasContract := accepted.Contract()
	if !hasContract {
		t.Fatalf("unstaged Private Endpoint acceptance = %+v", accepted)
	}
	activation, err := sharing.NewActivateContract(sharing.ActivateContractParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ContractID: contract.ID(), ExpectedContractVersion: contract.Version(),
		AccountSession: consumerSession, Reason: reason,
		Idempotency: resourceAuthorityProof(t, proofMarker+2),
	})
	if err != nil {
		t.Fatalf("construct unstaged Private Endpoint activation: %v", err)
	}
	activated, err := service.ActivateContract(ctx, activation)
	if err != nil {
		t.Fatalf("activate unstaged Private Endpoint: %v", err)
	}
	activeContract, hasContract := activated.Contract()
	if !hasContract || activeContract.State() != sharing.ContractStateActive {
		t.Fatalf("unstaged Private Endpoint activation = %+v", activated)
	}
	return activeContract, accessName
}

func assertCrossWorkspaceResourceSharingConsent(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	workerPool *postgresadapter.Pool,
	runtimePool *postgresadapter.Pool,
	service *sharing.Service,
	providerScope network.Scope,
	resourceID resource.ID,
	maximumTraffic sharing.TrafficSet,
	reason sharing.AuditReason,
) sharing.ImportedResourceID {
	t.Helper()
	seedCrossWorkspaceShareConsumerAuthority(ctx, t, admin)
	providerSession := managementRBACAccountSessionFixture(t)
	consumerSession := authorityConfirmerAccountSessionFixture(t)
	consumerScope := resourceAuthorityScope(t, 102, 202)
	assertCrossWorkspaceNoExpiryOffer(ctx, t, service, providerScope, consumerScope, resourceID, maximumTraffic,
		reason, providerSession, consumerSession)
	createCommand, err := sharing.NewCreateOffer(sharing.CreateOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ResourceID: resourceID, MaximumTraffic: maximumTraffic,
		ExpiresAt: time.Now().UTC().Add(time.Hour), AccountSession: providerSession,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 121),
	})
	if err != nil {
		t.Fatalf("construct cross-Workspace Share Offer: %v", err)
	}
	created, err := service.CreateOffer(ctx, createCommand)
	if err != nil {
		t.Fatalf("create cross-Workspace Share Offer: %v", err)
	}
	offer, hasOffer := created.Offer()
	token, hasToken := created.Token()
	if !hasOffer || !hasToken ||
		offer.Offer().ScopeRelation() != sharing.ScopeRelationCrossWorkspace ||
		!offer.Offer().ScopeRelation().RequiresIndependentWorkspaceConsent() {
		t.Fatalf("cross-Workspace Share Offer = %+v", created)
	}
	importedName, err := resource.ParseDisplayName("Cross Workspace production Resource")
	if err != nil {
		t.Fatalf("parse cross-Workspace Imported Resource name: %v", err)
	}
	accessName := offer.AccessName()
	providerDecision, err := sharing.NewDecideOffer(sharing.DecideOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		OfferID: offer.Offer().ID(), ExpectedOfferVersion: offer.Offer().Version(),
		Token: token, Action: sharing.DecisionActionAccept,
		ImportedDisplayName: importedName, AccessName: accessName, AccountSession: providerSession,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 122),
	})
	if err != nil {
		t.Fatalf("construct unauthorized provider acceptance: %v", err)
	}
	if _, err := service.DecideOffer(ctx, providerDecision); !errors.Is(err, sharing.ErrForbidden) {
		t.Fatalf("provider accepted for foreign Workspace: error = %v, want forbidden", err)
	}
	consumerDecision, err := sharing.NewDecideOffer(sharing.DecideOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		OfferID: offer.Offer().ID(), ExpectedOfferVersion: offer.Offer().Version(),
		Token: token, Action: sharing.DecisionActionAccept,
		ImportedDisplayName: importedName, AccessName: accessName, AccountSession: consumerSession,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 123),
	})
	if err != nil {
		t.Fatalf("construct consumer acceptance: %v", err)
	}
	accepted, err := service.DecideOffer(ctx, consumerDecision)
	if err != nil {
		t.Fatalf("consumer accept cross-Workspace Share Offer: %v", err)
	}
	contract, hasContract := accepted.Contract()
	if !hasContract || contract.State() != sharing.ContractStateActivating ||
		contract.ScopeRelation() != sharing.ScopeRelationCrossWorkspace {
		t.Fatalf("cross-Workspace accepted contract = %+v", accepted)
	}
	assertImportedResourceAccessName(
		ctx, t, admin, contract.ImportedResourceID(), accessName, "reserved", 1,
	)
	activateCommand, err := sharing.NewActivateContract(sharing.ActivateContractParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ContractID: contract.ID(), ExpectedContractVersion: contract.Version(),
		AccountSession: consumerSession, Reason: reason,
		Idempotency: resourceAuthorityProof(t, 124),
	})
	if err != nil {
		t.Fatalf("construct cross-Workspace activation: %v", err)
	}
	activated, err := service.ActivateContract(ctx, activateCommand)
	if err != nil {
		t.Fatalf("activate cross-Workspace Trust Contract: %v", err)
	}
	activeContract, hasContract := activated.Contract()
	if !hasContract || activeContract.State() != sharing.ContractStateActive ||
		activeContract.ScopeRelation() != sharing.ScopeRelationCrossWorkspace {
		t.Fatalf("cross-Workspace active contract = %+v", activated)
	}
	assertPrivateEndpointProvisioning(
		ctx, t, admin, activeContract.ImportedResourceID(), "provisioning", 1,
		// The same-Workspace share of this provider Device still retains
		// fd00:feed::1 in provider Network 203, so the lowest free host is ::2.
		"reserved", 1, "fd00:feed::2",
	)
	assertPrivateEndpointPublicationViaAdapter(
		ctx, t, admin, workerPool, activeContract.ImportedResourceID(), accessName, "fd00:feed::2",
	)
	assertPostgreSQLDeviceAliasReservation(ctx, t, admin, activeContract.ImportedResourceID())
	assertCrossWorkspaceSharingConsentEvidence(ctx, t, admin, offer.Offer().ID())

	var networkCount int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*)::INTEGER
FROM mesh.network WHERE workspace_id = 103 AND state = 'active'`).Scan(&networkCount); err != nil {
		t.Fatalf("query Workspace Network cardinality: %v", err)
	}
	if networkCount < 2 {
		t.Fatalf("active Networks in Workspace = %d, want at least 2", networkCount)
	}
	assertCrossWorkspaceShareExplained(
		ctx, t, admin, runtimePool, consumerSession, consumerScope, activeContract.ImportedResourceID(),
	)
	return activeContract.ImportedResourceID()
}

func assertAutomaticPrivateEndpointInvalidation(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	worker *pgx.Conn,
	workerPool *postgresadapter.Pool,
	importedResourceID, unstagedImportedResourceID sharing.ImportedResourceID,
) {
	t.Helper()
	const deploymentPublicID = "01890f00-0000-7000-8000-000000000001"
	if workerPool == nil || !importedResourceID.IsValid() || !unstagedImportedResourceID.IsValid() {
		t.Fatal("automatic Private Endpoint invalidation fixture is incomplete")
	}

	// Simulate a committed disaster-recovery epoch rotation. The integration
	// administrator bypasses the ordinary evidence trigger only for this fault
	// injection; production writers cannot perform this mutation directly.
	if _, err := admin.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatalf("enable recovery-epoch fault injection: %v", err)
	}
	restored := false
	defer func() {
		if !restored {
			_, _ = admin.Exec(context.WithoutCancel(ctx), `UPDATE mesh.deployment
SET recovery_epoch = 1, updated_at = pg_catalog.clock_timestamp()
WHERE installation_public_id = $1::UUID`, deploymentPublicID)
		}
		_, _ = admin.Exec(context.WithoutCancel(ctx), `SET session_replication_role = origin`)
	}()
	if _, err := admin.Exec(ctx, `UPDATE mesh.deployment
SET recovery_epoch = recovery_epoch + 1, updated_at = pg_catalog.clock_timestamp()
WHERE installation_public_id = $1::UUID`, deploymentPublicID); err != nil {
		t.Fatalf("rotate deployment recovery epoch: %v", err)
	}

	deploymentID, err := deployment.ParseID(deploymentPublicID)
	if err != nil {
		t.Fatalf("parse deployment ID: %v", err)
	}
	var endpointPublicID string
	if err := admin.QueryRow(ctx, `SELECT endpoint.public_id::TEXT
FROM mesh.private_endpoint AS endpoint
JOIN mesh.imported_resource AS imported ON imported.id = endpoint.imported_resource_id
WHERE imported.public_id = $1::UUID`, importedResourceID.String()).Scan(&endpointPublicID); err != nil {
		t.Fatalf("locate invalidated Private Endpoint: %v", err)
	}
	endpointID, err := sharing.ParsePrivateEndpointID(endpointPublicID)
	if err != nil {
		t.Fatalf("parse invalidated Private Endpoint ID: %v", err)
	}
	store, err := postgresadapter.NewPrivateEndpointPublicationStore(workerPool)
	if err != nil {
		t.Fatalf("construct Private Endpoint worker store: %v", err)
	}
	candidates, err := store.ListWithdrawalCandidates(ctx, deploymentID, 128)
	if err != nil {
		t.Fatalf("list invalidated Private Endpoint candidates: %v", err)
	}
	found := false
	for _, candidate := range candidates {
		if candidate.EndpointID == endpointID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("invalidated Private Endpoint %s was not selected", endpointID)
	}
	assertUnstagedPrivateEndpointInvalidation(
		ctx, t, admin, store, deploymentID, candidates, unstagedImportedResourceID,
	)
	snapshot, err := store.ReadWithdrawalSnapshot(ctx, deploymentID, endpointID)
	if err != nil {
		var raw []byte
		rawErr := worker.QueryRow(ctx, `SELECT
    mesh_ops.read_private_endpoint_withdrawal_snapshot_v1($1::UUID, $2::UUID)`,
			deploymentPublicID, endpointID.String(),
		).Scan(&raw)
		t.Fatalf("read invalidated Private Endpoint snapshot: error=%v raw_error=%v raw=%s", err, rawErr, raw)
	}
	if snapshot.Reason != endpointpublication.WithdrawalInvalidated {
		t.Fatalf("read invalidated Private Endpoint snapshot: reason=%s error=%v", snapshot.Reason, err)
	}
	terminalHash, err := snapshot.TerminalHash()
	if err != nil {
		t.Fatalf("hash invalidated Private Endpoint terminal state: %v", err)
	}

	results := make(chan error, 2)
	for range 2 {
		go func() {
			results <- store.FinalizeWithdrawal(
				ctx, snapshot, terminalHash, "integration-route-reconciler",
			)
		}()
	}
	succeeded, rejected := 0, 0
	for range 2 {
		if finalizeErr := <-results; finalizeErr == nil {
			succeeded++
		} else if errors.Is(finalizeErr, postgresadapter.ErrFinalizePrivateEndpointWithdrawal) {
			rejected++
		} else {
			t.Fatalf("unexpected concurrent Private Endpoint finalization error: %v", finalizeErr)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent Private Endpoint finalization = %d success/%d rejected", succeeded, rejected)
	}

	var endpointState, contractState, importedState, nameState, aliasState, dnsState string
	var endpointVersion, contractVersion, importedVersion, nameVersion, aliasVersion, dnsVersion int64
	if err := admin.QueryRow(ctx, `SELECT
    endpoint.state, endpoint.version, contract.state, contract.version,
    imported.state, imported.version, access_name.state, access_name.version,
    lease.state, lease.version, publication.state, publication.version
FROM mesh.private_endpoint AS endpoint
JOIN mesh.trust_contract AS contract ON contract.id = endpoint.trust_contract_id
JOIN mesh.imported_resource AS imported ON imported.id = endpoint.imported_resource_id
JOIN mesh.imported_resource_access_name AS access_name ON access_name.id = endpoint.access_name_id
JOIN mesh.federation_alias_lease AS lease ON lease.id = endpoint.alias_lease_id
JOIN mesh.imported_resource_dns_publication AS publication
  ON publication.private_endpoint_id = endpoint.id
WHERE imported.public_id = $1::UUID`, importedResourceID.String()).Scan(
		&endpointState, &endpointVersion, &contractState, &contractVersion,
		&importedState, &importedVersion, &nameState, &nameVersion,
		&aliasState, &aliasVersion, &dnsState, &dnsVersion,
	); err != nil {
		t.Fatalf("query invalidated Private Endpoint state: %v", err)
	}
	if endpointState != "invalidated" || endpointVersion != 3 ||
		contractState != "invalidated" || contractVersion != 3 ||
		importedState != "invalidated" || importedVersion != 3 ||
		nameState != "withdrawn" || nameVersion != 2 ||
		aliasState != "withdrawn" || aliasVersion != 3 ||
		dnsState != "withdrawn" || dnsVersion != 2 {
		t.Fatalf("automatic Private Endpoint invalidation is not atomic")
	}
	if _, err := admin.Exec(ctx, `UPDATE mesh.deployment
SET recovery_epoch = 1, updated_at = pg_catalog.clock_timestamp()
WHERE installation_public_id = $1::UUID`, deploymentPublicID); err != nil {
		t.Fatalf("restore deployment recovery epoch: %v", err)
	}
	restored = true
}

func assertUnstagedPrivateEndpointInvalidation(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	store *postgresadapter.PrivateEndpointPublicationStore,
	deploymentID deployment.ID,
	candidates []endpointpublication.Candidate,
	importedResourceID sharing.ImportedResourceID,
) {
	t.Helper()
	var endpointPublicID, endpointState, aliasState string
	var endpointVersion, aliasVersion, intentCount, readinessCount, dnsCount int64
	if err := admin.QueryRow(ctx, `SELECT
    endpoint.public_id::TEXT, endpoint.state, endpoint.version,
    lease.state, lease.version,
    (SELECT pg_catalog.count(*) FROM mesh_ops.private_endpoint_route_intent AS intent
     WHERE intent.private_endpoint_id = endpoint.id),
    (SELECT pg_catalog.count(*) FROM mesh.private_endpoint_readiness AS readiness
     WHERE readiness.private_endpoint_id = endpoint.id),
    (SELECT pg_catalog.count(*) FROM mesh.imported_resource_dns_publication AS publication
     WHERE publication.private_endpoint_id = endpoint.id)
FROM mesh.private_endpoint AS endpoint
JOIN mesh.imported_resource AS imported ON imported.id = endpoint.imported_resource_id
JOIN mesh.federation_alias_lease AS lease ON lease.id = endpoint.alias_lease_id
WHERE imported.public_id = $1::UUID`, importedResourceID.String()).Scan(
		&endpointPublicID, &endpointState, &endpointVersion, &aliasState, &aliasVersion,
		&intentCount, &readinessCount, &dnsCount,
	); err != nil {
		t.Fatalf("query unstaged Private Endpoint: %v", err)
	}
	if endpointState != "provisioning" || endpointVersion != 1 ||
		aliasState != "reserved" || aliasVersion != 1 ||
		intentCount != 0 || readinessCount != 0 || dnsCount != 0 {
		t.Fatal("unstaged Private Endpoint unexpectedly had route or DNS evidence")
	}
	endpointID, err := sharing.ParsePrivateEndpointID(endpointPublicID)
	if err != nil {
		t.Fatalf("parse unstaged Private Endpoint ID: %v", err)
	}
	found := false
	for _, candidate := range candidates {
		if candidate.EndpointID == endpointID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("unstaged invalidated Private Endpoint %s was not selected", endpointID)
	}
	snapshot, err := store.ReadWithdrawalSnapshot(ctx, deploymentID, endpointID)
	if err != nil {
		t.Fatalf("read unstaged Private Endpoint withdrawal snapshot: %v", err)
	}
	if snapshot.RoutePresent || snapshot.RouteSnapshotHash != ([sha256.Size]byte{}) ||
		snapshot.DNSPublicationVersion != 0 ||
		snapshot.Reason != endpointpublication.WithdrawalInvalidated {
		t.Fatalf("unstaged Private Endpoint withdrawal snapshot = %+v", snapshot)
	}
	terminalHash, err := snapshot.TerminalHash()
	if err != nil {
		t.Fatalf("hash unstaged Private Endpoint terminal state: %v", err)
	}
	if err := store.FinalizeWithdrawal(
		ctx, snapshot, terminalHash, "integration-route-reconciler",
	); err != nil {
		t.Fatalf("finalize unstaged Private Endpoint: %v", err)
	}

	var contractState, importedState, nameState string
	var contractVersion, importedVersion, nameVersion int64
	if err := admin.QueryRow(ctx, `SELECT
    endpoint.state, endpoint.version, contract.state, contract.version,
    imported.state, imported.version, access_name.state, access_name.version,
    lease.state, lease.version,
    (SELECT pg_catalog.count(*) FROM mesh.imported_resource_dns_publication AS publication
     WHERE publication.private_endpoint_id = endpoint.id)
FROM mesh.private_endpoint AS endpoint
JOIN mesh.trust_contract AS contract ON contract.id = endpoint.trust_contract_id
JOIN mesh.imported_resource AS imported ON imported.id = endpoint.imported_resource_id
JOIN mesh.imported_resource_access_name AS access_name ON access_name.id = endpoint.access_name_id
JOIN mesh.federation_alias_lease AS lease ON lease.id = endpoint.alias_lease_id
WHERE imported.public_id = $1::UUID`, importedResourceID.String()).Scan(
		&endpointState, &endpointVersion, &contractState, &contractVersion,
		&importedState, &importedVersion, &nameState, &nameVersion,
		&aliasState, &aliasVersion, &dnsCount,
	); err != nil {
		t.Fatalf("query terminal unstaged Private Endpoint: %v", err)
	}
	if endpointState != "invalidated" || endpointVersion != 2 ||
		contractState != "invalidated" || contractVersion != 3 ||
		importedState != "invalidated" || importedVersion != 3 ||
		nameState != "withdrawn" || nameVersion != 2 ||
		aliasState != "withdrawn" || aliasVersion != 2 || dnsCount != 0 {
		t.Fatal("unstaged Private Endpoint terminalization is not atomic")
	}
}

func assertAccessNameCollisionRollsBack(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	service *sharing.Service,
	session accountsession.Session,
	providerScope, consumerScope network.Scope,
	resourceID resource.ID,
	maximumTraffic sharing.TrafficSet,
	reason sharing.AuditReason,
	accessName sharing.AccessName,
) {
	t.Helper()
	created, err := service.CreateOffer(ctx, mustCreateSharingOffer(
		t,
		providerScope,
		consumerScope,
		resourceID,
		maximumTraffic,
		session,
		reason,
		115,
	))
	if err != nil {
		t.Fatalf("create access-name collision offer: %v", err)
	}
	offer, hasOffer := created.Offer()
	token, hasToken := created.Token()
	if !hasOffer || !hasToken {
		t.Fatalf("access-name collision offer result = %+v", created)
	}
	importedName, err := resource.ParseDisplayName("Secondary imported production Resource")
	if err != nil {
		t.Fatal(err)
	}
	command, err := sharing.NewDecideOffer(sharing.DecideOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		OfferID: offer.Offer().ID(), ExpectedOfferVersion: offer.Offer().Version(),
		Token: token, Action: sharing.DecisionActionAccept,
		ImportedDisplayName: importedName, AccessName: accessName, AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 116),
	})
	if err != nil {
		t.Fatalf("construct access-name collision decision: %v", err)
	}
	if _, err := service.DecideOffer(ctx, command); !errors.Is(err, sharing.ErrConflict) {
		t.Fatalf("accept duplicate access name: error = %v, want conflict", err)
	}

	var state string
	var version int64
	var contractCount int
	if err := admin.QueryRow(ctx, `SELECT
    offer.state,
    offer.version,
    (SELECT pg_catalog.count(*)::INTEGER
     FROM mesh.trust_contract AS contract
     WHERE contract.share_offer_id = offer.id)
FROM mesh.share_offer AS offer
WHERE offer.public_id = $1::UUID`, offer.Offer().ID().String()).Scan(
		&state,
		&version,
		&contractCount,
	); err != nil {
		t.Fatalf("query rolled-back access-name collision: %v", err)
	}
	if state != "offered" || version != 1 || contractCount != 0 {
		t.Fatalf(
			"access-name collision state/version/contracts = %s/%d/%d, want offered/1/0",
			state,
			version,
			contractCount,
		)
	}
}

func mustCreateSharingOffer(
	t *testing.T,
	providerScope, consumerScope network.Scope,
	resourceID resource.ID,
	maximumTraffic sharing.TrafficSet,
	session accountsession.Session,
	reason sharing.AuditReason,
	proofMarker byte,
	labels ...string,
) sharing.CreateOffer {
	t.Helper()
	var accessLabel sharing.AccessLabel
	if len(labels) == 1 {
		var err error
		if accessLabel, err = sharing.ParseAccessLabel(labels[0]); err != nil {
			t.Fatalf("parse share access label: %v", err)
		}
	}
	command, err := sharing.NewCreateOffer(sharing.CreateOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ResourceID: resourceID, MaximumTraffic: maximumTraffic,
		ExpiresAt: time.Now().UTC().Add(time.Hour), AccessLabel: accessLabel,
		AccountSession: session,
		Reason:         reason, Idempotency: resourceAuthorityProof(t, proofMarker),
	})
	if err != nil {
		t.Fatalf("construct Resource Share Offer: %v", err)
	}
	return command
}

func assertImportedResourceAccessName(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	importedResourceID sharing.ImportedResourceID,
	wantName sharing.AccessName,
	wantState string,
	wantVersion int64,
) {
	t.Helper()
	var name, state string
	var version int64
	if err := admin.QueryRow(ctx, `SELECT
    access_name.access_name,
    access_name.state,
    access_name.version
FROM mesh.imported_resource_access_name AS access_name
JOIN mesh.imported_resource AS imported
  ON imported.workspace_id = access_name.workspace_id
 AND imported.network_id = access_name.network_id
 AND imported.id = access_name.imported_resource_id
WHERE imported.public_id = $1::UUID`, importedResourceID.String()).Scan(
		&name,
		&state,
		&version,
	); err != nil {
		t.Fatalf("query Imported Resource access name: %v", err)
	}
	if name != wantName.String() || state != wantState || version != wantVersion {
		t.Fatalf(
			"Imported Resource access name/name-state-version = %s/%s/%d, want %s/%s/%d",
			name,
			state,
			version,
			wantName.String(),
			wantState,
			wantVersion,
		)
	}
}

type integrationEndpointPublicationCandidate struct {
	DeploymentID            string    `json:"deployment_public_id"`
	EndpointID              string    `json:"endpoint_public_id"`
	EndpointVersion         int64     `json:"endpoint_version"`
	EndpointGeneration      int64     `json:"endpoint_generation"`
	AliasLeaseVersion       int64     `json:"alias_lease_version"`
	ContractVersion         int64     `json:"contract_version"`
	ImportedResourceVersion int64     `json:"imported_resource_version"`
	TargetDeviceID          string    `json:"target_device_id"`
	TargetGeneration        int64     `json:"target_generation"`
	TargetAddresses         []string  `json:"target_addresses"`
	ResourceAlias           string    `json:"resource_alias"`
	AccessName              string    `json:"access_name"`
	ConstraintHash          string    `json:"constraint_hash"`
	SnapshotAt              time.Time `json:"snapshot_at"`
	ProviderNetworkRevision int64     `json:"provider_network_revision"`
	ProviderDNSRevision     int64     `json:"provider_dns_revision"`
	ProviderRouteRevision   int64     `json:"provider_route_revision"`
	ProviderSharingRevision int64     `json:"provider_sharing_revision"`
	ConsumerNetworkRevision int64     `json:"consumer_network_revision"`
	ConsumerDNSRevision     int64     `json:"consumer_dns_revision"`
	ConsumerRouteRevision   int64     `json:"consumer_route_revision"`
	ConsumerSharingRevision int64     `json:"consumer_sharing_revision"`
	ProviderStreamID        int64     `json:"provider_stream_id"`
	ProviderStreamSequence  int64     `json:"provider_stream_sequence"`
	ProviderStreamHash      string    `json:"provider_stream_hash"`
	ConsumerStreamID        int64     `json:"consumer_stream_id"`
	ConsumerStreamSequence  int64     `json:"consumer_stream_sequence"`
	ConsumerStreamHash      string    `json:"consumer_stream_hash"`
}

type integrationEndpointPublicationAuditPayload struct {
	EndpointID         string `json:"endpoint_public_id"`
	ReadinessID        string `json:"readiness_public_id"`
	DNSPublicationID   string `json:"dns_publication_public_id"`
	AuthoritySide      string `json:"authority_side"`
	ReconcilerID       string `json:"reconciler_id"`
	EndpointGeneration int64  `json:"endpoint_generation"`
	ResourceAlias      string `json:"resource_alias"`
	RouteSnapshotHash  string `json:"route_snapshot_hash"`
	NetworkRevision    int64  `json:"network_revision"`
	DNSRevision        int64  `json:"dns_revision"`
	RouteRevision      int64  `json:"route_revision"`
	SharingRevision    int64  `json:"sharing_revision"`
}

type integrationEndpointPublicationOutboxPayload struct {
	EndpointID      string `json:"endpoint_public_id"`
	NetworkRevision int64  `json:"network_revision"`
	DNSRevision     int64  `json:"dns_revision"`
	RouteRevision   int64  `json:"route_revision"`
	Subsystem       string `json:"subsystem"`
	SharingRevision int64  `json:"subsystem_revision"`
}

func assertPrivateEndpointPublication(
	ctx context.Context,
	t *testing.T,
	admin, worker *pgx.Conn,
	importedResourceID sharing.ImportedResourceID,
	accessName sharing.AccessName,
	wantResourceAlias string,
) {
	t.Helper()
	const deploymentID = "01890f00-0000-7000-8000-000000000001"
	var encoded []byte
	if err := worker.QueryRow(ctx, `SELECT
    mesh_ops.list_private_endpoint_publication_candidates_v1($1::UUID, 128)`,
		deploymentID,
	).Scan(&encoded); err != nil {
		t.Fatalf("list Private Endpoint publication candidates: %v", err)
	}
	var candidates []integrationEndpointPublicationCandidate
	if err := json.Unmarshal(encoded, &candidates); err != nil {
		t.Fatalf("decode Private Endpoint publication candidates: %v", err)
	}
	var candidate integrationEndpointPublicationCandidate
	for _, item := range candidates {
		if item.AccessName == accessName.String() {
			candidate = item
			break
		}
	}
	if candidate.EndpointID != "" {
		var snapshot []byte
		if err := worker.QueryRow(ctx, `SELECT
    mesh_ops.read_private_endpoint_publication_snapshot_v1($1::UUID, $2::UUID)`,
			deploymentID,
			candidate.EndpointID,
		).Scan(&snapshot); err != nil {
			t.Fatalf("read Private Endpoint publication snapshot: %v", err)
		}
		if err := json.Unmarshal(snapshot, &candidate); err != nil {
			t.Fatalf("decode Private Endpoint publication snapshot: %v", err)
		}
	}
	if candidate.EndpointID == "" || candidate.DeploymentID != deploymentID ||
		candidate.EndpointVersion != 1 || candidate.EndpointGeneration != 1 ||
		candidate.AliasLeaseVersion != 1 || candidate.ContractVersion <= 0 ||
		candidate.ImportedResourceVersion != 2 || candidate.TargetDeviceID == "" ||
		candidate.TargetGeneration <= 0 || len(candidate.TargetAddresses) == 0 ||
		candidate.ResourceAlias != wantResourceAlias || len(candidate.ConstraintHash) != 64 ||
		candidate.SnapshotAt.IsZero() {
		t.Fatalf("Private Endpoint publication candidate = %+v", candidate)
	}

	endpointID, err := publicid.Parse(candidate.EndpointID)
	if err != nil {
		t.Fatalf("parse Private Endpoint candidate ID: %v", err)
	}
	changeID := newIntegrationPublicationID(t)
	readinessID := newIntegrationPublicationID(t)
	dnsPublicationID := newIntegrationPublicationID(t)
	providerEventID := newIntegrationPublicationID(t)
	providerOutboxID := newIntegrationPublicationID(t)
	consumerEventID := newIntegrationPublicationID(t)
	consumerOutboxID := newIntegrationPublicationID(t)
	routeMaterial, err := json.Marshal(struct {
		EndpointID         string   `json:"endpoint_public_id"`
		EndpointGeneration int64    `json:"endpoint_generation"`
		TargetDeviceID     string   `json:"target_device_id"`
		TargetGeneration   int64    `json:"target_generation"`
		TargetAddresses    []string `json:"target_addresses"`
		ResourceAlias      string   `json:"resource_alias"`
	}{
		EndpointID: candidate.EndpointID, EndpointGeneration: candidate.EndpointGeneration,
		TargetDeviceID: candidate.TargetDeviceID, TargetGeneration: candidate.TargetGeneration,
		TargetAddresses: candidate.TargetAddresses, ResourceAlias: candidate.ResourceAlias,
	})
	if err != nil {
		t.Fatalf("encode Private Endpoint route snapshot: %v", err)
	}
	routeHash := sha256.Sum256(routeMaterial)
	reconcilerID := "integration-route-reconciler"
	intentID := newIntegrationPublicationID(t)
	var stagedHash []byte
	if err := worker.QueryRow(ctx, `SELECT mesh_ops.stage_private_endpoint_route_v1(
    $1::UUID,$2::UUID,$3::BIGINT,$4::BIGINT,$5::UUID,$6::BYTEA,$7::TEXT,$8::TIMESTAMPTZ
)`,
		deploymentID, candidate.EndpointID, candidate.EndpointVersion,
		candidate.EndpointGeneration, intentID.String(), routeHash[:], reconcilerID,
		candidate.SnapshotAt,
	).Scan(&stagedHash); err != nil || !bytes.Equal(stagedHash, routeHash[:]) {
		t.Fatalf("stage Private Endpoint route intent: hash=%x err=%v", stagedHash, err)
	}
	providerAudit := integrationEndpointPublicationAuditPayload{
		EndpointID: candidate.EndpointID, ReadinessID: readinessID.String(),
		DNSPublicationID: dnsPublicationID.String(), AuthoritySide: "provider",
		ReconcilerID: reconcilerID, EndpointGeneration: candidate.EndpointGeneration,
		ResourceAlias: candidate.ResourceAlias, RouteSnapshotHash: hex.EncodeToString(routeHash[:]),
		NetworkRevision: candidate.ProviderNetworkRevision + 1,
		DNSRevision:     candidate.ProviderDNSRevision,
		RouteRevision:   candidate.ProviderRouteRevision + 1,
		SharingRevision: candidate.ProviderSharingRevision + 1,
	}
	consumerAudit := integrationEndpointPublicationAuditPayload{
		EndpointID: candidate.EndpointID, ReadinessID: readinessID.String(),
		DNSPublicationID: dnsPublicationID.String(), AuthoritySide: "consumer",
		ReconcilerID: reconcilerID, EndpointGeneration: candidate.EndpointGeneration,
		ResourceAlias: candidate.ResourceAlias, RouteSnapshotHash: hex.EncodeToString(routeHash[:]),
		NetworkRevision: candidate.ConsumerNetworkRevision + 1,
		DNSRevision:     candidate.ConsumerDNSRevision + 1,
		RouteRevision:   candidate.ConsumerRouteRevision + 1,
		SharingRevision: candidate.ConsumerSharingRevision + 1,
	}
	providerOutbox := integrationEndpointPublicationOutboxPayload{
		EndpointID: candidate.EndpointID, NetworkRevision: providerAudit.NetworkRevision,
		DNSRevision: providerAudit.DNSRevision, RouteRevision: providerAudit.RouteRevision,
		Subsystem: "sharing", SharingRevision: providerAudit.SharingRevision,
	}
	consumerOutbox := integrationEndpointPublicationOutboxPayload{
		EndpointID: candidate.EndpointID, NetworkRevision: consumerAudit.NetworkRevision,
		DNSRevision: consumerAudit.DNSRevision, RouteRevision: consumerAudit.RouteRevision,
		Subsystem: "sharing", SharingRevision: consumerAudit.SharingRevision,
	}
	providerAuditJSON := mustIntegrationJSON(t, providerAudit)
	consumerAuditJSON := mustIntegrationJSON(t, consumerAudit)
	providerOutboxJSON := mustIntegrationJSON(t, providerOutbox)
	consumerOutboxJSON := mustIntegrationJSON(t, consumerOutbox)
	providerPreviousHash := mustIntegrationHash(t, candidate.ProviderStreamHash)
	consumerPreviousHash := mustIntegrationHash(t, candidate.ConsumerStreamHash)
	providerEventHash := mustIntegrationPublicationEventHash(t, audit.EventHashMaterial{
		PreviousHash: providerPreviousHash, EventID: providerEventID, ChangeID: changeID,
		AggregateKind: "private_endpoint", AggregateID: endpointID, AggregateVersion: 2,
		NetworkRevision: providerAudit.NetworkRevision, Action: "private_endpoint.published",
		Permission: "system.reconcile", CorrelationID: endpointID, AfterSemanticHash: routeHash,
		AuditPayloadHash:  sha256.Sum256(providerAuditJSON),
		OutboxEventClass:  "sharing.private_endpoint.published",
		OutboxPayloadHash: sha256.Sum256(providerOutboxJSON),
	})
	consumerEventHash := mustIntegrationPublicationEventHash(t, audit.EventHashMaterial{
		PreviousHash: consumerPreviousHash, EventID: consumerEventID, ChangeID: changeID,
		AggregateKind: "private_endpoint", AggregateID: endpointID, AggregateVersion: 2,
		NetworkRevision: consumerAudit.NetworkRevision, Action: "private_endpoint.published",
		Permission: "system.reconcile", CorrelationID: endpointID, AfterSemanticHash: routeHash,
		AuditPayloadHash:  sha256.Sum256(consumerAuditJSON),
		OutboxEventClass:  "sharing.private_endpoint.published",
		OutboxPayloadHash: sha256.Sum256(consumerOutboxJSON),
	})

	transaction, err := worker.Begin(ctx)
	if err != nil {
		t.Fatalf("begin Private Endpoint publication: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.WithoutCancel(ctx)) }()
	var providerNetwork, providerDNS, providerRoute, providerSharing int64
	var consumerNetwork, consumerDNS, consumerRoute, consumerSharing int64
	var aliasVersion, endpointVersion, readinessVersion, dnsVersion int64
	observedAt := candidate.SnapshotAt
	if err := transaction.QueryRow(ctx, `SELECT * FROM mesh_ops.publish_private_endpoint_v1(
    $1::UUID,$2::UUID,$3::BIGINT,$4::BIGINT,$5::BIGINT,$6::BIGINT,$7::BIGINT,
    $8::BIGINT,$9::BIGINT,$10::BIGINT,$11::BIGINT,$12::BIGINT,$13::BIGINT,$14::BIGINT,$15::BIGINT,
    $16::UUID,$17::UUID,$18::UUID,$19::BYTEA,$20::TEXT,$21::TIMESTAMPTZ,
    $22::BIGINT,$23::UUID,$24::UUID,$25::BIGINT,$26::BYTEA,$27::BYTEA,$28::JSONB,$29::JSONB,
    $30::BIGINT,$31::UUID,$32::UUID,$33::BIGINT,$34::BYTEA,$35::BYTEA,$36::JSONB,$37::JSONB
)`,
		deploymentID, candidate.EndpointID, candidate.EndpointVersion,
		candidate.EndpointGeneration, candidate.AliasLeaseVersion,
		candidate.ContractVersion, candidate.ImportedResourceVersion,
		candidate.ProviderNetworkRevision, candidate.ProviderDNSRevision,
		candidate.ProviderRouteRevision, candidate.ProviderSharingRevision,
		candidate.ConsumerNetworkRevision, candidate.ConsumerDNSRevision,
		candidate.ConsumerRouteRevision, candidate.ConsumerSharingRevision,
		changeID.String(), readinessID.String(), dnsPublicationID.String(), routeHash[:],
		reconcilerID, observedAt, candidate.ProviderStreamID, providerEventID.String(),
		providerOutboxID.String(), candidate.ProviderStreamSequence, providerPreviousHash[:],
		providerEventHash[:], providerAuditJSON, providerOutboxJSON,
		candidate.ConsumerStreamID, consumerEventID.String(), consumerOutboxID.String(),
		candidate.ConsumerStreamSequence, consumerPreviousHash[:], consumerEventHash[:],
		consumerAuditJSON, consumerOutboxJSON,
	).Scan(
		&providerNetwork, &providerDNS, &providerRoute, &providerSharing,
		&consumerNetwork, &consumerDNS, &consumerRoute, &consumerSharing,
		&aliasVersion, &endpointVersion, &readinessVersion, &dnsVersion,
	); err != nil {
		t.Fatalf(
			"publish Private Endpoint %s with candidate %+v: %v",
			wantResourceAlias,
			candidate,
			err,
		)
	}
	if providerNetwork != providerAudit.NetworkRevision || providerDNS != providerAudit.DNSRevision ||
		providerRoute != providerAudit.RouteRevision || providerSharing != providerAudit.SharingRevision ||
		consumerNetwork != consumerAudit.NetworkRevision || consumerDNS != consumerAudit.DNSRevision ||
		consumerRoute != consumerAudit.RouteRevision || consumerSharing != consumerAudit.SharingRevision ||
		aliasVersion != 2 || endpointVersion != 2 || readinessVersion != 1 || dnsVersion != 1 {
		t.Fatalf("Private Endpoint publication result has unexpected revisions")
	}
	if err := transaction.Commit(ctx); err != nil {
		t.Fatalf("commit Private Endpoint publication: %v", err)
	}

	var endpointState, aliasState, publicationState, publishedName string
	var storedEndpointVersion, storedAliasVersion, publicationVersion, evidenceCount int64
	if err := admin.QueryRow(ctx, `SELECT
    endpoint.state, endpoint.version, lease.state, lease.version,
    publication.state, publication.version, publication.access_name,
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event_identity AS event
     WHERE event.change_public_id = $2::UUID)
FROM mesh.private_endpoint AS endpoint
JOIN mesh.federation_alias_lease AS lease ON lease.id = endpoint.alias_lease_id
JOIN mesh.imported_resource AS imported ON imported.id = endpoint.imported_resource_id
JOIN mesh.imported_resource_dns_publication AS publication
  ON publication.private_endpoint_id = endpoint.id
WHERE imported.public_id = $1::UUID`, importedResourceID.String(), changeID.String()).Scan(
		&endpointState, &storedEndpointVersion, &aliasState, &storedAliasVersion,
		&publicationState, &publicationVersion, &publishedName, &evidenceCount,
	); err != nil {
		t.Fatalf("query published Private Endpoint: %v", err)
	}
	if endpointState != "ready" || storedEndpointVersion != 2 || aliasState != "active" ||
		storedAliasVersion != 2 || publicationState != "published" || publicationVersion != 1 ||
		publishedName != accessName.String() || evidenceCount != 2 {
		t.Fatalf("published Private Endpoint state/evidence is inconsistent")
	}
}

func assertPrivateEndpointPublicationViaAdapter(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	workerPool *postgresadapter.Pool,
	importedResourceID sharing.ImportedResourceID,
	accessName sharing.AccessName,
	wantResourceAlias string,
) {
	t.Helper()
	const deploymentPublicID = "01890f00-0000-7000-8000-000000000001"
	deploymentID, err := deployment.ParseID(deploymentPublicID)
	if err != nil {
		t.Fatalf("parse publication Deployment ID: %v", err)
	}
	var endpointPublicID string
	if err := admin.QueryRow(ctx, `SELECT endpoint.public_id::TEXT
FROM mesh.private_endpoint AS endpoint
JOIN mesh.imported_resource AS imported ON imported.id = endpoint.imported_resource_id
WHERE imported.public_id = $1::UUID`, importedResourceID.String()).Scan(&endpointPublicID); err != nil {
		t.Fatalf("locate adapter publication endpoint: %v", err)
	}
	endpointID, err := sharing.ParsePrivateEndpointID(endpointPublicID)
	if err != nil {
		t.Fatalf("parse adapter publication endpoint ID: %v", err)
	}
	store, err := postgresadapter.NewPrivateEndpointPublicationStore(workerPool)
	if err != nil {
		t.Fatalf("construct adapter publication store: %v", err)
	}
	candidates, err := store.ListPublicationCandidates(ctx, deploymentID, 128)
	if err != nil {
		t.Fatalf("list adapter publication candidates: %v", err)
	}
	found := false
	for _, candidate := range candidates {
		if candidate.EndpointID == endpointID && candidate.Generation == 1 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("adapter publication endpoint %s was not selected", endpointID)
	}
	snapshot, err := store.ReadPublicationSnapshot(ctx, deploymentID, endpointID)
	if err != nil {
		t.Fatalf("read adapter publication snapshot: %v", err)
	}
	if snapshot.ResourceAlias.String() != wantResourceAlias || snapshot.AccessName != accessName ||
		len(snapshot.TargetAddresses) == 0 || len(snapshot.Traffic) == 0 {
		t.Fatalf("adapter publication snapshot is incomplete: %+v", snapshot)
	}
	route, err := snapshot.Route()
	if err != nil {
		t.Fatalf("construct adapter publication route: %v", err)
	}
	routeHash, err := route.Hash()
	if err != nil {
		t.Fatalf("hash adapter publication route: %v", err)
	}
	if err := store.StagePublication(
		ctx, snapshot, routeHash, "integration-route-reconciler",
	); err != nil {
		t.Fatalf("stage adapter publication: %v", err)
	}
	if err := store.ConfirmPublication(
		ctx, snapshot, routeHash, "integration-route-reconciler",
	); err != nil {
		t.Fatalf("confirm adapter publication: %v", err)
	}

	var endpointState, aliasState, publicationState, publishedName string
	var endpointVersion, aliasVersion, publicationVersion, evidenceCount int64
	if err := admin.QueryRow(ctx, `SELECT
    endpoint.state, endpoint.version, lease.state, lease.version,
    publication.state, publication.version, publication.access_name,
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event AS event
     WHERE event.target_kind = 'private_endpoint'
       AND event.target_public_id = endpoint.public_id
       AND event.action = 'private_endpoint.published')
FROM mesh.private_endpoint AS endpoint
JOIN mesh.federation_alias_lease AS lease ON lease.id = endpoint.alias_lease_id
JOIN mesh.imported_resource AS imported ON imported.id = endpoint.imported_resource_id
JOIN mesh.imported_resource_dns_publication AS publication
  ON publication.private_endpoint_id = endpoint.id
WHERE imported.public_id = $1::UUID`, importedResourceID.String()).Scan(
		&endpointState, &endpointVersion, &aliasState, &aliasVersion,
		&publicationState, &publicationVersion, &publishedName, &evidenceCount,
	); err != nil {
		t.Fatalf("query adapter-published Private Endpoint: %v", err)
	}
	if endpointState != "ready" || endpointVersion != 2 || aliasState != "active" ||
		aliasVersion != 2 || publicationState != "published" || publicationVersion != 1 ||
		publishedName != accessName.String() || evidenceCount != 2 {
		t.Fatalf("adapter-published Private Endpoint state/evidence is inconsistent")
	}
}

func newIntegrationPublicationID(t *testing.T) publicid.ID {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatalf("generate Private Endpoint publication ID: %v", err)
	}
	return id
}

func mustIntegrationJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode Private Endpoint publication evidence: %v", err)
	}
	return encoded
}

func mustIntegrationHash(t *testing.T, value string) [sha256.Size]byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		t.Fatalf("decode Private Endpoint publication hash %q: %v", value, err)
	}
	var result [sha256.Size]byte
	copy(result[:], decoded)
	return result
}

func mustIntegrationPublicationEventHash(
	t *testing.T,
	material audit.EventHashMaterial,
) [sha256.Size]byte {
	t.Helper()
	digest, err := audit.HashEvent(material)
	if err != nil {
		t.Fatalf("hash Private Endpoint publication event: %v", err)
	}
	return digest
}

func assertPrivateEndpointPublicationWithdrawn(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	importedResourceID sharing.ImportedResourceID,
	accessName sharing.AccessName,
) {
	t.Helper()
	var state, name string
	var version int64
	var withdrawnAt pgtype.Timestamptz
	if err := admin.QueryRow(ctx, `SELECT
    publication.state, publication.version, publication.access_name, publication.withdrawn_at
FROM mesh.imported_resource_dns_publication AS publication
JOIN mesh.imported_resource AS imported ON imported.id = publication.imported_resource_id
WHERE imported.public_id = $1::UUID`, importedResourceID.String()).Scan(
		&state, &version, &name, &withdrawnAt,
	); err != nil {
		t.Fatalf("query withdrawn Private Endpoint publication: %v", err)
	}
	if state != "withdrawn" || version != 2 || name != accessName.String() || !withdrawnAt.Valid {
		t.Fatalf("withdrawn Private Endpoint publication = %s/%d/%s/%v", state, version, name, withdrawnAt)
	}
}

func assertPrivateEndpointProvisioning(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	importedResourceID sharing.ImportedResourceID,
	wantEndpointState string,
	wantEndpointVersion int64,
	wantAliasState string,
	wantAliasVersion int64,
	wantAliasAddress string,
) {
	t.Helper()
	var endpointState, aliasState, aliasAddress string
	var endpointVersion, aliasVersion int64
	var readyAt, endpointEndedAt, aliasActivatedAt, aliasWithdrawnAt pgtype.Timestamptz
	if err := admin.QueryRow(ctx, `SELECT
    endpoint.state,
    endpoint.version,
    endpoint.ready_at,
    endpoint.ended_at,
    pg_catalog.host(endpoint.resource_alias),
    lease.state,
    lease.version,
    lease.activated_at,
    lease.withdrawn_at
FROM mesh.private_endpoint AS endpoint
JOIN mesh.federation_alias_lease AS lease
  ON lease.id = endpoint.alias_lease_id
 AND lease.resource_alias = endpoint.resource_alias
JOIN mesh.imported_resource AS imported
  ON imported.workspace_id = endpoint.consumer_workspace_id
 AND imported.network_id = endpoint.consumer_network_id
 AND imported.id = endpoint.imported_resource_id
WHERE imported.public_id = $1::UUID`, importedResourceID.String()).Scan(
		&endpointState,
		&endpointVersion,
		&readyAt,
		&endpointEndedAt,
		&aliasAddress,
		&aliasState,
		&aliasVersion,
		&aliasActivatedAt,
		&aliasWithdrawnAt,
	); err != nil {
		t.Fatalf("query Private Endpoint provisioning: %v", err)
	}
	if endpointState != wantEndpointState || endpointVersion != wantEndpointVersion ||
		aliasState != wantAliasState || aliasVersion != wantAliasVersion ||
		aliasAddress != wantAliasAddress {
		t.Fatalf(
			"Private Endpoint state/version/alias = %s/%d/%s/%d/%s, want %s/%d/%s/%d/%s",
			endpointState,
			endpointVersion,
			aliasState,
			aliasVersion,
			aliasAddress,
			wantEndpointState,
			wantEndpointVersion,
			wantAliasState,
			wantAliasVersion,
			wantAliasAddress,
		)
	}
	published := wantEndpointState == "ready" || wantEndpointState == "revoked"
	if published != readyAt.Valid || published != aliasActivatedAt.Valid {
		t.Fatalf(
			"Private Endpoint publication timestamps ready=%v alias=%v, published=%t",
			readyAt,
			aliasActivatedAt,
			published,
		)
	}
	terminal := wantEndpointState == "revoked"
	if terminal != endpointEndedAt.Valid || terminal != aliasWithdrawnAt.Valid {
		t.Fatalf(
			"Private Endpoint terminal timestamps endpoint=%v alias=%v, terminal=%t",
			endpointEndedAt,
			aliasWithdrawnAt,
			terminal,
		)
	}
}

func seedCrossWorkspaceShareConsumerAuthority(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
) {
	t.Helper()
	var networkRevision int64
	if err := admin.QueryRow(ctx, `SELECT network_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 102 AND network_id = 202`).Scan(&networkRevision); err != nil {
		t.Fatalf("query cross-Workspace consumer Network revision: %v", err)
	}
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID:         "01890f01-0000-7000-8000-000000000869",
		eventPublicID:          "01890f02-0000-7000-8000-000000000869",
		outboxPublicID:         "01890f03-0000-7000-8000-000000000869",
		streamID:               202,
		aggregateKind:          "role_binding",
		aggregatePublicID:      "01890f00-0000-7000-8000-000000000869",
		aggregateVersion:       1,
		networkRevision:        networkRevision,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "cross_workspace_share_authority.seeded",
		permission:             "system.bootstrap",
		outboxEventClass:       "cross_workspace_share_authority.seeded",
	}, func(transaction pgx.Tx) {
		statements := []struct {
			name  string
			query string
		}{
			{
				name: "cross-Workspace consumer membership",
				query: `INSERT INTO mesh.workspace_membership (
    id, public_id, deployment_id, workspace_id, principal_id,
    state, authority_generation, valid_from
) OVERRIDING SYSTEM VALUE VALUES (
    864, '01890f00-0000-7000-8000-000000000864', 1, 102, 13,
    'active', 1, pg_catalog.transaction_timestamp() - INTERVAL '1 minute'
)`,
			},
			{
				name: "cross-Workspace share manager role",
				query: `INSERT INTO mesh.role_definition (
    id, public_id, deployment_id, workspace_id, role_key, display_name,
    kind, state, authority_generation
) OVERRIDING SYSTEM VALUE VALUES (
    865, '01890f00-0000-7000-8000-000000000865', 1, 102,
    'resource_share_manager', 'Resource Share Manager', 'custom', 'active', 1
)`,
			},
			{
				name: "cross-Workspace share read permission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 866, '01890f00-0000-7000-8000-000000000866', 1, 102, 865, permission.id
FROM mesh.permission AS permission WHERE permission.permission_key = 'share.read'`,
			},
			{
				name: "cross-Workspace share accept permission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 867, '01890f00-0000-7000-8000-000000000867', 1, 102, 865, permission.id
FROM mesh.permission AS permission WHERE permission.permission_key = 'share.accept'`,
			},
			{
				name: "cross-Workspace share revoke permission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 868, '01890f00-0000-7000-8000-000000000868', 1, 102, 865, permission.id
FROM mesh.permission AS permission WHERE permission.permission_key = 'share.revoke'`,
			},
			{
				name: "cross-Workspace policy explain permission",
				query: `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT 870, '01890f00-0000-7000-8000-000000000870', 1, 102, 865, permission.id
FROM mesh.permission AS permission WHERE permission.permission_key = 'policy.explain'`,
			},
			{
				name: "cross-Workspace consumer Network binding",
				query: `INSERT INTO mesh.role_binding (
    id, public_id, deployment_id, workspace_id, network_id, principal_id,
    workspace_membership_id, role_definition_id, state,
    authority_generation, valid_from
) OVERRIDING SYSTEM VALUE VALUES (
    869, '01890f00-0000-7000-8000-000000000869', 1, 102, 202, 13,
    864, 865, 'active', 1, pg_catalog.transaction_timestamp() - INTERVAL '1 minute'
)`,
			},
		}
		for _, statement := range statements {
			if _, err := transaction.Exec(ctx, statement.query); err != nil {
				t.Fatalf("insert %s: %v", statement.name, err)
			}
		}
	})
}

func assertCrossWorkspaceSharingConsentEvidence(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	offerID sharing.OfferID,
) {
	t.Helper()
	var providerConsent, consumerConsent int
	if err := admin.QueryRow(ctx, `SELECT
    pg_catalog.count(*) FILTER (
        WHERE action = 'share_offer.created'
          AND permission = 'share.offer'
          AND actor_principal_public_id = '01890f00-0000-7000-8000-000000000011'::UUID
          AND payload->>'scope_relation' = 'cross_workspace'
          AND payload->>'authority_side' = 'provider'
    )::INTEGER,
    pg_catalog.count(*) FILTER (
        WHERE action = 'share_offer.accepted'
          AND permission = 'share.accept'
          AND actor_principal_public_id = '01890f00-0000-7000-8000-000000000013'::UUID
          AND payload->>'scope_relation' = 'cross_workspace'
          AND payload->>'authority_side' = 'consumer'
    )::INTEGER
FROM mesh_audit.audit_event
WHERE target_kind = 'share_offer' AND target_public_id = $1::UUID`, offerID.String()).Scan(
		&providerConsent,
		&consumerConsent,
	); err != nil {
		t.Fatalf("query cross-Workspace consent evidence: %v", err)
	}
	if providerConsent != 2 || consumerConsent != 2 {
		t.Fatalf(
			"cross-Workspace provider/consumer consent evidence = %d/%d, want 2/2",
			providerConsent,
			consumerConsent,
		)
	}
}

func assertAtomicImportedPolicyPublication(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	session accountsession.Session,
	destination sharing.PolicyDestination,
) {
	t.Helper()
	const (
		releaseID     = "01890f93-0000-7000-8000-000000000001"
		projectionID  = "01890f93-0000-7000-8000-000000000002"
		ruleID        = "01890f93-0000-7000-8000-000000000003"
		changeID      = "01890f93-0000-7000-8000-000000000004"
		staleChangeID = "01890f93-0000-7000-8000-000000000005"
	)
	var sourceNodeID string
	if err := admin.QueryRow(ctx, `SELECT device.public_id::TEXT
FROM mesh.device AS device
WHERE device.workspace_id = 103
  AND device.network_id = 204
  AND device.state = 'active'
  AND pg_catalog.transaction_timestamp() < device.expires_at
ORDER BY device.id
LIMIT 1`).Scan(&sourceNodeID); err != nil {
		t.Fatalf("query active consumer Device: %v", err)
	}
	contract := destination.Contract()
	binding := contract.Resource()
	resourceHash := binding.SemanticHash().Bytes()
	constraintHash := contract.MaximumTraffic().Hash()
	publicationRule := map[string]any{
		"projection_public_id":                        projectionID,
		"access_rule_public_id":                       ruleID,
		"source_node_public_id":                       sourceNodeID,
		"protocol":                                    "tcp",
		"port_range_first":                            []int{443},
		"port_range_last":                             []int{443},
		"destination_imported_resource_public_id":     destination.ImportedResourceID().String(),
		"destination_imported_resource_version":       destination.ImportedResourceVersion(),
		"destination_trust_contract_public_id":        contract.ID().String(),
		"destination_trust_contract_version":          contract.Version(),
		"destination_resource_export_public_id":       contract.ExportID().String(),
		"destination_resource_export_version":         destination.ExportVersion(),
		"destination_provider_workspace_public_id":    destination.ProviderScope().WorkspaceID().String(),
		"destination_provider_network_public_id":      destination.ProviderScope().NetworkID().String(),
		"destination_provider_resource_public_id":     binding.ResourceID().String(),
		"destination_provider_resource_version":       binding.ResourceVersion(),
		"destination_provider_target_generation":      binding.TargetGeneration(),
		"destination_provider_resource_semantic_hash": hex.EncodeToString(resourceHash[:]),
		"destination_provider_inventory_revision":     destination.ProviderInventoryRevision(),
		"destination_provider_sharing_revision":       destination.ProviderSharingRevision(),
		"destination_consumer_sharing_revision":       destination.ConsumerSharingRevision(),
		"destination_provider_authority_generation":   contract.ProviderAuthorityGeneration(),
		"destination_consumer_authority_generation":   contract.ConsumerAuthorityGeneration(),
		"destination_recovery_epoch":                  contract.RecoveryEpoch(),
		"destination_contract_expires_at":             contract.ExpiresAt().UTC().Format(time.RFC3339Nano),
		"destination_constraint_hash":                 hex.EncodeToString(constraintHash[:]),
	}
	payload, err := json.Marshal([]map[string]any{publicationRule})
	if err != nil {
		t.Fatalf("encode Imported Resource publication fixture: %v", err)
	}
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin Imported Resource publication transaction: %v", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	setIntegrationScope(ctx, t, transaction, 103, 204)
	setIntegrationChange(ctx, t, transaction, changeID)
	var baseNetworkRevision, basePolicyRevision int64
	if err := transaction.QueryRow(ctx, `SELECT network_revision, policy_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 204`).Scan(
		&baseNetworkRevision, &basePolicyRevision,
	); err != nil {
		t.Fatalf("query Imported Resource publication baseline: %v", err)
	}
	semanticHash := sha256.Sum256(payload)
	var networkRevision, policyRevision, releaseVersion int64
	if err := transaction.QueryRow(ctx, `SELECT network_revision, policy_revision, release_version
FROM mesh_ops.publish_compiled_policy(
	$1::UUID, $2::BIGINT, $3::BYTEA, 4, $4::TIMESTAMPTZ, $5::JSONB
)`, releaseID, basePolicyRevision, semanticHash[:], destination.EvaluatedAt(), payload).Scan(
		&networkRevision, &policyRevision, &releaseVersion,
	); err != nil {
		_ = transaction.Rollback(ctx)
		t.Fatalf("publish Imported Resource policy atomically: %v", err)
	}
	if networkRevision != baseNetworkRevision+1 || policyRevision != basePolicyRevision+1 ||
		releaseVersion != 1 {
		t.Fatalf("Imported Resource publication revisions = %d/%d/%d, base = %d/%d",
			networkRevision, policyRevision, releaseVersion,
			baseNetworkRevision, basePolicyRevision)
	}
	var provenanceCount, localRuleCount int
	if err := transaction.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*)
     FROM mesh.compiled_policy_imported_resource_destination AS imported
     JOIN mesh.policy_release AS release ON release.id = imported.policy_release_id
     WHERE release.public_id = $1::UUID),
    (SELECT pg_catalog.count(*)
     FROM mesh.compiled_policy_rule AS rule
     JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
     WHERE release.public_id = $1::UUID)`, releaseID).Scan(
		&provenanceCount, &localRuleCount,
	); err != nil {
		t.Fatalf("query Imported Resource publication evidence: %v", err)
	}
	if provenanceCount != 1 || localRuleCount != 0 {
		t.Fatalf("Imported Resource publication evidence = provenance %d, local rules %d",
			provenanceCount, localRuleCount)
	}
	assertDirectMapSQLProjection(ctx, t, transaction, destination)
	assertSharedDestinationExplanation(ctx, t, transaction, session, destination, sourceNodeID, ruleID)
	assertSharedDestinationGraph(ctx, t, transaction, session, destination, sourceNodeID, ruleID)
	if err := transaction.Rollback(ctx); err != nil {
		t.Fatalf("rollback Imported Resource publication probe: %v", err)
	}
	var releaseCount int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh.policy_release
WHERE public_id = $1::UUID`, releaseID).Scan(&releaseCount); err != nil {
		t.Fatalf("verify Imported Resource publication rollback: %v", err)
	}
	if releaseCount != 0 {
		t.Fatalf("Imported Resource publication probe leaked %d releases", releaseCount)
	}

	publicationRule["destination_provider_inventory_revision"] =
		destination.ProviderInventoryRevision() + 1
	stalePayload, err := json.Marshal([]map[string]any{publicationRule})
	if err != nil {
		t.Fatalf("encode stale Imported Resource publication fixture: %v", err)
	}
	staleHash := sha256.Sum256(stalePayload)
	staleTransaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin stale Imported Resource publication transaction: %v", err)
	}
	setIntegrationScope(ctx, t, staleTransaction, 103, 204)
	setIntegrationChange(ctx, t, staleTransaction, staleChangeID)
	var ignoredNetworkRevision, ignoredPolicyRevision, ignoredReleaseVersion int64
	err = staleTransaction.QueryRow(ctx, `SELECT network_revision, policy_revision, release_version
FROM mesh_ops.publish_compiled_policy(
	$1::UUID, $2::BIGINT, $3::BYTEA, 4, $4::TIMESTAMPTZ, $5::JSONB
)`, releaseID, basePolicyRevision, staleHash[:], destination.EvaluatedAt(), stalePayload).Scan(
		&ignoredNetworkRevision, &ignoredPolicyRevision, &ignoredReleaseVersion,
	)
	postgresError, isPostgresError := errors.AsType[*pgconn.PgError](err)
	if !isPostgresError || postgresError.Code != "MT001" {
		_ = staleTransaction.Rollback(ctx)
		t.Fatalf("stale Imported Resource publication error = %v, want MT001", err)
	}
	if err := staleTransaction.Rollback(ctx); err != nil {
		t.Fatalf("rollback stale Imported Resource publication: %v", err)
	}
	var currentNetworkRevision, currentPolicyRevision int64
	if err := admin.QueryRow(ctx, `SELECT network_revision, policy_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 204`).Scan(
		&currentNetworkRevision, &currentPolicyRevision,
	); err != nil {
		t.Fatalf("query revision after stale publication: %v", err)
	}
	if currentNetworkRevision != baseNetworkRevision || currentPolicyRevision != basePolicyRevision {
		t.Fatalf(
			"stale Imported Resource publication advanced revisions to %d/%d, want %d/%d",
			currentNetworkRevision,
			currentPolicyRevision,
			baseNetworkRevision,
			basePolicyRevision,
		)
	}
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh.policy_release
WHERE public_id = $1::UUID`, releaseID).Scan(&releaseCount); err != nil {
		t.Fatalf("verify stale Imported Resource publication rollback: %v", err)
	}
	if releaseCount != 0 {
		t.Fatalf("stale Imported Resource publication leaked %d releases", releaseCount)
	}
}

func newIntegrationResourceSharingStore(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *postgresadapter.ResourceSharingStore {
	t.Helper()
	store, err := postgresadapter.NewResourceSharingStore(
		runtimePool,
		postgresadapter.ResourceSharingOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
			IdempotencyTTL:   time.Hour,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewResourceSharingStore() error = %v", err)
	}
	return store
}

func integrationSharingTraffic(t *testing.T) sharing.TrafficSet {
	t.Helper()
	port, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatalf("policy.NewPortRange() error = %v", err)
	}
	constraint, err := sharing.NewTrafficConstraint(sharing.TrafficConstraintParams{
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{port},
	})
	if err != nil {
		t.Fatalf("sharing.NewTrafficConstraint() error = %v", err)
	}
	traffic, err := sharing.NewTrafficSet([]sharing.TrafficConstraint{constraint})
	if err != nil {
		t.Fatalf("sharing.NewTrafficSet() error = %v", err)
	}
	return traffic
}

func assertCommittedResourceSharingEvidence(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	offerID sharing.OfferID,
	contractID sharing.ContractID,
) {
	t.Helper()
	var offerCount, contractCount, importCount, auditCount, outboxCount int
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh.share_offer WHERE public_id = $1::UUID),
    (SELECT pg_catalog.count(*) FROM mesh.trust_contract WHERE public_id = $2::UUID AND state = 'revoked'),
    (SELECT pg_catalog.count(*) FROM mesh.imported_resource AS imported
     JOIN mesh.trust_contract AS contract ON contract.id = imported.trust_contract_id
     WHERE contract.public_id = $2::UUID AND imported.state = 'revoked'),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event
     WHERE target_public_id IN ($1::UUID, $2::UUID)),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event
     WHERE event_class = 'network.revision.advanced'
       AND payload->>'subsystem' = 'sharing')`, offerID.String(), contractID.String()).Scan(
		&offerCount, &contractCount, &importCount, &auditCount, &outboxCount,
	); err != nil {
		t.Fatalf("query committed Resource Sharing evidence: %v", err)
	}
	if offerCount != 1 || contractCount != 1 || importCount != 1 ||
		auditCount != 8 || outboxCount < 8 {
		t.Fatalf(
			"Resource Sharing evidence offer=%d contract=%d import=%d audit=%d outbox=%d",
			offerCount, contractCount, importCount, auditCount, outboxCount,
		)
	}
}

// assertDerivedAccessName checks that a new offer carries a frozen label and
// the Core-derived <label>.<workspace code>.<network code>.shared.mesh name.
func assertDerivedAccessName(t *testing.T, offer sharing.OfferSnapshot) {
	t.Helper()
	label := offer.AccessLabel()
	pattern := regexp.MustCompile(`^` + regexp.QuoteMeta(label.String()) + `\.[0-9]{12}\.[0-9]{12}\.shared\.mesh$`)
	if !label.IsValid() || !pattern.MatchString(offer.AccessName().String()) {
		t.Fatalf("offer access label/name = %q/%q", label, offer.AccessName())
	}
}

// assertCrossWorkspaceNoExpiryOffer covers the owner decision of 2026-10-06:
// a cross-Workspace share may have no scheduled expiry, while any other
// deadline stays within 30 days. The consumer rejects the offer so the
// finite share below proceeds alone.
func assertCrossWorkspaceNoExpiryOffer(
	ctx context.Context,
	t *testing.T,
	service *sharing.Service,
	providerScope, consumerScope network.Scope,
	resourceID resource.ID,
	maximumTraffic sharing.TrafficSet,
	reason sharing.AuditReason,
	providerSession, consumerSession accountsession.Session,
) {
	t.Helper()
	tooLong, err := sharing.NewCreateOffer(sharing.CreateOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ResourceID: resourceID, MaximumTraffic: maximumTraffic,
		ExpiresAt: time.Now().UTC().Add(31 * 24 * time.Hour), AccountSession: providerSession,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 221),
	})
	if err == nil {
		if _, err = service.CreateOffer(ctx, tooLong); !errors.Is(err, sharing.ErrInvalidManagementRequest) {
			t.Fatalf("cross-Workspace 31-day share: error = %v, want invalid", err)
		}
	}
	command, err := sharing.NewCreateOffer(sharing.CreateOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		ResourceID: resourceID, MaximumTraffic: maximumTraffic,
		ExpiresAt: sharing.NoExpiryTime(), AccountSession: providerSession,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 222),
	})
	if err != nil {
		t.Fatalf("construct cross-Workspace share without expiry: %v", err)
	}
	created, err := service.CreateOffer(ctx, command)
	if err != nil {
		t.Fatalf("create cross-Workspace share without expiry: %v", err)
	}
	offer, hasOffer := created.Offer()
	token, hasToken := created.Token()
	if !hasOffer || !hasToken || offer.Offer().ScopeRelation() != sharing.ScopeRelationCrossWorkspace ||
		!sharing.HasNoExpiry(offer.ShareExpiresAt()) {
		t.Fatalf("cross-Workspace share without expiry = %+v", created)
	}
	reject, err := sharing.NewDecideOffer(sharing.DecideOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope,
		OfferID: offer.Offer().ID(), ExpectedOfferVersion: offer.Offer().Version(),
		Token: token, Action: sharing.DecisionActionReject, AccountSession: consumerSession,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 223),
	})
	if err != nil {
		t.Fatalf("construct cross-Workspace rejection: %v", err)
	}
	if _, err := service.DecideOffer(ctx, reject); err != nil {
		t.Fatalf("reject cross-Workspace share without expiry: %v", err)
	}
}
