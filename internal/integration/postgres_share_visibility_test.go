//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

// assertProviderSeesWhoAccesses lists the provider's accepted outgoing
// shares: the provider learns the contract's state and expiry and the
// consumer Network's display code, which it typed when it shared.
func assertProviderSeesWhoAccesses(
	ctx context.Context,
	t *testing.T,
	service *sharing.Service,
	providerSession accountsession.Session,
	providerScope network.Scope,
	offerID sharing.OfferID,
	contract sharing.Contract,
) {
	t.Helper()
	page, err := service.ListOffers(
		ctx, providerSession, providerScope, sharing.DirectionOutgoing,
		sharing.OfferStateAccepted, 100, sharing.EmptyPageCursor(),
	)
	if err != nil {
		t.Fatalf("list provider outgoing accepted shares: %v", err)
	}
	for _, item := range page.Items() {
		if item.Offer().ID() != offerID {
			continue
		}
		listed, hasContract := item.Contract()
		codes := item.DisplayCodes()
		if !hasContract || listed.ID() != contract.ID() || listed.State() != sharing.ContractStateActive ||
			!listed.ExpiresAt().Equal(contract.ExpiresAt()) ||
			!codes.ConsumerNetwork.IsValid() || !codes.ProviderNetwork.IsValid() {
			t.Fatalf("provider view of the share = contract %+v (%t), codes %+v", listed, hasContract, codes)
		}
		return
	}
	t.Fatalf("provider outgoing shares omit accepted offer %s", offerID)
}

// assertImportedDeviceCannotBeReshared proves trust is not transitive: the
// consumer cannot offer a Device it received, because an offer exports only
// a Resource of the offering Network and a shared-in Device is not one.
func assertImportedDeviceCannotBeReshared(
	ctx context.Context,
	t *testing.T,
	service *sharing.Service,
	consumerSession accountsession.Session,
	consumerScope network.Scope,
	providerScope network.Scope,
	importedID sharing.ImportedResourceID,
	maximumTraffic sharing.TrafficSet,
	reason sharing.AuditReason,
) {
	t.Helper()
	asResource, err := resource.ParseID(importedID.String())
	if err != nil {
		t.Fatalf("read imported Device identity as a Resource: %v", err)
	}
	command, err := sharing.NewCreateOffer(sharing.CreateOfferParams{
		ProviderScope: consumerScope, ConsumerScope: providerScope,
		ResourceID: asResource, MaximumTraffic: maximumTraffic,
		ExpiresAt: time.Now().UTC().Add(time.Hour), AccountSession: consumerSession,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 231),
	})
	if err != nil {
		t.Fatalf("construct re-share offer: %v", err)
	}
	if created, err := service.CreateOffer(ctx, command); err == nil {
		t.Fatalf("consumer re-shared an imported Device: %+v", created)
	}
}
