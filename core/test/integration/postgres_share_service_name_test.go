//go:build integration

package integration

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/sharing"
)

// assertShareServiceNames checks service names on a share offer (DNS design
// D3a, schema 218): the provider suggests them with the offer, both sides
// read them and no other Network does, and the consumer's accept answers each
// one. Approved names become DNS names of the consumer Network pointing at
// the share, in the zone that covers them or a zone of their own, in the
// accept's transaction: a name that cannot be made rolls the whole accept
// back.
func assertShareServiceNames(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	session accountsession.Session,
	providerScope, consumerScope, foreignScope network.Scope,
	resourceID resource.ID,
	maximumTraffic sharing.TrafficSet,
	reason sharing.AuditReason,
) {
	t.Helper()
	dnsZones := newIntegrationDNSZoneService(t, runtimePool, dnszone.DefaultLimits())
	store, err := postgresadapter.NewResourceSharingStore(runtimePool, postgresadapter.ResourceSharingOptions{
		StatementTimeout: 5 * time.Second, LockTimeout: 2 * time.Second, IdleTimeout: 10 * time.Second,
		IdempotencyTTL: time.Hour, ServiceNames: dnsZones,
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := sharing.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	name := func(value string) sharing.ServiceName {
		parsed, err := sharing.ParseServiceName(value)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	suggested := []sharing.ServiceName{name("app.meshtransit-d3.com"), name("wiki.svc.internal"),
		name("taken.svc.internal")}
	accessLabel, err := sharing.ParseAccessLabel("svc-names")
	if err != nil {
		t.Fatal(err)
	}
	offerCommand, err := sharing.NewCreateOffer(sharing.CreateOfferParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope, ResourceID: resourceID,
		MaximumTraffic: maximumTraffic, ExpiresAt: time.Now().UTC().Add(time.Hour), AccessLabel: accessLabel,
		ServiceNames: suggested, AccountSession: session, Reason: reason, Idempotency: resourceAuthorityProof(t, 180),
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.CreateOffer(ctx, offerCommand)
	if err != nil {
		t.Fatalf("create an offer with service names: %v", err)
	}
	offer, _ := created.Offer()
	token, _ := created.Token()
	offerID := offer.Offer().ID()
	for _, scope := range []network.Scope{providerScope, consumerScope} {
		names, err := store.OfferServiceNames(ctx, scope, offerID)
		if err != nil || len(names) != 3 || names[0] != suggested[0] || names[2] != suggested[2] {
			t.Fatalf("service names read by %v = %v, error = %v", scope, names, err)
		}
	}
	if names, err := store.OfferServiceNames(ctx, foreignScope, offerID); err == nil && len(names) != 0 {
		t.Fatalf("another Network read the offer's service names: %v", names)
	}

	displayName, err := resource.ParseDisplayName("Service names Resource")
	if err != nil {
		t.Fatal(err)
	}
	accept := func(decisions []sharing.ServiceNameDecision, marker byte) (sharing.MutationResult, error) {
		command, err := sharing.NewDecideOffer(sharing.DecideOfferParams{
			ProviderScope: providerScope, ConsumerScope: consumerScope, OfferID: offerID,
			ExpectedOfferVersion: offer.Offer().Version(), Token: token, Action: sharing.DecisionActionAccept,
			ImportedDisplayName: displayName, ServiceNames: decisions, AccountSession: session, Reason: reason,
			Idempotency: resourceAuthorityProof(t, marker),
		})
		if err != nil {
			t.Fatal(err)
		}
		return service.DecideOffer(ctx, command)
	}
	// A session that may accept shares but not manage DNS approves nothing.
	if _, err := accept([]sharing.ServiceNameDecision{{Name: suggested[0], Approve: true}, {Name: suggested[1]},
		{Name: suggested[2]}}, 185); !errors.As(err, new(*sharing.ServiceNameError)) ||
		!errors.Is(err, dnszone.ErrForbidden) {
		t.Fatalf("an approval without dns.manage: %v", err)
	}
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	// The consumer already has a zone, and a name in it.
	zone, err := dnsZones.Create(ctx, session, consumerScope, dnszone.Definition{Domain: "svc.internal",
		OtherNames: dnszone.OtherNXDomain}, false, newCorrelationID(t))
	if err != nil {
		t.Fatalf("create the consumer's zone: %v", err)
	}
	if _, err := dnsZones.CreateName(ctx, session, consumerScope, zone.Zone.ID, dnszone.NameDefinition{
		Label: "taken", Kind: dnszone.NameAddress,
		Target: dnszone.NameTarget{Addresses: []netip.Addr{netip.MustParseAddr("10.0.7.1")}},
	}, newCorrelationID(t)); err != nil {
		t.Fatalf("create the consumer's own name: %v", err)
	}

	approveAll := []sharing.ServiceNameDecision{{Name: suggested[0], Approve: true},
		{Name: suggested[1], Approve: true}, {Name: suggested[2], Approve: true}}
	_, err = accept(approveAll, 181)
	var failure *sharing.ServiceNameError
	if !errors.As(err, &failure) || failure.Index != 2 || !errors.Is(err, dnszone.ErrNameTaken) {
		t.Fatalf("an accept approving a taken name: %v", err)
	}
	// Nothing of it stayed: the offer is still open, no zone was made.
	if reread, err := service.GetOffer(ctx, session, consumerScope, offerID); err != nil ||
		reread.Offer().State() != sharing.OfferStateOffered {
		t.Fatalf("the offer after a failed accept = %+v, error = %v", reread, err)
	}
	var appZones int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.network_dns_zone
WHERE domain = 'app.meshtransit-d3.com' AND state = 'active'`).Scan(&appZones); err != nil || appZones != 0 {
		t.Fatalf("zones left by a failed accept = %d, error = %v", appZones, err)
	}
	if _, err := accept(approveAll[:2], 182); !errors.Is(err, sharing.ErrServiceNameDecisions) {
		t.Fatalf("an accept that leaves a name unanswered: %v", err)
	}

	accepted, err := accept([]sharing.ServiceNameDecision{{Name: suggested[2]},
		{Name: suggested[0], Approve: true}, {Name: suggested[1], Approve: true}}, 183)
	if err != nil {
		t.Fatalf("an accept approving two names: %v", err)
	}
	contract, found := accepted.Contract()
	if !found {
		t.Fatalf("accepted = %+v", accepted)
	}
	share := contract.ImportedResourceID()
	// A replay answers the same accept and makes no name twice; the same key
	// with other answers is refused.
	replayed, err := accept([]sharing.ServiceNameDecision{{Name: suggested[2]},
		{Name: suggested[0], Approve: true}, {Name: suggested[1], Approve: true}}, 183)
	if replayContract, found := replayed.Contract(); err != nil || !found || replayContract.ID() != contract.ID() {
		t.Fatalf("a replayed accept = %+v, error = %v", replayed, err)
	}
	if _, err := accept([]sharing.ServiceNameDecision{{Name: suggested[2]},
		{Name: suggested[0], Approve: true}, {Name: suggested[1]}}, 183); err == nil {
		t.Fatal("the same key accepted other answers")
	}
	inside, err := dnsZones.ListNames(ctx, session, consumerScope, zone.Zone.ID, dnszone.NameID{}, "wiki", 10)
	if err != nil || len(inside.Names) != 1 || inside.Names[0].FQDN != "wiki.svc.internal" ||
		inside.Names[0].Target.ShareID != share {
		t.Fatalf("the approved name in the consumer's zone = %+v, error = %v", inside, err)
	}
	var ownZoneID string
	if err := admin.QueryRow(ctx, `SELECT zone.public_id::TEXT FROM mesh.network_dns_zone AS zone
WHERE zone.domain = 'app.meshtransit-d3.com' AND zone.state = 'active' AND zone.other_names = 'host'
  AND zone.public_confirmed`).Scan(&ownZoneID); err != nil {
		t.Fatalf("the zone of its own for app.meshtransit-d3.com: %v", err)
	}
	ownZone, err := dnszone.ParseID(ownZoneID)
	if err != nil {
		t.Fatal(err)
	}
	own, err := dnsZones.ListNames(ctx, session, consumerScope, ownZone, dnszone.NameID{}, "", 10)
	if err != nil || len(own.Names) != 1 || own.Names[0].Label != dnszone.Apex ||
		own.Names[0].Target.ShareID != share || own.Names[0].Share == nil || !own.Names[0].Share.Active {
		t.Fatalf("the approved name in its own zone = %+v, error = %v", own, err)
	}

	// Leave no share or names behind for the steps that follow.
	revoke, err := sharing.NewRevokeContract(sharing.RevokeContractParams{
		ProviderScope: providerScope, ConsumerScope: consumerScope, ContractID: contract.ID(),
		ExpectedContractVersion: contract.Version(), LocalScope: consumerScope, AccountSession: session,
		Reason: reason, Idempotency: resourceAuthorityProof(t, 184),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RevokeContract(ctx, revoke); err != nil {
		t.Fatalf("revoke the share with service names: %v", err)
	}
	for _, id := range []dnszone.ID{zone.Zone.ID, ownZone} {
		read, err := dnsZones.Read(ctx, session, consumerScope, id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := dnsZones.Delete(ctx, session, consumerScope, id, read.Zone.Version, true,
			newCorrelationID(t)); err != nil {
			t.Fatalf("delete zone %s with its names: %v", id, err)
		}
	}
}
