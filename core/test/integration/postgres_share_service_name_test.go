//go:build integration

package integration

import (
	"context"
	"errors"
	"net/netip"
	"slices"
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

	assertContractServiceNames(ctx, t, admin, runtimePool, dnsZones, session, providerScope, consumerScope,
		contract.ID(), share)

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
	contractNames, err := postgresadapter.NewContractServiceNameStore(runtimePool, postgresadapter.AccountSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second}, dnsZones)
	if err != nil {
		t.Fatal(err)
	}
	ended, err := contractNames.ContractServiceNames(ctx, session, providerScope, contract.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := contractNames.ReplaceContractServiceNames(ctx, session, providerScope, contract.ID(),
		ended.Version, nil, newCorrelationID(t)); !errors.Is(err, sharing.ErrContractEnded) {
		t.Fatalf("a revoked contract's suggestions changed: %v", err)
	}
	if len(ended.Names) == 0 {
		t.Fatal("the revoked contract lost its suggestions")
	}
	if _, _, err := contractNames.UseContractServiceName(ctx, session, consumerScope, contract.ID(), ended.Names[0],
		newCorrelationID(t)); !errors.Is(err, sharing.ErrContractEnded) {
		t.Fatalf("a revoked contract's name was used: %v", err)
	}
	read, err := dnsZones.Read(ctx, session, consumerScope, zone.Zone.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dnsZones.Delete(ctx, session, consumerScope, zone.Zone.ID, read.Zone.Version, true,
		newCorrelationID(t)); err != nil {
		t.Fatalf("delete zone %s with its names: %v", zone.Zone.ID, err)
	}
	for _, id := range ownZones(ctx, t, admin, consumerScope) {
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

// ownZones lists the active zones of the scope's Network.
func ownZones(ctx context.Context, t *testing.T, admin *pgx.Conn, scope network.Scope) []dnszone.ID {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT zone.public_id::TEXT FROM mesh.network_dns_zone AS zone
JOIN mesh.network AS net ON net.id = zone.network_id
WHERE net.public_id = $1::UUID AND zone.state = 'active' ORDER BY zone.id`, scope.NetworkID().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var zones []dnszone.ID
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		id, err := dnszone.ParseID(value)
		if err != nil {
			t.Fatal(err)
		}
		zones = append(zones, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return zones
}

// assertContractServiceNames checks the service names of a running share
// (DNS design D3 §19, schema 220), right after an accept that approved
// app.meshtransit-d3.com and wiki.svc.internal and declined
// taken.svc.internal: both sides read the suggestions, only the consumer its
// names; the provider replaces them at the version it read, which never
// touches the consumer's names and is audited; the consumer makes a current
// suggestion a DNS name of its Network, and nothing else.
func assertContractServiceNames(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, dnsZones *dnszone.Service, session accountsession.Session,
	providerScope, consumerScope network.Scope, contractID sharing.ContractID, share sharing.ImportedResourceID,
) {
	t.Helper()
	store, err := postgresadapter.NewContractServiceNameStore(runtimePool, postgresadapter.AccountSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second}, dnsZones)
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
	fqdns := func(names []sharing.ContractDNSName) []string {
		values := make([]string, 0, len(names))
		for _, item := range names {
			values = append(values, item.FQDN)
		}
		return values
	}
	consumer, err := store.ContractServiceNames(ctx, session, consumerScope, contractID)
	if err != nil || consumer.Provider || consumer.Version != 0 || len(consumer.Names) != 3 ||
		consumer.ShareID != share || !slices.Equal(fqdns(consumer.DNSNames),
		[]string{"app.meshtransit-d3.com", "wiki.svc.internal"}) || !consumer.Running(time.Now()) {
		t.Fatalf("the consumer's read = %+v, error = %v", consumer, err)
	}
	provider, err := store.ContractServiceNames(ctx, session, providerScope, contractID)
	if err != nil || !provider.Provider || provider.Version != 0 || len(provider.Names) != 3 ||
		provider.ShareID.IsValid() || len(provider.DNSNames) != 0 {
		t.Fatalf("the provider's read = %+v, error = %v", provider, err)
	}

	next := []sharing.ServiceName{name("app.meshtransit-d3.com"), name("shop.svc.internal")}
	replaced, changed, err := store.ReplaceContractServiceNames(ctx, session, providerScope, contractID, 0, next,
		newCorrelationID(t))
	if err != nil || !changed || replaced.Version != 1 || !slices.Equal(replaced.Names, next) {
		t.Fatalf("replace at version 0 = %+v, %v, error = %v", replaced, changed, err)
	}
	if _, changed, err := store.ReplaceContractServiceNames(ctx, session, providerScope, contractID, 1, next,
		newCorrelationID(t)); err != nil || changed {
		t.Fatalf("the same names again: changed %v, error = %v", changed, err)
	}
	// A second change updates the set, one version on.
	reordered := []sharing.ServiceName{next[1], next[0]}
	if replaced, changed, err := store.ReplaceContractServiceNames(ctx, session, providerScope, contractID, 1,
		reordered, newCorrelationID(t)); err != nil || !changed || replaced.Version != 2 {
		t.Fatalf("replace at version 1 = %+v, %v, error = %v", replaced, changed, err)
	}
	if replaced, _, err := store.ReplaceContractServiceNames(ctx, session, providerScope, contractID, 2, next,
		newCorrelationID(t)); err != nil || replaced.Version != 3 || !slices.Equal(replaced.Names, next) {
		t.Fatalf("replace at version 2 = %+v, error = %v", replaced, err)
	}
	var revisions int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(DISTINCT (event.payload ->> 'version'))
FROM mesh_audit.audit_event AS event
WHERE event.action = 'trust_contract.service_names_changed' AND event.payload ->> 'trust_contract_id' = $1`,
		contractID.String()).Scan(&revisions); err != nil || revisions != 3 {
		t.Fatalf("audited versions = %d, error = %v", revisions, err)
	}
	if _, _, err := store.ReplaceContractServiceNames(ctx, session, providerScope, contractID, 0, nil,
		newCorrelationID(t)); !errors.Is(err, sharing.ErrServiceNamesChanged) {
		t.Fatalf("a replace at a stale version: %v", err)
	}
	if _, _, err := store.ReplaceContractServiceNames(ctx, session, consumerScope, contractID, 1, nil,
		newCorrelationID(t)); !errors.Is(err, sharing.ErrForbidden) {
		t.Fatalf("the consumer replaced the suggestions: %v", err)
	}
	// The consumer's names stay; the read shows the new suggestions.
	consumer, err = store.ContractServiceNames(ctx, session, consumerScope, contractID)
	if err != nil || consumer.Version != 3 || !slices.Equal(consumer.Names, next) || len(consumer.DNSNames) != 2 {
		t.Fatalf("the consumer's read after the replace = %+v, error = %v", consumer, err)
	}

	if _, _, err := store.UseContractServiceName(ctx, session, consumerScope, contractID, name("wiki.svc.internal"),
		newCorrelationID(t)); !errors.Is(err, sharing.ErrServiceNameNotSuggested) {
		t.Fatalf("a name no longer suggested was used: %v", err)
	}
	made, zone, err := store.UseContractServiceName(ctx, session, consumerScope, contractID,
		name("shop.svc.internal"), newCorrelationID(t))
	if err != nil || made.FQDN != "shop.svc.internal" || zone.Domain.String() != "svc.internal" ||
		made.Target.ShareID != share {
		t.Fatalf("use shop.svc.internal = %+v in %+v, error = %v", made, zone, err)
	}
	if _, _, err := store.UseContractServiceName(ctx, session, consumerScope, contractID, name("shop.svc.internal"),
		newCorrelationID(t)); !errors.Is(err, dnszone.ErrNameTaken) {
		t.Fatalf("a name used twice: %v", err)
	}
	if _, _, err := store.UseContractServiceName(ctx, session, providerScope, contractID, name("shop.svc.internal"),
		newCorrelationID(t)); !errors.Is(err, sharing.ErrForbidden) {
		t.Fatalf("the provider used a name: %v", err)
	}
	consumer, err = store.ContractServiceNames(ctx, session, consumerScope, contractID)
	if err != nil || len(consumer.DNSNames) != 3 {
		t.Fatalf("the consumer's names after a use = %+v, error = %v", consumer, err)
	}
}
