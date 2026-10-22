//go:build integration

package integration

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	postgresmapsession "meshtransit.net/core/internal/adapter/postgres/mapsession"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
)

// assertDNSZoneMaps qualifies schema 214 through the shared map store, for
// zone corp.internal sent to group with resolver Device then 1.1.1.1: before
// any rule admits the group to the resolver, the consumer's route asks only
// 1.1.1.1; once a rule admits UDP 5335 it asks the resolver first, the
// resolver is a peer of its map, and the resolver's map, which never gets
// its own zone, keeps the consumer as a peer; Derive rebuilds the same; a
// store without DNS zones carries none. It publishes a deny-all release
// before it returns.
func assertDNSZoneMaps(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool,
	owner accountsession.Session, scope network.Scope, group devicegroup.ID, resolver, consumer node.ID) {
	t.Helper()
	resolverIdentity, consumerIdentity := fixtureDeviceIdentity(ctx, t, admin, resolver),
		fixtureDeviceIdentity(ctx, t, admin, consumer)
	storeWith := func(dnsZones bool) *postgresmapsession.Store {
		store, err := postgresadapter.NewMapSessionStore(runtimePool, postgresadapter.MapSessionOptions{
			StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
			PeerCandidateLimit: mapsession.MaximumPeerCandidates, PolicyRuleLimit: mapsession.MaximumPacketPolicyRules,
			RelayDirectory: integrationRelayDirectory(t), SharedInventory: true,
			InventoryStatementTimeout: 30 * time.Second, InventoryMaxAge: 30 * time.Second,
			DNSZones: dnsZones, RoutePeerLimit: mapsession.DefaultPeerLimit,
		})
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	zones := storeWith(true)
	internet := mapsession.DNSResolverRoute{Address: netip.MustParseAddr("1.1.1.1"), Port: 53}
	corp := func(snapshot mapsession.Snapshot) mapsession.DNSZoneRoute {
		t.Helper()
		for _, zone := range snapshot.Routes().DNSZones() {
			if zone.Domain == "corp.internal" {
				return zone
			}
		}
		t.Fatalf("corp.internal not in the map: %+v", snapshot.Routes().DNSZones())
		return mapsession.DNSZoneRoute{}
	}
	before, err := zones.Load(ctx, consumerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if zone := corp(before); zone.FailOpen || zone.SearchPosition != 1 ||
		!slices.Equal(zone.Resolvers, []mapsession.DNSResolverRoute{internet}) {
		t.Fatalf("corp.internal without a rule = %+v", zone)
	}

	compiler := newIntegrationSitePolicyCompiler(t, runtimePool)
	reason, err := publication.NewAuditReason("integration DNS zone maps")
	if err != nil {
		t.Fatal(err)
	}
	publish := func(base int64, intents ...compilation.RuleIntent) {
		t.Helper()
		if intents == nil {
			intents = []compilation.RuleIntent{} // deny-all
		}
		candidate, err := compileSiteRules(ctx, t, compiler, owner, scope, base+1, intents...)
		if err != nil {
			t.Fatal(err)
		}
		command, err := publication.NewManagementCommand(publication.ManagementCommandParams{
			Candidate: candidate, BasePolicyRevision: base, AccountSession: owner, AuditReason: reason,
		})
		if err != nil {
			t.Fatal(err)
		}
		publishPolicyOverBrowserManagement(ctx, t, runtimePool,
			newIntegrationManagementPolicyPublicationService(t, runtimePool), command)
	}
	publish(fixturePolicyRevision(ctx, t, admin), dnsRuleIntent(t, scope, group, resolver, 5335))
	defer publish(fixturePolicyRevision(ctx, t, admin))

	consumerMap, err := zones.Load(ctx, consumerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if zone := corp(consumerMap); !slices.Equal(zone.Resolvers, []mapsession.DNSResolverRoute{
		{NodeID: resolver, Port: 5335}, internet}) {
		t.Fatalf("corp.internal with a rule = %+v", zone)
	}
	if !slices.Contains(consumerMap.Routes().Peers(), resolver) || !slices.ContainsFunc(consumerMap.AuthorizedPeers(),
		func(peer mapsession.PeerCandidate) bool { return peer.NodeID() == resolver }) {
		t.Fatal("the consumer's map lacks its resolver Device as a needed peer")
	}
	resolverMap, err := zones.Load(ctx, resolverIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(resolverMap.Routes().DNSZones(), func(zone mapsession.DNSZoneRoute) bool {
		return zone.Domain == "corp.internal"
	}) || !slices.Contains(resolverMap.Routes().Peers(), consumer) {
		t.Fatalf("resolver map zones %+v, peers %v", resolverMap.Routes().DNSZones(), resolverMap.Routes().Peers())
	}
	if derived, found, err := zones.Derive(ctx, consumerMap, 0); err != nil || !found ||
		!derived.Routes().Equal(consumerMap.Routes()) {
		t.Fatalf("derived consumer zones = %+v, found %t, error %v", derived.Routes().DNSZones(), found, err)
	}
	if plain, err := storeWith(false).Load(ctx, consumerIdentity); err != nil || len(plain.Routes().DNSZones()) != 0 {
		t.Fatalf("zones without DNS zones on = %+v, error %v", plain.Routes().DNSZones(), err)
	}
}

// dnsRuleIntent admits source to the resolver Device over UDP on port.
func dnsRuleIntent(t *testing.T, scope network.Scope, source devicegroup.ID, resolver node.ID,
	port uint16) compilation.RuleIntent {
	t.Helper()
	ruleID, err := policy.ParseRuleID(newCorrelationID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	ports, err := policy.NewPortRange(port, port)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: ruleID, Scope: scope, SourceGroupID: source, DestinationNodeID: resolver,
		Protocol: policy.ProtocolUDP, DestinationPortRanges: []policy.PortRange{ports},
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

// assertDNSNameMaps qualifies schema 216 through the shared map store for
// the nxdomain zone corp.internal and its names: the map of target sees its
// own name, and another Device's map, which no rule lets reach target, does
// not; both see the fixed-address names and the CNAME, and the zone with its
// kind.
func assertDNSNameMaps(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool,
	target, other node.ID) {
	t.Helper()
	store, err := postgresadapter.NewMapSessionStore(runtimePool, postgresadapter.MapSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
		PeerCandidateLimit: mapsession.MaximumPeerCandidates, PolicyRuleLimit: mapsession.MaximumPacketPolicyRules,
		RelayDirectory: integrationRelayDirectory(t), SharedInventory: true,
		InventoryStatementTimeout: 30 * time.Second, InventoryMaxAge: 30 * time.Second,
		DNSZones: true, RoutePeerLimit: mapsession.DefaultPeerLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	names := func(device node.ID) []string {
		t.Helper()
		snapshot, err := store.Load(ctx, fixtureDeviceIdentity(ctx, t, admin, device))
		if err != nil {
			t.Fatal(err)
		}
		kind := mapsession.DNSOtherUnknown
		for _, zone := range snapshot.Routes().DNSZones() {
			if zone.Domain == "corp.internal" {
				kind = zone.OtherNames
			}
		}
		if kind != mapsession.DNSOtherNXDomain {
			t.Fatalf("corp.internal in the map of %s: %v", device, kind)
		}
		var fqdns []string
		for _, name := range snapshot.Routes().DNSNames() {
			fqdns = append(fqdns, name.FQDN)
		}
		return fqdns
	}
	if own := names(target); !slices.Equal(own, []string{"corp.internal", "git.corp.internal",
		"printer.corp.internal", "wiki.corp.internal"}) {
		t.Fatalf("the target's names = %v", own)
	}
	if seen := names(other); !slices.Equal(seen, []string{"corp.internal", "printer.corp.internal",
		"wiki.corp.internal"}) {
		t.Fatalf("another Device's names = %v", seen)
	}
}
