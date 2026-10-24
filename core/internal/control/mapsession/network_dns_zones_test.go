package mapsession

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

// dnsFixture: Devices 1..8 live. Device group 10 = {1, 2, 3}. Zone 900
// corp.internal, closed, search position 1, sent to group 10, asks Device 7
// on port 5335 then 1.1.1.1. Zone 901 lab.lan, open, sent to every Device,
// asks Device 8 on port 53. Rules: group 10 -> Device 7 over UDP 5335;
// Device 4 -> Device 8 over UDP 53; group 10 -> Device 8 over TCP 53 only.
type dnsFixture struct {
	params NetworkPolicyParams
	ids    map[int64]node.ID
}

func newDNSFixture(t *testing.T) *dnsFixture {
	t.Helper()
	ids := map[int64]node.ID{}
	devices := make([]PolicyDevice, 0, 8)
	for device := int64(1); device <= 8; device++ {
		ids[device] = policyNodeID(t, device)
		devices = append(devices, PolicyDevice{Device: device, NodeID: ids[device], ExpiresAt: policyNow.Add(24 * time.Hour)})
	}
	port := func(value uint16) []policy.PortRange {
		return []policy.PortRange{must(policy.NewPortRange(value, value))}
	}
	return &dnsFixture{ids: ids, params: NetworkPolicyParams{
		Scope: snapshotFixture(t).Scope(), Revision: 4, ReleaseActive: true, Devices: devices,
		Members: []SelectorMember{
			{Kind: SelectorDeviceGroup, Selector: 10, Device: 1}, {Kind: SelectorDeviceGroup, Selector: 10, Device: 2},
			{Kind: SelectorDeviceGroup, Selector: 10, Device: 3},
		},
		Rules: []NetworkPolicyRule{
			{ID: policyRuleID(t, 1), SourceKind: SelectorDeviceGroup, SourceRef: 10, DestinationKind: SelectorDevice,
				DestinationRef: 7, Protocol: policy.ProtocolUDP, Ports: port(5335)},
			{ID: policyRuleID(t, 2), SourceKind: SelectorDevice, SourceRef: 4, DestinationKind: SelectorDevice,
				DestinationRef: 8, Protocol: policy.ProtocolUDP, Ports: port(53)},
			{ID: policyRuleID(t, 3), SourceKind: SelectorDeviceGroup, SourceRef: 10, DestinationKind: SelectorDevice,
				DestinationRef: 8, Protocol: policy.ProtocolTCP, Ports: port(53)},
		},
		RouteRevision: 9, RoutePeerLimit: 10_000,
		DNSZones: []DNSZone{
			{Zone: 901, Domain: "lab.lan", OtherNames: DNSOtherForward, FailOpen: true, Resolvers: []DNSZoneResolver{
				{Device: 8, NodeID: ids[8], Eligible: true, Port: 53}}},
			{Zone: 900, Domain: "corp.internal", OtherNames: DNSOtherForward, Groups: []int64{10}, SearchPosition: 1,
				Resolvers: []DNSZoneResolver{
					{Device: 7, NodeID: ids[7], Eligible: true, Port: 5335},
					{Address: netip.MustParseAddr("1.1.1.1"), Port: 53}}},
		},
	}}
}

func (fixture *dnsFixture) policy(t *testing.T) NetworkPolicy {
	t.Helper()
	networkPolicy, err := NewNetworkPolicy(fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	return networkPolicy
}

func TestRoutesForDNSZones(t *testing.T) {
	t.Parallel()
	fixture := newDNSFixture(t)
	ids := fixture.ids
	networkPolicy := fixture.policy(t)

	// A member of group 10: both zones, sorted by domain; lab.lan has no
	// resolver it may use (only TCP is allowed to Device 8).
	consumer := networkPolicy.RoutesFor(ids[1], policyNow)
	zones := consumer.DNSZones()
	if len(zones) != 2 || zones[0].Domain != "corp.internal" || zones[0].FailOpen || zones[0].SearchPosition != 1 ||
		!slices.Equal(zones[0].Resolvers, []DNSResolverRoute{{NodeID: ids[7], Port: 5335},
			{Address: netip.MustParseAddr("1.1.1.1"), Port: 53}}) ||
		zones[1].Domain != "lab.lan" || !zones[1].FailOpen || len(zones[1].Resolvers) != 0 {
		t.Fatalf("consumer zones = %+v", zones)
	}
	if !slices.Equal(consumer.Peers(), []node.ID{ids[7]}) {
		t.Fatalf("consumer peers = %v", consumer.Peers())
	}
	// Device 4: only lab.lan, through Device 8.
	if zones := networkPolicy.RoutesFor(ids[4], policyNow).DNSZones(); len(zones) != 1 ||
		!slices.Equal(zones[0].Resolvers, []DNSResolverRoute{{NodeID: ids[8], Port: 53}}) {
		t.Fatalf("Device 4 zones = %+v", zones)
	}
	// A resolver Device never gets its own zone, and keeps its consumers as
	// needed peers whatever its capabilities.
	resolver := networkPolicy.RoutesFor(ids[7], policyNow)
	if zones := resolver.DNSZones(); len(zones) != 1 || zones[0].Domain != "lab.lan" {
		t.Fatalf("resolver zones = %+v", zones)
	}
	if !slices.Equal(resolver.Peers(), sortedIDs(ids[1], ids[2], ids[3])) {
		t.Fatalf("resolver peers = %v", resolver.Peers())
	}
	stripped := resolver.ForCapabilities(RouteCapabilities{})
	if len(stripped.DNSZones()) != 0 || !slices.Equal(stripped.Peers(), sortedIDs(ids[1], ids[2], ids[3])) {
		t.Fatalf("resolver without dns.forward1 = %+v, peers %v", stripped.DNSZones(), stripped.Peers())
	}
	if kept := consumer.ForCapabilities(RouteCapabilities{}); !kept.IsEmpty() {
		t.Fatalf("zones without dns.forward1 = %+v", kept.DNSZones())
	}
	if !consumer.ForCapabilities(RouteCapabilities{DNSForward: true}).Equal(consumer) || consumer.Equal(resolver) ||
		!networkPolicy.Equal(fixture.policy(t)) {
		t.Fatal("DNS views or policies compare wrongly")
	}
	if peers := networkPolicy.RoutesFor(ids[8], policyNow).Peers(); !slices.Equal(peers, []node.ID{ids[4]}) {
		t.Fatalf("Device 8 peers = %v", peers)
	}
}

func TestRoutesForDNSZoneResolverStates(t *testing.T) {
	t.Parallel()
	ids := newDNSFixture(t).ids
	corp := func(t *testing.T, self int64, change func(*NetworkPolicyParams)) DNSZoneRoute {
		t.Helper()
		fixture := newDNSFixture(t)
		change(&fixture.params)
		for _, zone := range fixture.policy(t).RoutesFor(ids[self], policyNow).DNSZones() {
			if zone.Domain == "corp.internal" {
				return zone
			}
		}
		t.Fatal("corp.internal not sent")
		return DNSZoneRoute{}
	}
	internetOnly := []DNSResolverRoute{{Address: netip.MustParseAddr("1.1.1.1"), Port: 53}}
	for name, change := range map[string]func(*NetworkPolicyParams){
		"not eligible": func(params *NetworkPolicyParams) { params.DNSZones[1].Resolvers[0].Eligible = false },
		"gone": func(params *NetworkPolicyParams) {
			params.DNSZones[1].Resolvers[0].Device, params.DNSZones[1].Resolvers[0].Eligible = 0, false
		},
		"offline": func(params *NetworkPolicyParams) { params.Devices[6].ExpiresAt = policyNow },
		"exit node": func(params *NetworkPolicyParams) {
			params.ExitPools = []ExitPool{{Pool: 500, Ref: "p", Name: "P", ConntrackPerConsumer: 1}}
			params.ExitNodes = []ExitNode{{Pool: 500, Device: 7, NodeID: ids[7], Active: false}}
		},
		"other port": func(params *NetworkPolicyParams) { params.DNSZones[1].Resolvers[0].Port = 53 },
		"no release": func(params *NetworkPolicyParams) { params.ReleaseActive, params.Rules = false, nil },
	} {
		if zone := corp(t, 1, change); !slices.Equal(zone.Resolvers, internetOnly) {
			t.Errorf("%s: resolvers = %+v", name, zone.Resolvers)
		}
	}
	// The resolver's map holds 2 consumers: the third by Device order is
	// left out, and its resolver with it.
	capacity := func(params *NetworkPolicyParams) { params.RoutePeerLimit = 4 }
	if zone := corp(t, 3, capacity); !slices.Equal(zone.Resolvers, internetOnly) {
		t.Errorf("capacity: resolvers = %+v", zone.Resolvers)
	}
	if zone := corp(t, 2, capacity); len(zone.Resolvers) != 2 {
		t.Errorf("within capacity: resolvers = %+v", zone.Resolvers)
	}
	fixture := newDNSFixture(t)
	capacity(&fixture.params)
	if peers := fixture.policy(t).RoutesFor(ids[7], policyNow).Peers(); !slices.Equal(peers, sortedIDs(ids[1], ids[2])) {
		t.Errorf("capacity: resolver peers = %v", peers)
	}
}

// The root zone is computed like any zone and reaches only clients that
// apply it (dns.root1): for another, it goes with the resolver Devices only
// it uses (DNS design D1b §3.2).
func TestRoutesForRootZone(t *testing.T) {
	t.Parallel()
	fixture := newDNSFixture(t)
	fixture.params.DNSZones[0].Domain = "."
	view := fixture.policy(t).RoutesFor(fixture.ids[4], policyNow)
	zones := view.DNSZones()
	if len(zones) == 0 || zones[0].Domain != "." || len(zones[0].Resolvers) == 0 {
		t.Fatalf("root zone not computed: %+v", zones)
	}
	full := view.ForCapabilities(RouteCapabilities{DNSForward: true, DNSRecords: true, DNSRoot: true})
	if !slices.EqualFunc(full.DNSZones(), zones, equalDNSZoneRoute) || !slices.Equal(full.Peers(), view.Peers()) {
		t.Fatalf("with dns.root1: zones %+v, peers %v", full.DNSZones(), full.Peers())
	}
	without := view.ForCapabilities(RouteCapabilities{DNSForward: true, DNSRecords: true})
	var kept []node.ID
	for _, zone := range without.DNSZones() {
		if zone.Domain == "." {
			t.Fatalf("root zone sent without dns.root1: %+v", without.DNSZones())
		}
		for _, resolver := range zone.Resolvers {
			if resolver.NodeID.IsValid() {
				kept = append(kept, resolver.NodeID)
			}
		}
	}
	for _, resolver := range zones[0].Resolvers {
		if resolver.NodeID.IsValid() && !slices.Contains(kept, resolver.NodeID) &&
			slices.Contains(without.Peers(), resolver.NodeID) {
			t.Fatalf("a resolver Device only the root zone uses is still a peer: %v", without.Peers())
		}
	}
	if len(without.DNSZones()) != len(zones)-1 {
		t.Fatalf("without dns.root1: %+v", without.DNSZones())
	}
}

func TestNewNetworkPolicyRefusesInvalidDNSZones(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*NetworkPolicyParams){
		"root as a search domain": func(params *NetworkPolicyParams) {
			params.DNSZones[1].Domain = "."
		},
		"private address": func(params *NetworkPolicyParams) {
			params.DNSZones[1].Resolvers[1].Address = netip.MustParseAddr("10.0.0.2")
		},
		"low port":       func(params *NetworkPolicyParams) { params.DNSZones[0].Resolvers[0].Port = 80 },
		"internet port":  func(params *NetworkPolicyParams) { params.DNSZones[1].Resolvers[1].Port = 5353 },
		"duplicate zone": func(params *NetworkPolicyParams) { params.DNSZones[1].Zone = 901 },
		"twice":          func(params *NetworkPolicyParams) { params.DNSZones[1].Resolvers[1] = params.DNSZones[1].Resolvers[0] },
		"bad group":      func(params *NetworkPolicyParams) { params.DNSZones[1].Groups = []int64{0} },
		"eligible gone": func(params *NetworkPolicyParams) {
			params.DNSZones[0].Resolvers[0].Device = 0
		},
	} {
		fixture := newDNSFixture(t)
		change(&fixture.params)
		if _, err := NewNetworkPolicy(fixture.params); !errors.Is(err, ErrInvalidNetworkPolicy) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDNSViewForwardZones(t *testing.T) {
	t.Parallel()
	base := namedSnapshot(t)
	resolver, _ := node.ParseID("01890f00-0000-7000-8000-000000000709")
	missing, _ := node.ParseID("01890f00-0000-7000-8000-00000000070a")
	params := base.params()
	params.Routes = RouteView{dnsZones: []DNSZoneRoute{
		{Domain: "a.lan", SearchPosition: 3, Resolvers: []DNSResolverRoute{{NodeID: missing, Port: 53}}},
		{Domain: "corp.internal", FailOpen: true, SearchPosition: 1, Resolvers: []DNSResolverRoute{
			{NodeID: resolver, Port: 5335}, {Address: netip.MustParseAddr("1.1.1.1"), Port: 53}}},
		{Domain: "z.lan"},
	}, resolvers: []node.ID{resolver}}
	view, err := must(NewSnapshot(params)).DNSView(dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	zones := view.Zones()
	if len(zones) != 3 || len(zones[0].Resolvers) != 0 || !zones[1].FailOpen ||
		!slices.Equal(zones[1].Resolvers, []DNSResolver{{Address: netip.MustParseAddr("100.64.0.9"), Port: 5335},
			{Address: netip.MustParseAddr("1.1.1.1"), Port: 53}}) || zones[2].Domain != "z.lan" {
		t.Fatalf("zones = %+v", zones)
	}
	if search := view.SearchDomains(); !slices.Equal(search, []string{view.SearchDomain(), "corp.internal", "a.lan"}) {
		t.Fatalf("search domains = %v", search)
	}
}

// A resolver of one zone still consumes the zones it does not resolve, even
// from a Device that resolves another zone with it (both resolve
// corp.internal; only Device 8 resolves lab.lan). A zone whose resolvers the
// store dropped is sent, unavailable.
func TestRoutesForDNSZoneCoResolvers(t *testing.T) {
	t.Parallel()
	fixture := newDNSFixture(t)
	ids := fixture.ids
	fixture.params.DNSZones[1].Resolvers = append(fixture.params.DNSZones[1].Resolvers[:1],
		DNSZoneResolver{Device: 8, NodeID: ids[8], Eligible: true, Port: 53})
	fixture.params.Rules = append(fixture.params.Rules, NetworkPolicyRule{ID: policyRuleID(t, 4),
		SourceKind: SelectorDevice, SourceRef: 7, DestinationKind: SelectorDevice, DestinationRef: 8,
		Protocol: policy.ProtocolUDP, Ports: []policy.PortRange{must(policy.NewPortRange(53, 53))}})
	zones := fixture.policy(t).RoutesFor(ids[7], policyNow).DNSZones()
	if len(zones) != 1 || zones[0].Domain != "lab.lan" ||
		!slices.Equal(zones[0].Resolvers, []DNSResolverRoute{{NodeID: ids[8], Port: 53}}) {
		t.Fatalf("co-resolver zones = %+v", zones)
	}
	fixture = newDNSFixture(t)
	fixture.params.DNSZones[0].Resolvers = nil
	if zones := fixture.policy(t).RoutesFor(ids[4], policyNow).DNSZones(); len(zones) != 1 ||
		len(zones[0].Resolvers) != 0 {
		t.Fatalf("zone without resolvers = %+v", zones)
	}
}

// Resolver Devices share the routers' part of the peer limit: with room
// for one, Device 1 keeps corp.internal's resolver and loses lab.lan's.
func TestRoutesForDNSZoneResolversShareTheRouterBudget(t *testing.T) {
	t.Parallel()
	fixture := newDNSFixture(t)
	ids := fixture.ids
	fixture.params.RoutePeerLimit = 2 // one router, one consumer
	fixture.params.Rules = append(fixture.params.Rules, NetworkPolicyRule{ID: policyRuleID(t, 4),
		SourceKind: SelectorDeviceGroup, SourceRef: 10, DestinationKind: SelectorDevice, DestinationRef: 8,
		Protocol: policy.ProtocolUDP, Ports: []policy.PortRange{must(policy.NewPortRange(53, 53))}})
	view := fixture.policy(t).RoutesFor(ids[1], policyNow)
	zones := view.DNSZones()
	if len(zones) != 2 || len(zones[0].Resolvers) != 2 || len(zones[1].Resolvers) != 0 ||
		!slices.Equal(view.Peers(), []node.ID{ids[7]}) {
		t.Fatalf("zones = %+v, peers %v", zones, view.Peers())
	}
	// The resolver the router budget leaves out is counted (TD-CORE-76).
	if view.Omitted() != 1 {
		t.Fatalf("omitted = %d, want the resolver past the router budget", view.Omitted())
	}
}

// Zone writes refuse a resolver Device more consumers than its map keeps.
func TestDNSZoneConsumerLimitMatchesTheMapCut(t *testing.T) {
	t.Parallel()
	if dnszone.MaximumConsumersPerResolver != DefaultPeerLimit-min(MaximumRouteRouters, DefaultPeerLimit/2) {
		t.Fatalf("zone writes allow %d consumers per resolver, maps keep %d", dnszone.MaximumConsumersPerResolver,
			DefaultPeerLimit-min(MaximumRouteRouters, DefaultPeerLimit/2))
	}
}
