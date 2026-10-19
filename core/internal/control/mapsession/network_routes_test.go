package mapsession

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

func prefixes(texts ...string) []netip.Prefix {
	parsed := make([]netip.Prefix, len(texts))
	for index, text := range texts {
		parsed[index] = netip.MustParsePrefix(text)
	}
	return parsed
}

// routeFixture: Devices 1..6 live. Device group 10 = {1, 2, 3}; identity
// group 30 = {4 until policyNow+1h}. Site 100 "a-hq" = 10.20.0.0/16 and
// 2001:db8:20::/48, routed by Device 5 (priority 10, active, Workspace-owned,
// offering 10.0.0.0/8 and 2001:db8::/32). Site 200 "b-lab" = 10.30.0.0/16
// with only a draining router, Device 6. Rules: group 10 -> HQ 10.20.5.0/24
// (tcp/443); identity group 30 -> the whole HQ; Device 1 -> Lab.
type routeFixture struct {
	params NetworkPolicyParams
	ids    map[int64]node.ID
}

func newRouteFixture(t *testing.T) *routeFixture {
	t.Helper()
	ids := map[int64]node.ID{}
	devices := make([]PolicyDevice, 0, 6)
	for device := int64(1); device <= 6; device++ {
		ids[device] = policyNodeID(t, device)
		devices = append(devices, PolicyDevice{Device: device, NodeID: ids[device], ExpiresAt: policyNow.Add(24 * time.Hour)})
	}
	https, _ := policy.NewPortRange(443, 443)
	return &routeFixture{ids: ids, params: NetworkPolicyParams{
		Scope: snapshotFixture(t).Scope(), Revision: 4, ReleaseActive: true, Devices: devices,
		Members: []SelectorMember{
			{Kind: SelectorDeviceGroup, Selector: 10, Device: 1}, {Kind: SelectorDeviceGroup, Selector: 10, Device: 2},
			{Kind: SelectorDeviceGroup, Selector: 10, Device: 3},
			{Kind: SelectorIdentityGroup, Selector: 30, Device: 4, ValidUntil: policyNow.Add(time.Hour)},
		},
		RouteRevision: 7, RoutePeerLimit: 10_000,
		Sites: []RouteSite{
			{Site: 100, Ref: "a-hq", Prefixes: prefixes("10.20.0.0/16", "2001:db8:20::/48"), Masquerade: true,
				Probes: []RouteProbe{{Address: netip.MustParseAddr("10.20.0.1")}}},
			{Site: 200, Ref: "b-lab", Prefixes: prefixes("10.30.0.0/16")},
		},
		RouteRouters: []RouteRouter{
			{Site: 100, Device: 5, NodeID: ids[5], Priority: 10, Active: true, WorkspaceOwned: true,
				Offered: prefixes("10.0.0.0/8", "2001:db8::/32")},
			{Site: 200, Device: 6, NodeID: ids[6], Priority: 1, WorkspaceOwned: true, Offered: prefixes("10.30.0.0/16")},
		},
		RouteRules: []RouteRule{
			{ID: policyRuleID(t, 1), SourceKind: SelectorDeviceGroup, SourceRef: 10, Site: 100,
				Prefixes: prefixes("10.20.5.0/24"), Protocol: policy.ProtocolTCP, Ports: []policy.PortRange{https}},
			{ID: policyRuleID(t, 2), SourceKind: SelectorIdentityGroup, SourceRef: 30, Site: 100,
				Prefixes: prefixes("10.20.0.0/16", "2001:db8:20::/48"), Protocol: policy.ProtocolICMP},
			{ID: policyRuleID(t, 3), SourceKind: SelectorDevice, SourceRef: 1, Site: 200,
				Prefixes: prefixes("10.30.0.0/16"), Protocol: policy.ProtocolICMP},
		},
	}}
}

func (fixture *routeFixture) policy(t *testing.T) NetworkPolicy {
	t.Helper()
	networkPolicy, err := NewNetworkPolicy(fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	return networkPolicy
}

func TestRoutesForConsumersAndRouters(t *testing.T) {
	t.Parallel()
	fixture := newRouteFixture(t)
	ids := fixture.ids
	networkPolicy := fixture.policy(t)

	consumer := networkPolicy.RoutesFor(ids[1], policyNow)
	sites := consumer.Sites()
	if len(sites) != 2 || sites[0].Ref != "a-hq" || sites[1].Ref != "b-lab" {
		t.Fatalf("consumer Sites = %+v", sites)
	}
	hq := sites[0]
	if !slices.Equal(hq.Prefixes, prefixes("10.20.5.0/24")) || hq.Primary != ids[5] ||
		!slices.Equal(hq.Candidates, []node.ID{ids[5]}) || hq.Generation != 7 || hq.Status != RouteServed {
		t.Fatalf("HQ route = %+v", hq)
	}
	// A draining router is listed but never primary.
	if lab := sites[1]; lab.Primary.IsValid() || lab.Status != RouteUnserved || !slices.Equal(lab.Candidates, []node.ID{ids[6]}) {
		t.Fatalf("Lab route = %+v", lab)
	}
	if !slices.Contains(consumer.Peers(), ids[5]) || !slices.Contains(consumer.Peers(), ids[6]) {
		t.Fatalf("consumer route peers = %v", consumer.Peers())
	}

	// The whole Site for the Identity Group member, until its membership ends.
	if whole := networkPolicy.RoutesFor(ids[4], policyNow).Sites(); len(whole) != 1 ||
		!slices.Equal(whole[0].Prefixes, prefixes("10.20.0.0/16", "2001:db8:20::/48")) {
		t.Fatalf("whole-Site route = %+v", whole)
	}
	if later := networkPolicy.RoutesFor(ids[4], policyNow.Add(2*time.Hour)); !later.IsEmpty() {
		t.Fatalf("an ended membership still routes: %+v", later.Sites())
	}

	router := networkPolicy.RoutesFor(ids[5], policyNow)
	if len(router.Sites()) != 0 {
		t.Fatalf("a router got routes: %+v", router.Sites())
	}
	served := router.Served()
	if len(served) != 1 || served[0].Ref != "a-hq" || !served[0].Masquerade || len(served[0].Probes) != 1 ||
		!slices.Equal(served[0].Prefixes, prefixes("10.20.0.0/16", "2001:db8:20::/48")) {
		t.Fatalf("served = %+v", served)
	}
	inbound := router.Inbound()
	if len(inbound) != 2 {
		t.Fatalf("inbound = %+v", inbound)
	}
	for _, rule := range inbound {
		switch rule.Protocol {
		case policy.ProtocolTCP:
			if !slices.Equal(rule.Sources, sortedIDs(ids[1], ids[2], ids[3])) ||
				!slices.Equal(rule.Prefixes, prefixes("10.20.5.0/24")) {
				t.Fatalf("group inbound = %+v", rule)
			}
		case policy.ProtocolICMP:
			if !slices.Equal(rule.Sources, []node.ID{ids[4]}) {
				t.Fatalf("identity inbound = %+v", rule)
			}
		}
	}
	if !slices.Equal(router.Peers(), sortedIDs(ids[1], ids[2], ids[3], ids[4])) {
		t.Fatalf("router peers = %v", router.Peers())
	}
	// A draining router still serves its Site.
	if lab := networkPolicy.RoutesFor(ids[6], policyNow).Served(); len(lab) != 1 || lab[0].Ref != "b-lab" {
		t.Fatalf("draining router served = %+v", lab)
	}
	if networkPolicy.RoutesFor(ids[2], policyNow).Equal(consumer) || !networkPolicy.Equal(fixture.policy(t)) {
		t.Fatal("route views or policies compare wrongly")
	}
}

func TestRoutesForStatuses(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*routeFixture)
		want   RouteStatus
	}{
		{"offer does not cover the Site", func(f *routeFixture) {
			f.params.RouteRouters[0].Offered = prefixes("10.20.0.0/16")
		}, RouteUnserved},
		{"router not Workspace-owned", func(f *routeFixture) { f.params.RouteRouters[0].WorkspaceOwned = false }, RouteUnserved},
		{"router Device not live", func(f *routeFixture) {
			f.params.Devices = slices.DeleteFunc(f.params.Devices, func(device PolicyDevice) bool { return device.Device == 5 })
		}, RouteUnserved},
		{"overlapping Sites", func(f *routeFixture) { f.params.Sites[1].Prefixes = prefixes("10.20.0.0/16") }, RouteConflict},
		{"beyond the router's peer limit", func(f *routeFixture) { f.params.RoutePeerLimit = 2 }, RouteCapacity},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newRouteFixture(t)
			if test.name == "overlapping Sites" {
				fixture.params.RouteRules[2].SourceKind, fixture.params.RouteRules[2].SourceRef = SelectorDeviceGroup, 10
				fixture.params.RouteRules[2].Prefixes = prefixes("10.20.0.0/16")
			}
			test.change(fixture)
			sites := fixture.policy(t).RoutesFor(fixture.ids[2], policyNow).Sites()
			if len(sites) == 0 || sites[0].Status != test.want {
				t.Fatalf("status = %+v, want %d", sites, test.want)
			}
		})
	}
	// The cut keeps the first consumers in Device order on both sides.
	fixture := newRouteFixture(t)
	fixture.params.RoutePeerLimit = 2
	networkPolicy := fixture.policy(t)
	if first := networkPolicy.RoutesFor(fixture.ids[1], policyNow).Sites(); first[0].Status != RouteServed {
		t.Fatalf("the first consumer = %+v", first)
	}
	if peers := networkPolicy.RoutesFor(fixture.ids[5], policyNow).Peers(); !slices.Equal(peers, []node.ID{fixture.ids[1]}) {
		t.Fatalf("router peers within the limit = %v", peers)
	}
}

func TestRoutesForBoundsAndValidation(t *testing.T) {
	t.Parallel()
	fixture := newRouteFixture(t)
	fixture.params.RouteRevision = 0
	if _, err := NewNetworkPolicy(fixture.params); err == nil {
		t.Fatal("routes without a route revision were accepted")
	}
	// A Site that a router routes and a rule of its own grants is not a
	// route of that router.
	fixture = newRouteFixture(t)
	fixture.params.Members = append(fixture.params.Members, SelectorMember{Kind: SelectorDeviceGroup, Selector: 10, Device: 5})
	if sites := fixture.policy(t).RoutesFor(fixture.ids[5], policyNow).Sites(); len(sites) != 0 {
		t.Fatalf("a router routes to its own Site: %+v", sites)
	}
	// A rule of an unknown Site grants nothing.
	fixture = newRouteFixture(t)
	fixture.params.RouteRules[0].Site = 999
	if sites := fixture.policy(t).RoutesFor(fixture.ids[2], policyNow).Sites(); len(sites) != 0 {
		t.Fatalf("a rule of an unknown Site routes: %+v", sites)
	}
	// Prefixes beyond the bound are left out, whole Sites at a time.
	fixture = newRouteFixture(t)
	big := make([]netip.Prefix, 0, MaximumRoutePrefixes)
	for index := range MaximumRoutePrefixes {
		big = append(big, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 20, byte(index / 16), byte(index % 16 * 16)}), 28))
	}
	fixture.params.Sites[0].Prefixes = prefixes("10.20.0.0/16")
	fixture.params.RouteRules[2] = RouteRule{ID: policyRuleID(t, 3), SourceKind: SelectorDevice, SourceRef: 1, Site: 200,
		Prefixes: prefixes("10.30.0.0/16"), Protocol: policy.ProtocolICMP}
	fixture.params.RouteRules[0].Prefixes = big
	view := fixture.policy(t).RoutesFor(fixture.ids[1], policyNow)
	// HQ grants more prefixes than one Site may carry: it is left out.
	if sites := view.Sites(); len(sites) != 1 || sites[0].Ref != "b-lab" || view.Omitted() != 1 {
		t.Fatalf("bounded Sites = %+v, omitted %d", sites, view.Omitted())
	}
	// A router of two overlapping Sites serves the first by reference.
	fixture = newRouteFixture(t)
	fixture.params.Sites[1].Prefixes = prefixes("10.20.0.0/24")
	fixture.params.RouteRouters[1] = RouteRouter{Site: 200, Device: 5, NodeID: fixture.ids[5], Active: true,
		WorkspaceOwned: true, Offered: prefixes("10.0.0.0/8")}
	fixture.params.RouteRules = fixture.params.RouteRules[:2]
	router := fixture.policy(t).RoutesFor(fixture.ids[5], policyNow)
	if served := router.Served(); len(served) != 1 || served[0].Ref != "a-hq" || router.Omitted() != 1 {
		t.Fatalf("served overlapping Sites = %+v, omitted %d", served, router.Omitted())
	}
}

func TestRoutesForKeepsRoomForTheRoutersOfARouter(t *testing.T) {
	t.Parallel()
	// A peer limit of 4 keeps room for 2 routers: the router admits its
	// first 2 consumers, and the third finds itself beyond them.
	fixture := newRouteFixture(t)
	fixture.params.RoutePeerLimit = 4
	networkPolicy := fixture.policy(t)
	if peers := networkPolicy.RoutesFor(fixture.ids[5], policyNow).Peers(); !slices.Equal(peers,
		sortedIDs(fixture.ids[1], fixture.ids[2])) {
		t.Fatalf("router peers = %v", peers)
	}
	if third := networkPolicy.RoutesFor(fixture.ids[3], policyNow).Sites(); third[0].Status != RouteCapacity {
		t.Fatalf("the third consumer = %+v", third)
	}
	// With a peer limit of 2 a map reaches 1 router: the second Site is left
	// out rather than its router cut from the map.
	fixture = newRouteFixture(t)
	fixture.params.RoutePeerLimit = 2
	if view := fixture.policy(t).RoutesFor(fixture.ids[1], policyNow); len(view.Sites()) != 1 || view.Omitted() != 1 {
		t.Fatalf("routes within 1 router = %+v, omitted %d", view.Sites(), view.Omitted())
	}
	// A co-router of the Site is never one of its consumers.
	fixture = newRouteFixture(t)
	fixture.params.RouteRouters = append(fixture.params.RouteRouters, RouteRouter{Site: 100, Device: 2,
		NodeID: fixture.ids[2], Priority: 20, Active: true, WorkspaceOwned: true, Offered: prefixes("10.0.0.0/8")})
	if peers := fixture.policy(t).RoutesFor(fixture.ids[5], policyNow).Peers(); slices.Contains(peers, fixture.ids[2]) {
		t.Fatalf("a co-router is a consumer: %v", peers)
	}
}

func sortedIDs(ids ...node.ID) []node.ID {
	sorted := slices.Clone(ids)
	slices.SortFunc(sorted, compareNodeIDs)
	return sorted
}
