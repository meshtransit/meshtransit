package mapsession

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

// exitFixture: Devices 1..8 live. Device group 10 = {1, 2, 3}. Pool 500
// "p-main" with exit nodes 7 (priority 1) and 8 (priority 2), both active,
// Workspace-owned and offering; nobody elected yet. Rules: group 10 ->
// pool over TCP 443; Device 4 -> pool over ICMP; Device 7 -> pool (its own).
type exitFixture struct {
	params NetworkPolicyParams
	ids    map[int64]node.ID
}

func newExitFixture(t *testing.T) *exitFixture {
	t.Helper()
	ids := map[int64]node.ID{}
	devices := make([]PolicyDevice, 0, 8)
	for device := int64(1); device <= 8; device++ {
		ids[device] = policyNodeID(t, device)
		devices = append(devices, PolicyDevice{Device: device, NodeID: ids[device], ExpiresAt: policyNow.Add(24 * time.Hour)})
	}
	https, _ := policy.NewPortRange(443, 443)
	return &exitFixture{ids: ids, params: NetworkPolicyParams{
		Scope: snapshotFixture(t).Scope(), Revision: 4, ReleaseActive: true, Devices: devices,
		Members: []SelectorMember{
			{Kind: SelectorDeviceGroup, Selector: 10, Device: 1}, {Kind: SelectorDeviceGroup, Selector: 10, Device: 2},
			{Kind: SelectorDeviceGroup, Selector: 10, Device: 3},
		},
		RouteRevision: 9, RoutePeerLimit: 10_000,
		ExitPools: []ExitPool{{Pool: 500, Ref: "p-main", Name: "Main", ConntrackPerConsumer: 4096,
			DNSUpstreams: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
			Probes:       []ExitProbe{{Address: netip.MustParseAddr("9.9.9.9"), Port: 443}}}},
		ExitNodes: []ExitNode{
			{Pool: 500, Device: 8, NodeID: ids[8], Priority: 2, Active: true, WorkspaceOwned: true, Offered: true},
			{Pool: 500, Device: 7, NodeID: ids[7], Priority: 1, Active: true, WorkspaceOwned: true, Offered: true},
		},
		ExitRules: []ExitRule{
			{ID: policyRuleID(t, 1), SourceKind: SelectorDeviceGroup, SourceRef: 10, Pool: 500,
				Protocol: policy.ProtocolTCP, Ports: []policy.PortRange{https}},
			{ID: policyRuleID(t, 2), SourceKind: SelectorDevice, SourceRef: 4, Pool: 500, Protocol: policy.ProtocolICMP},
			{ID: policyRuleID(t, 3), SourceKind: SelectorDevice, SourceRef: 7, Pool: 500, Protocol: policy.ProtocolICMP},
		},
	}}
}

func (fixture *exitFixture) policy(t *testing.T) NetworkPolicy {
	t.Helper()
	networkPolicy, err := NewNetworkPolicy(fixture.params)
	if err != nil {
		t.Fatal(err)
	}
	return networkPolicy
}

func TestRoutesForExitConsumersAndExitNodes(t *testing.T) {
	t.Parallel()
	fixture := newExitFixture(t)
	ids := fixture.ids
	networkPolicy := fixture.policy(t)

	consumer := networkPolicy.RoutesFor(ids[1], policyNow)
	pools := consumer.Exits()
	if len(pools) != 1 || pools[0].Ref != "p-main" || pools[0].Name != "Main" || pools[0].Primary != ids[7] ||
		!slices.Equal(pools[0].Candidates, []node.ID{ids[7], ids[8]}) || pools[0].Generation != 9 ||
		pools[0].Status != RouteServed {
		t.Fatalf("consumer pools = %+v", pools)
	}
	if !slices.Equal(consumer.Peers(), sortedIDs(ids[7], ids[8])) || len(consumer.Sites()) != 0 {
		t.Fatalf("consumer peers = %v", consumer.Peers())
	}
	if none := networkPolicy.RoutesFor(ids[5], policyNow); !none.IsEmpty() {
		t.Fatalf("a Device without a rule got %+v", none.Exits())
	}

	// An exit node never gets its own pool, and serves it.
	exitNode := networkPolicy.RoutesFor(ids[7], policyNow)
	if len(exitNode.Exits()) != 0 {
		t.Fatalf("an exit node got its own pool: %+v", exitNode.Exits())
	}
	served := exitNode.ServedExits()
	if len(served) != 1 || served[0].Ref != "p-main" || served[0].ConntrackPerConsumer != 4096 ||
		served[0].SMTPAllowed || len(served[0].Probes) != 1 || len(served[0].DNSUpstreams) != 1 {
		t.Fatalf("served exits = %+v", served)
	}
	inbound := exitNode.ExitInbound()
	if len(inbound) != 2 {
		t.Fatalf("exit inbound = %+v", inbound)
	}
	for _, rule := range inbound {
		switch rule.Protocol {
		case policy.ProtocolTCP:
			if !slices.Equal(rule.Sources, sortedIDs(ids[1], ids[2], ids[3])) || len(rule.Ports) != 1 {
				t.Fatalf("group inbound = %+v", rule)
			}
		case policy.ProtocolICMP:
			if !slices.Equal(rule.Sources, []node.ID{ids[4]}) {
				t.Fatalf("Device inbound = %+v", rule)
			}
		}
	}
	if !slices.Equal(exitNode.Peers(), sortedIDs(ids[1], ids[2], ids[3], ids[4])) {
		t.Fatalf("exit node peers = %v", exitNode.Peers())
	}
	// Every exit node of the pool serves, not only the primary.
	if standby := networkPolicy.RoutesFor(ids[8], policyNow).ServedExits(); len(standby) != 1 {
		t.Fatalf("standby served = %+v", standby)
	}

	// Capabilities: without routes.exit.v1 no pool and none of its peers;
	// without router.exit.v1 nothing served.
	if kept := consumer.ForCapabilities(RouteCapabilities{ExitRouter: true}); !kept.IsEmpty() {
		t.Fatalf("pools without routes.exit.v1 = %+v", kept.Exits())
	}
	if kept := exitNode.ForCapabilities(RouteCapabilities{Exits: true}); !kept.IsEmpty() {
		t.Fatalf("served exits without router.exit.v1 = %+v", kept.ServedExits())
	}
	if !consumer.ForCapabilities(RouteCapabilities{Exits: true}).Equal(consumer) ||
		consumer.Equal(exitNode) || !networkPolicy.Equal(fixture.policy(t)) {
		t.Fatal("exit views or policies compare wrongly")
	}
}

func TestRoutesForExitStatuses(t *testing.T) {
	t.Parallel()
	ids := newExitFixture(t).ids
	primary := func(t *testing.T, change func(*NetworkPolicyParams)) ExitPoolRoute {
		t.Helper()
		fixture := newExitFixture(t)
		change(&fixture.params)
		pools := fixture.policy(t).RoutesFor(ids[1], policyNow).Exits()
		if len(pools) != 1 {
			t.Fatalf("pools = %+v", pools)
		}
		return pools[0]
	}
	nodeOf := func(params *NetworkPolicyParams, device int64) *ExitNode {
		index := slices.IndexFunc(params.ExitNodes, func(exitNode ExitNode) bool { return exitNode.Device == device })
		return &params.ExitNodes[index]
	}
	// The first exit node does not offer: still the primary before any
	// election, but it cannot serve.
	if route := primary(t, func(params *NetworkPolicyParams) { nodeOf(params, 7).Offered = false }); route.Primary != ids[7] ||
		route.Status != RouteUnserved {
		t.Fatalf("unoffered primary = %+v", route)
	}
	if route := primary(t, func(params *NetworkPolicyParams) { nodeOf(params, 7).WorkspaceOwned = false }); route.Status != RouteUnserved {
		t.Fatalf("personal primary = %+v", route)
	}
	// Core's election decides; none means unserved.
	if route := primary(t, func(params *NetworkPolicyParams) {
		params.ExitPools[0].Elected, params.ExitPools[0].Primary = true, 8
	}); route.Primary != ids[8] || route.Status != RouteServed {
		t.Fatalf("elected primary = %+v", route)
	}
	if route := primary(t, func(params *NetworkPolicyParams) { params.ExitPools[0].Elected = true }); route.Primary.IsValid() ||
		route.Status != RouteUnserved {
		t.Fatalf("no elected primary = %+v", route)
	}
	// An elected Device that is no longer an active exit node of the pool is
	// no primary: the first active exit node is, until the next election.
	if route := primary(t, func(params *NetworkPolicyParams) {
		params.ExitPools[0].Elected, params.ExitPools[0].Primary = true, 6
	}); route.Primary != ids[7] {
		t.Fatalf("stale elected primary = %+v", route)
	}
	if route := primary(t, func(params *NetworkPolicyParams) {
		nodeOf(params, 7).Active = false
	}); route.Primary != ids[8] || !slices.Equal(route.Candidates, []node.ID{ids[7], ids[8]}) {
		t.Fatalf("draining first exit node = %+v", route)
	}
	// A pool whose exit nodes are all gone cannot be sent.
	fixture := newExitFixture(t)
	fixture.params.ExitNodes = nil
	if consumer := fixture.policy(t).RoutesFor(ids[1], policyNow); len(consumer.Exits()) != 0 ||
		consumer.Omitted() != 0 {
		t.Fatalf("a pool without exit nodes = %+v", consumer.Exits())
	}
}

func TestRoutesForExitCapacityAndValidation(t *testing.T) {
	t.Parallel()
	fixture := newExitFixture(t)
	ids := fixture.ids
	// A peer limit of 4 keeps 2 consumers per exit node: 1 and 2 of the
	// pool's sorted consumers {1, 2, 3, 4}.
	fixture.params.RoutePeerLimit = 4
	networkPolicy := fixture.policy(t)
	if pools := networkPolicy.RoutesFor(ids[2], policyNow).Exits(); len(pools) != 1 || pools[0].Status != RouteServed {
		t.Fatalf("a consumer within the limit = %+v", pools)
	}
	if pools := networkPolicy.RoutesFor(ids[3], policyNow).Exits(); len(pools) != 1 || pools[0].Status != RouteCapacity {
		t.Fatalf("a consumer past the limit = %+v", pools)
	}
	if peers := networkPolicy.RoutesFor(ids[7], policyNow).Peers(); !slices.Equal(peers, sortedIDs(ids[1], ids[2])) {
		t.Fatalf("exit node peers past the limit = %v", peers)
	}

	invalid := map[string]func(*NetworkPolicyParams){
		"one Device in two pools": func(params *NetworkPolicyParams) {
			params.ExitPools = append(params.ExitPools, ExitPool{Pool: 600, Ref: "q", Name: "Q",
				ConntrackPerConsumer: 1024})
			params.ExitNodes = append(params.ExitNodes, ExitNode{Pool: 600, Device: 7, NodeID: ids[7], Active: true})
		},
		"a duplicate pool": func(params *NetworkPolicyParams) {
			params.ExitPools = append(params.ExitPools, params.ExitPools[0])
		},
		"a primary before any election": func(params *NetworkPolicyParams) { params.ExitPools[0].Primary = 7 },
		"exit rules without a release":  func(params *NetworkPolicyParams) { params.ReleaseActive = false },
		"too many pools": func(params *NetworkPolicyParams) {
			for pool := int64(1); pool <= MaximumExitPools; pool++ {
				params.ExitPools = append(params.ExitPools, ExitPool{Pool: 1000 + pool, Ref: "x", Name: "X",
					ConntrackPerConsumer: 1024})
			}
		},
	}
	for name, change := range invalid {
		broken := newExitFixture(t)
		change(&broken.params)
		if _, err := NewNetworkPolicy(broken.params); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A Device that routes a Site and serves a pool cuts both sets of consumers
// at one place, so neither side ever drops a peer the other needs.
func TestRoutesForRouterAndExitNodeShareConsumers(t *testing.T) {
	t.Parallel()
	fixture := newExitFixture(t)
	ids := fixture.ids
	fixture.params.Sites = []RouteSite{{Site: 100, Ref: "a-hq", Prefixes: prefixes("10.20.0.0/16")}}
	fixture.params.RouteRouters = []RouteRouter{{Site: 100, Device: 7, NodeID: ids[7], Priority: 1, Active: true,
		WorkspaceOwned: true, Offered: prefixes("10.20.0.0/16")}}
	fixture.params.RouteRules = []RouteRule{{ID: policyRuleID(t, 9), SourceKind: SelectorDevice, SourceRef: 5,
		Site: 100, Prefixes: prefixes("10.20.0.0/16"), Protocol: policy.ProtocolICMP}}
	networkPolicy := fixture.policy(t)
	view := networkPolicy.RoutesFor(ids[7], policyNow)
	if len(view.Served()) != 1 || len(view.ServedExits()) != 1 ||
		!slices.Equal(view.Peers(), sortedIDs(ids[1], ids[2], ids[3], ids[4], ids[5])) {
		t.Fatalf("router and exit node = %+v / %+v, peers %v", view.Served(), view.ServedExits(), view.Peers())
	}
	// Device 5 reaches the Site through 7 and the pool's other exit node
	// is no Site router: it uses neither as a consumer of the pool.
	if consumer := networkPolicy.RoutesFor(ids[5], policyNow); len(consumer.Sites()) != 1 || len(consumer.Exits()) != 0 {
		t.Fatalf("Site consumer = %+v / %+v", consumer.Sites(), consumer.Exits())
	}
}

// An exit node gets the Internet resolvers of the Network's zones as the
// only resolvers its forwarder relays to, each once, in address order; a
// change of them is a change of what it serves (DNS design D1c §4.1).
func TestServedExitCarriesDNSRelayTargets(t *testing.T) {
	t.Parallel()
	fixture := newExitFixture(t)
	fixture.params.DNSZones = []DNSZone{
		{Zone: 901, Domain: "corp.example", OtherNames: DNSOtherForward, Resolvers: []DNSZoneResolver{
			{Address: netip.MustParseAddr("9.9.9.9"), Port: 53},
			{Address: netip.MustParseAddr("8.8.8.8"), Port: 53},
		}},
		{Zone: 902, Domain: "lab.example", OtherNames: DNSOtherForward, FailOpen: true, Resolvers: []DNSZoneResolver{
			{Address: netip.MustParseAddr("2606:4700:4700::1111"), Port: 53},
			{Address: netip.MustParseAddr("9.9.9.9"), Port: 53},
			{Device: 3, NodeID: fixture.ids[3], Eligible: true, Port: 53},
		}},
	}
	served := fixture.policy(t).RoutesFor(fixture.ids[7], policyNow).ServedExits()
	want := []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9"),
		netip.MustParseAddr("2606:4700:4700::1111")}
	if len(served) != 1 || !slices.Equal(served[0].DNSRelayTargets, want) {
		t.Fatalf("relay targets = %+v", served)
	}
	changed := served[0]
	changed.DNSRelayTargets = want[:2]
	if equalServedExit(served[0], changed) {
		t.Fatal("a change of relay targets is no change of what the exit node serves")
	}
	consumer := fixture.policy(t).RoutesFor(fixture.ids[1], policyNow)
	if len(consumer.ServedExits()) != 0 {
		t.Fatalf("a consumer got relay targets: %+v", consumer.ServedExits())
	}
}

func TestRelayTargetsAreBounded(t *testing.T) {
	t.Parallel()
	addresses := make([]netip.Addr, 0, MaximumDNSRelayTargets+10)
	for index := range MaximumDNSRelayTargets + 10 {
		addresses = append(addresses, netip.AddrFrom4([4]byte{1, 0, byte(index >> 8), byte(index)}))
	}
	addresses = append(addresses, addresses[0])
	targets, dropped := relayTargets(addresses)
	if len(targets) != MaximumDNSRelayTargets || dropped != 10 || targets[0] != netip.MustParseAddr("1.0.0.0") ||
		!slices.IsSortedFunc(targets, func(first, second netip.Addr) int { return first.Compare(second) }) {
		t.Fatalf("%d targets, %d dropped", len(targets), dropped)
	}
}
