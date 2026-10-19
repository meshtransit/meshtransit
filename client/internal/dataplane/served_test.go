package dataplane

import (
	"context"
	"encoding/binary"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/packetmeta"
	"meshtransit.net/client/internal/routesettings"
	"meshtransit.net/shared/routedigest"
)

// testRouterSnapshot is the policy test map seen from a router: the peer
// 100.64.0.4 may reach TCP 443 in the Site 10.35.0.0/17 through it.
func testRouterSnapshot() networkmap.Snapshot {
	snapshot := testPolicySnapshot()
	site := netip.MustParsePrefix("10.35.0.0/17")
	snapshot.Policy = []networkmap.Rule{{
		Sources: []networkmap.Selector{{Kind: networkmap.SelectorPrefix, Prefix: netip.MustParsePrefix("100.64.0.4/32")}},
		Destinations: []networkmap.Destination{{
			Selector: networkmap.Selector{Kind: networkmap.SelectorPrefix, Prefix: site},
			PortFrom: 443, PortTo: 443,
		}},
		Protocols: []uint8{packetmeta.ProtocolTCP},
	}}
	snapshot.Served = []networkmap.ServedSite{{Ref: "prod", Prefixes: []netip.Prefix{site}, Masquerade: true}}
	return snapshot
}

func TestPolicyFilterForwardsIntoServedSitesAsRulesAllow(t *testing.T) {
	t.Parallel()
	filter := newPolicyFilter()
	filter.UpdateNetwork(testRouterSnapshot())
	peer, target, router := [4]byte{100, 64, 0, 4}, [4]byte{10, 35, 0, 4}, [4]byte{10, 35, 0, 2}
	toTarget := testIPv4TransportPacket(peer, target, 40000, 443, packetmeta.ProtocolTCP, 0x02)
	if filter.Allow(PacketInbound, toTarget) {
		t.Fatal("a Site was reached before the helper forwarded into it")
	}
	entries := []routedigest.Entry{{SiteRef: "prod", Prefix: netip.MustParsePrefix("10.35.0.0/17"), Masquerade: true}}
	filter.SetServedInstalled(entries, []netip.Addr{netip.AddrFrom4(router)})
	if !filter.Allow(PacketInbound, toTarget) {
		t.Fatal("an allowed packet into the Site was denied")
	}
	if filter.Allow(PacketInbound, testIPv4TransportPacket(peer, target, 40000, 22, packetmeta.ProtocolTCP, 0x02)) {
		t.Fatal("a port the rules do not allow was forwarded")
	}
	if filter.Allow(PacketInbound, testIPv4TransportPacket(peer, router, 40000, 443, packetmeta.ProtocolTCP, 0x02)) {
		t.Fatal("the router's own LAN address was reached through the Site")
	}
	if filter.Allow(PacketInbound, testIPv4TransportPacket(peer, [4]byte{10, 99, 0, 1}, 40000, 443, packetmeta.ProtocolTCP, 0x02)) {
		t.Fatal("the router forwarded outside its Sites like an exit node")
	}
	// The Site answers the peer; it never speaks for another range.
	if !filter.Allow(PacketOutbound, reverseTestPacket(toTarget)) {
		t.Fatal("the Site's answer was denied")
	}
	if filter.Allow(PacketOutbound, testIPv4TransportPacket([4]byte{10, 99, 0, 1}, peer, 443, 40000, packetmeta.ProtocolTCP, 0x12)) {
		t.Fatal("a source outside the Site reached the mesh")
	}
	enforced, _ := filter.Enforced()
	want, count, err := routedigest.Compute(entries)
	if err != nil || enforced.RouteDigest != want || enforced.RouteEntries != count {
		t.Fatalf("route digest = %v/%d, want %v/%d", enforced.RouteDigest, enforced.RouteEntries, want, count)
	}
}

// fragmentationNeeded is what a router on the path answers a packet too big
// for the next hop.
func fragmentationNeeded(from, to [4]byte, original []byte) []byte {
	packet := make([]byte, 28+28)
	packet[0], packet[8], packet[9] = 0x45, 64, packetmeta.ProtocolICMPv4
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet))) //nolint:gosec // G115: test packets are small
	copy(packet[12:16], from[:])
	copy(packet[16:20], to[:])
	packet[20], packet[21] = 3, 4
	copy(packet[28:], original[:28])
	return packet
}

func TestPolicyFilterAdmitsErrorsAboutTrackedFlows(t *testing.T) {
	t.Parallel()
	filter := newPolicyFilter()
	filter.UpdateNetwork(testRoutedSnapshot())
	filter.SetRoutedInstalled([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
	self, site := [4]byte{100, 64, 0, 3}, [4]byte{10, 20, 0, 5}
	flow := testIPv4TransportPacket(self, site, 40000, 443, packetmeta.ProtocolTCP, 0x02)
	other := testIPv4TransportPacket(self, site, 40001, 443, packetmeta.ProtocolTCP, 0x10)
	// Path MTU discovery: the error comes from inside the Site.
	tooBig := fragmentationNeeded([4]byte{10, 20, 0, 1}, self, flow)
	if filter.Allow(PacketInbound, tooBig) {
		t.Fatal("an error about no flow was admitted")
	}
	if !filter.Allow(PacketOutbound, flow) {
		t.Fatal("the flow was denied")
	}
	if !filter.Allow(PacketInbound, tooBig) {
		t.Fatal("fragmentation needed for a tracked flow was dropped")
	}
	if filter.Allow(PacketInbound, fragmentationNeeded([4]byte{10, 20, 0, 1}, self, other)) {
		t.Fatal("an error about an untracked flow was admitted")
	}
	if filter.Allow(PacketInbound, fragmentationNeeded([4]byte{192, 168, 9, 9}, self, flow)) {
		t.Fatal("an error from outside the mesh's paths was admitted")
	}
}

type servedTUNOpener struct {
	wireGuardTUNOpener
	mu       sync.Mutex
	requests [][]netip.Prefix
	plain    [][]netip.Prefix
	refuse   map[netip.Prefix]string
	err      error
}

func (o *servedTUNOpener) SetServedRoutes(_ context.Context, served, unmasqueraded []netip.Prefix) (netadmin.ServedResult, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.requests, o.plain = append(o.requests, slices.Clone(served)), append(o.plain, slices.Clone(unmasqueraded))
	if o.err != nil {
		return netadmin.ServedResult{}, o.err
	}
	result := netadmin.ServedResult{Installed: []netip.Prefix{}}
	for _, prefix := range served {
		if reason, refused := o.refuse[prefix]; refused {
			result.Refused = append(result.Refused, routesettings.Refusal{Prefix: prefix, Reason: reason})
			result.RefusedTotal++
			continue
		}
		result.Installed = append(result.Installed, prefix)
	}
	return result, nil
}

func (o *servedTUNOpener) sent() ([][]netip.Prefix, [][]netip.Prefix) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.requests), slices.Clone(o.plain)
}

func TestWireGuardEngineForwardsIntoServedSitesThroughTheHelper(t *testing.T) {
	t.Parallel()
	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Served = []networkmap.ServedSite{
		{Ref: "lab", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.36.0.0/24")}},
		{Ref: "prod", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.35.0.0/17")}, Masquerade: true},
	}
	opener := &servedTUNOpener{refuse: map[netip.Prefix]string{
		netip.MustParsePrefix("10.36.0.0/24"): routesettings.ReasonNotAdvertised,
	}}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: &fakeWireGuardDevice{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	changes := engine.EnforcementChanges()
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the served routes", func() bool { return engine.SubnetRouter().Requested == 2 })
	requests, plain := opener.sent()
	if len(requests) != 1 || len(requests[0]) != 2 || !slices.Equal(plain[0], []netip.Prefix{netip.MustParsePrefix("10.36.0.0/24")}) {
		t.Fatalf("requests = %v, unmasqueraded = %v", requests, plain)
	}
	status := engine.SubnetRouter()
	if status.Sites != 2 || status.Served != 1 || status.RefusedTotal != 1 || !status.NotAdvertised || status.Error != "" {
		t.Fatalf("SubnetRouter() = %+v", status)
	}
	select {
	case <-changes:
	case <-time.After(time.Second):
		t.Fatal("the new route digest was not signalled")
	}
	enforced, _ := engine.filter.Enforced()
	want, _, _ := routedigest.Compute([]routedigest.Entry{{SiteRef: "prod", Prefix: netip.MustParsePrefix("10.35.0.0/17"), Masquerade: true}})
	if enforced.RouteDigest != want || enforced.RouteEntries != 1 {
		t.Fatalf("route digest = %v/%d", enforced.RouteDigest, enforced.RouteEntries)
	}
	// Served Sites gone stop the forwarding.
	snapshot.Revision++
	snapshot.Served = nil
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "forwarding to stop", func() bool { return engine.SubnetRouter().Sites == 0 })
	if requests, _ := opener.sent(); len(requests) != 2 || len(requests[1]) != 0 {
		t.Fatalf("requests = %v", requests)
	}
	empty, _, _ := routedigest.Compute(nil)
	if enforced, _ := engine.filter.Enforced(); enforced.RouteDigest != empty {
		t.Fatal("the route digest still covers removed Sites")
	}
}

func TestServedEntriesNameTheSiteOfEachPart(t *testing.T) {
	t.Parallel()
	sites := []networkmap.ServedSite{
		{Ref: "lab", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.40.0.0/16")}},
		{Ref: "prod", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.35.0.0/17")}, Masquerade: true},
	}
	got := servedEntries(sites, []netip.Prefix{netip.MustParsePrefix("10.35.0.0/17"), netip.MustParsePrefix("10.40.2.0/24")})
	want := []routedigest.Entry{
		{SiteRef: "prod", Prefix: netip.MustParsePrefix("10.35.0.0/17"), Masquerade: true},
		{SiteRef: "lab", Prefix: netip.MustParsePrefix("10.40.2.0/24")},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("servedEntries() = %v, want %v", got, want)
	}
}

// checkingTUNOpener also answers the router health check.
type checkingTUNOpener struct {
	servedTUNOpener
	problems []string
}

func (o *checkingTUNOpener) CheckServedRoutes(context.Context) (netadmin.ServedHealth, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	health := netadmin.ServedHealth{Problems: slices.Clone(o.problems)}
	if len(o.requests) != 0 {
		health.Installed = slices.Clone(o.requests[len(o.requests)-1])
	}
	return health, nil
}

func TestWireGuardEngineMeasuresServedSites(t *testing.T) {
	t.Parallel()
	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Served = []networkmap.ServedSite{
		{Ref: "prod", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.35.0.0/17")}, Masquerade: true},
	}
	opener := &checkingTUNOpener{problems: []string{netadmin.ProblemForwardingOff}}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: &fakeWireGuardDevice{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Site's health", func() bool {
		health := engine.SubnetRouter().Health
		return len(health) == 1 && health[0] == SiteHealth{Ref: "prod", State: SiteHealthFailed, Code: SiteCodeForwardingOff}
	})
	snapshot.Revision++
	snapshot.Served = nil
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the health to clear", func() bool { return len(engine.SubnetRouter().Health) == 0 })
}
