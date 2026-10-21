package dataplane

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/packetmeta"
	"meshtransit.net/client/internal/underlay"
)

// withExitRoute gives snapshot a pool whose only candidate is its first
// peer, and the local choice to use it.
func withExitRoute(snapshot networkmap.Snapshot, ipv6 bool) networkmap.Snapshot {
	snapshot.Peers[0].StableID = "exit"
	snapshot.Exits = []networkmap.ExitPool{{
		Ref: "pool", Name: "Pool", Primary: "exit", Status: networkmap.ExitServed,
		Candidates: []networkmap.ExitCandidate{{DeviceID: "exit", State: networkmap.ExitStateOK, IPv4: true, IPv6: ipv6}},
	}}
	snapshot.ExitRoute = &networkmap.ExitRoute{Pool: "pool", Node: "exit", IPv6: ipv6}
	return snapshot
}

func TestBuildWireGuardPlanGivesTheExitNodeTheDefaultRoutes(t *testing.T) {
	t.Parallel()
	for _, ipv6 := range []bool{false, true} {
		privateKey, snapshot := testWireGuardSnapshot(t)
		plan, err := buildWireGuardPlan(withExitRoute(snapshot, ipv6), privateKey, 41641)
		if err != nil {
			t.Fatal(err)
		}
		want := []netip.Prefix{netip.MustParsePrefix("100.64.0.4/32"), netip.MustParsePrefix("0.0.0.0/0")}
		if ipv6 {
			want = append(want, netip.MustParsePrefix("::/0"))
		}
		if len(plan.peers) != 1 || !slices.Equal(plan.peers[0].allowedIPs, want) {
			t.Fatalf("ipv6 %t: allowed IPs = %v, want %v", ipv6, plan.peers[0].allowedIPs, want)
		}
		// The helper's exit table sends the Internet into the TUN; its own
		// routes stay the overlay's.
		if !slices.Equal(plan.routes, []netip.Prefix{netip.MustParsePrefix("100.64.0.4/32")}) {
			t.Fatalf("tun routes = %v", plan.routes)
		}
		plan.clearSecrets()
	}
	// No exit node available: nobody holds a default route.
	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot = withExitRoute(snapshot, true)
	snapshot.ExitRoute.Node = ""
	plan, err := buildWireGuardPlan(snapshot, privateKey, 41641)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.clearSecrets()
	if len(plan.peers[0].allowedIPs) != 1 {
		t.Fatalf("allowed IPs without an exit node = %v", plan.peers[0].allowedIPs)
	}
}

func TestPolicyFilterSendsOnlyTheInternetThroughTheExitNode(t *testing.T) {
	t.Parallel()
	filter := newPolicyFilter()
	filter.UpdateNetwork(withExitRoute(testPolicySnapshot(), false))
	self := [4]byte{100, 64, 0, 3}
	out := testIPv4TransportPacket(self, [4]byte{8, 8, 8, 8}, 40000, 443, packetmeta.ProtocolTCP, 0x02)
	reply := reverseTestPacket(out)
	reply[33] = 0x12
	if filter.Allow(PacketOutbound, out) {
		t.Fatal("the Internet was reached before the helper routed it into the mesh")
	}
	filter.SetExitRouted(true)
	if !filter.Allow(PacketOutbound, out) || !filter.Allow(PacketInbound, reply) {
		t.Fatal("the Internet was not reachable through the exit node")
	}
	// The Internet never opens a flow to this node through the exit node.
	opening := testIPv4TransportPacket([4]byte{1, 1, 1, 1}, self, 443, 18080, packetmeta.ProtocolTCP, 0x02)
	if filter.Allow(PacketInbound, opening) {
		t.Fatal("an Internet host opened a flow through the exit node")
	}
	// Nor is anything but the Internet reached or accepted through it: a
	// LAN, metadata or shared address is no exit node's.
	for _, private := range [][4]byte{{10, 1, 2, 3}, {169, 254, 169, 254}, {100, 70, 0, 9}} {
		packet := testIPv4TransportPacket(self, private, 40001, 443, packetmeta.ProtocolTCP, 0x02)
		if filter.Allow(PacketOutbound, packet) {
			t.Fatalf("%v was reached through the exit node", private)
		}
		answer := reverseTestPacket(packet)
		answer[33] = 0x12
		if filter.Allow(PacketInbound, answer) {
			t.Fatalf("a packet from %v was accepted from the exit node", private)
		}
	}
	// Once the helper stops routing the Internet, its flows end.
	filter.SetExitRouted(false)
	if filter.Allow(PacketInbound, reply) {
		t.Fatal("a flow outlived the exit route")
	}
}

// exitRouteOpener records the exit routes asked of the helper.
type exitRouteOpener struct {
	wireGuardTUNOpener
	mu       sync.Mutex
	requests []netadmin.ExitRouteRequest
	refused  string
}

func (o *exitRouteOpener) SetExitRoute(_ context.Context, route netadmin.ExitRouteRequest) (netadmin.ExitRouting, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.requests = append(o.requests, route)
	if !route.Use {
		return netadmin.ExitRouting{}, nil
	}
	if o.refused != "" {
		return netadmin.ExitRouting{Refused: o.refused}, nil
	}
	return netadmin.ExitRouting{Routing: true}, nil
}

func (o *exitRouteOpener) requested() []netadmin.ExitRouteRequest {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.requests)
}

func TestWireGuardEngineRoutesTheInternetThroughTheHelper(t *testing.T) {
	// Not parallel: asking for an exit route keeps the process's own sockets
	// off the mesh routes (underlay.SetExitBound), and on macOS stops every
	// engine's direct paths, the other tests' too.
	t.Cleanup(func() { underlay.SetExitBound(underlay.ExitRequested|underlay.ExitHeld, false) })
	privateKey, snapshot := testWireGuardSnapshot(t)
	opener := &exitRouteOpener{}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: &fakeWireGuardDevice{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	// A map without an exit choice never asks.
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	snapshot = withExitRoute(snapshot, true)
	snapshot.Revision++
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the exit route", func() bool { return engine.ExitRoute().Routing })
	if got := opener.requested(); len(got) != 1 || got[0] != (netadmin.ExitRouteRequest{Use: true, IPv6: true}) {
		t.Fatalf("requests = %+v", got)
	}
	if status := engine.ExitRoute(); status.Pool != "pool" || status.Node != "exit" || !status.IPv6 {
		t.Fatalf("ExitRoute() = %+v", status)
	}
	// With no exit node left the helper keeps routing into the mesh, where
	// the traffic is dropped: nothing new is asked.
	snapshot.Revision++
	snapshot.ExitRoute.Node = ""
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	if status := engine.ExitRoute(); status.Node != "" || !status.Routing {
		t.Fatalf("ExitRoute() without an exit node = %+v", status)
	}
	// Closing keeps the helper's kill switch: no request is sent.
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if got := opener.requested(); len(got) != 1 {
		t.Fatalf("requests after Close = %+v", got)
	}
}

func TestWireGuardEngineStopsTheExitRoute(t *testing.T) {
	// Not parallel: asking for an exit route keeps the process's own sockets
	// off the mesh routes (underlay.SetExitBound), and on macOS stops every
	// engine's direct paths, the other tests' too.
	t.Cleanup(func() { underlay.SetExitBound(underlay.ExitRequested|underlay.ExitHeld, false) })
	privateKey, snapshot := testWireGuardSnapshot(t)
	opener := &exitRouteOpener{refused: netadmin.ExitRouteRefusedOff}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: &fakeWireGuardDevice{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	snapshot = withExitRoute(snapshot, false)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the refusal", func() bool { return engine.ExitRoute().Refused == netadmin.ExitRouteRefusedOff })
	snapshot.Revision++
	snapshot.ExitRoute = nil
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the release", func() bool { return len(opener.requested()) == 2 })
	if got := opener.requested(); got[1].Use {
		t.Fatalf("requests = %+v, want a release", got)
	}
}

// Only new TCP connections through the exit node count, and any answer from
// the Internet clears them.
func TestPolicyFilterCountsConnectionsThroughTheExitNode(t *testing.T) {
	t.Parallel()
	filter := newPolicyFilter()
	filter.UpdateNetwork(withExitRoute(testPolicySnapshot(), false))
	filter.SetExitRouted(true)
	self := [4]byte{100, 64, 0, 3}
	for index := range 3 {
		syn := testIPv4TransportPacket(self, [4]byte{1, 1, 1, byte(index + 1)}, 40000, 443, packetmeta.ProtocolTCP, 0x02)
		for range 2 { // the second is a retransmission
			if !filter.Allow(PacketOutbound, syn) {
				t.Fatal("a connection through the exit node was denied")
			}
		}
	}
	activity := filter.ExitActivity()
	if activity.Node != "exit" || activity.NewConnections != 3 || activity.WaitingSince.IsZero() {
		t.Fatalf("activity = %+v", activity)
	}
	answer := reverseTestPacket(testIPv4TransportPacket(self, [4]byte{1, 1, 1, 1}, 40000, 443, packetmeta.ProtocolTCP, 0x02))
	answer[33] = 0x12
	if !filter.Allow(PacketInbound, answer) {
		t.Fatal("the answer was denied")
	}
	if activity := filter.ExitActivity(); activity.NewConnections != 0 || activity.LastAnswered.IsZero() {
		t.Fatalf("activity after an answer = %+v", activity)
	}
}
