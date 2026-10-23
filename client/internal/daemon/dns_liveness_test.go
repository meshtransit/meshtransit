package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/peerprobe"
)

var resolverAddress = netip.MustParseAddr("100.64.0.21")

// failoverMapWithResolver is failoverMap plus a DNS zone whose first
// resolver is the Device resolver-1 at 100.64.0.21, and whose second is on
// the Internet.
func failoverMapWithResolver() networkmap.Snapshot {
	snapshot := failoverMap("router-1")
	snapshot.Peers = append(slices.Clone(snapshot.Peers), networkmap.Node{
		ID: 21, StableID: "resolver-1",
		Addresses: []netip.Prefix{netip.PrefixFrom(resolverAddress, 32), netip.MustParsePrefix("fd7a:115c:a1e0::21/128")},
	})
	snapshot.DNS = &networkmap.DNSConfig{Routes: []networkmap.DNSRoute{{
		Suffix: "corp.internal",
		Resolvers: []networkmap.DNSResolver{
			{Address: netip.AddrPortFrom(resolverAddress, 53)},
			{Address: netip.MustParseAddrPort("192.0.2.53:53")}, // on the Internet: not a peer
		},
	}}}
	return snapshot
}

func newLivenessFailover(t *testing.T) (*routeFailover, *failoverClock) {
	t.Helper()
	clock := &failoverClock{now: time.Date(2026, time.October, 23, 14, 0, 0, 0, time.UTC)}
	failover := newRouteFailover(clock.Now)
	failover.effective(failoverMapWithResolver())
	return failover, clock
}

// A resolver Device is pinged only while in use, after the routers; a
// question to one not pinged yet wakes the watcher (DNS design D1b §5.6).
func TestLivenessPeersPingResolversInUse(t *testing.T) {
	t.Parallel()
	failover, clock := newLivenessFailover(t)
	if got, _ := failover.livenessPeers(); !slices.Equal(got, []uint64{11, 12, 13}) {
		t.Fatalf("idle: liveness peers = %v", got)
	}
	failoverLiveness{failover}.Asked(resolverAddress)
	select {
	case <-failover.livenessWake:
	default:
		t.Fatal("a question to a resolver not pinged did not wake the watcher")
	}
	got, changed := failover.livenessPeers()
	if !changed || !slices.Equal(got, []uint64{11, 12, 13, 21}) {
		t.Fatalf("in use: liveness peers = %v (changed %t)", got, changed)
	}
	if _, changed := failover.livenessPeers(); changed {
		t.Fatal("an unchanged list is reported changed")
	}
	clock.now = clock.now.Add(resolverInUseFor + time.Second)
	if got, changed := failover.livenessPeers(); !changed || slices.Contains(got, 21) {
		t.Fatalf("idle again: liveness peers = %v (changed %t)", got, changed)
	}
}

// A resolver Device is reported stopped only once it answered and then went
// silent while pinged: never when it never answered, nor in its first
// seconds of pings, nor after the session ends.
func TestResolverStoppedOnlyAfterItAnswered(t *testing.T) {
	t.Parallel()
	failover, clock := newLivenessFailover(t)
	liveness := failoverLiveness{failover}
	liveness.Asked(resolverAddress)
	failover.livenessPeers()
	clock.now = clock.now.Add(10 * time.Second)
	if liveness.Stopped(resolverAddress) {
		t.Fatal("a resolver that never answered is reported stopped")
	}
	failover.ObserveRelayPong(21, clock.now)
	clock.now = clock.now.Add(failoverAliveWithin)
	if liveness.Stopped(resolverAddress) {
		t.Fatal("a resolver that answered within the window is reported stopped")
	}
	clock.now = clock.now.Add(time.Second)
	if !liveness.Stopped(resolverAddress) {
		t.Fatal("a resolver that stopped answering is not reported")
	}
	if liveness.Stopped(netip.MustParseAddr("192.0.2.53")) || liveness.Stopped(netip.MustParseAddr("100.64.0.11")) {
		t.Fatal("an address that is no resolver Device is reported stopped")
	}
	failover.closeLiveness()
	if liveness.Stopped(resolverAddress) {
		t.Fatal("a resolver is reported stopped after the session's pings ended")
	}
	clock.now = clock.now.Add(resolverInUseFor + time.Second)
	liveness.Asked(resolverAddress)
	if got, _ := failover.livenessPeers(); slices.Contains(got, 21) {
		t.Fatal("a question after the session ended made the resolver pinged")
	}
}

// A pong from before the resolver was pinged, or from before it went idle,
// does not make it stopped the moment it is pinged again: it gets the window
// to answer first.
func TestResolverStoppedWaitsForItsFirstPings(t *testing.T) {
	t.Parallel()
	failover, clock := newLivenessFailover(t)
	liveness := failoverLiveness{failover}
	failover.ObserveRelayPong(21, clock.now)
	clock.now = clock.now.Add(time.Hour)
	liveness.Asked(resolverAddress)
	failover.livenessPeers()
	clock.now = clock.now.Add(failoverAliveWithin)
	if liveness.Stopped(resolverAddress) {
		t.Fatal("reported stopped before it could answer the new pings")
	}
	clock.now = clock.now.Add(time.Second)
	if !liveness.Stopped(resolverAddress) {
		t.Fatal("silent past the window is not reported")
	}
	// Idle long enough to leave the pinged peers, then asked again.
	clock.now = clock.now.Add(resolverInUseFor + time.Second)
	failover.livenessPeers()
	liveness.Asked(resolverAddress)
	failover.livenessPeers()
	if liveness.Stopped(resolverAddress) {
		t.Fatal("reported stopped right after it is pinged again")
	}
}

// A zone with one resolver has nothing to ask first: its resolver Device is
// never pinged for DNS.
func TestResolverPeersSkipZonesWithOneResolver(t *testing.T) {
	t.Parallel()
	snapshot := failoverMapWithResolver()
	snapshot.DNS.Routes[0].Resolvers = snapshot.DNS.Routes[0].Resolvers[:1]
	if peers, order := resolverPeersOf(snapshot); len(peers) != 0 || len(order) != 0 {
		t.Fatalf("resolver peers = %v %v", peers, order)
	}
}

// Past the relay's bound the routers keep their place and the resolver
// Devices are the ones left out; a resolver left out is never reported. A
// resolver Device that is also a router is listed once, in the router's
// place.
func TestLivenessPeersKeepRoutersFirst(t *testing.T) {
	t.Parallel()
	clock := &failoverClock{now: time.Date(2026, time.October, 23, 14, 0, 0, 0, time.UTC)}
	failover := newRouteFailover(clock.Now)
	snapshot := failoverMapWithResolver()
	internet := networkmap.DNSResolver{Address: netip.MustParseAddrPort("192.0.2.53:53")}
	routes := []networkmap.DNSRoute{{
		Suffix: "router.internal", Resolvers: []networkmap.DNSResolver{
			{Address: netip.MustParseAddrPort("100.64.0.12:53")}, internet,
		},
	}}
	snapshot.Peers[1].Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.12/32")} // router-2
	var addresses []netip.Addr
	for index := range peerprobe.MaxRelayLivenessPeers {
		address := netip.AddrFrom4([4]byte{100, 64, 1, byte(index)})
		addresses = append(addresses, address)
		snapshot.Peers = append(snapshot.Peers, networkmap.Node{
			ID: uint64(100 + index), Addresses: []netip.Prefix{netip.PrefixFrom(address, 32)},
		})
		routes = append(routes, networkmap.DNSRoute{
			Suffix:    fmt.Sprintf("zone%d.internal", index),
			Resolvers: []networkmap.DNSResolver{{Address: netip.AddrPortFrom(address, 53)}, internet},
		})
	}
	snapshot.DNS.Routes = append(routes, snapshot.DNS.Routes...)
	failover.effective(snapshot)
	liveness := failoverLiveness{failover}
	liveness.Asked(netip.MustParseAddr("100.64.0.12"))
	for _, address := range addresses {
		liveness.Asked(address)
	}
	liveness.Asked(resolverAddress)
	peers, _ := failover.livenessPeers()
	if len(peers) != peerprobe.MaxRelayLivenessPeers || !slices.Equal(peers[:4], []uint64{11, 12, 13, 100}) ||
		slices.Contains(peers, 21) {
		t.Fatalf("liveness peers = %v", peers)
	}
	failover.ObserveRelayPong(21, clock.now)
	clock.now = clock.now.Add(time.Minute - time.Second)
	if liveness.Stopped(resolverAddress) {
		t.Fatal("a resolver that is not pinged is reported stopped")
	}
}

// The watcher sets the list when a question wakes it with a resolver not
// pinged yet, never an unchanged list again, and ends with its context.
func TestWatchResolverLiveness(t *testing.T) {
	t.Parallel()
	failover, _ := newLivenessFailover(t)
	failover.syncRelayLiveness(func([]uint64) {}, true)
	sets := make(chan []uint64, 4)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchResolverLiveness(ctx, failover, func(peers []uint64) { sets <- peers })
	}()
	failoverLiveness{failover}.Asked(resolverAddress)
	select {
	case peers := <-sets:
		if !slices.Contains(peers, 21) {
			t.Fatalf("set %v", peers)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the watcher did not set the resolver in use")
	}
	select {
	case peers := <-sets:
		t.Fatalf("an unchanged list was set again: %v", peers)
	case <-time.After(1500 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the watcher outlived its context")
	}
}
