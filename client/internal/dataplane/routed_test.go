package dataplane

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/packetmeta"
	"meshtransit.net/client/internal/routesettings"
)

// testRoutedSnapshot is the policy test map with the peer as the primary
// router of two Sites, one served and one not.
func testRoutedSnapshot() networkmap.Snapshot {
	snapshot := testPolicySnapshot()
	snapshot.Peers[0].ID, snapshot.Peers[0].StableID, snapshot.Peers[0].PublicKey = 2, "router", "nodekey:router"
	snapshot.Routes = []networkmap.SiteRoute{
		{
			Ref: "site-a", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
			Candidates: []string{"router"}, Primary: "router", Generation: 1, Status: networkmap.RouteServed,
		},
		{
			Ref: "site-b", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")},
			Candidates: []string{"router"}, Generation: 1, Status: networkmap.RouteUnserved,
		},
	}
	return snapshot
}

func TestRoutedTableFindsTheMostSpecificSite(t *testing.T) {
	t.Parallel()
	snapshot := testRoutedSnapshot()
	snapshot.Routes = append(snapshot.Routes, networkmap.SiteRoute{
		Ref: "site-c", Prefixes: []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")},
		Candidates: []string{"gone"}, Primary: "gone", Generation: 1, Status: networkmap.RouteServed,
	})
	table := newRoutedTable(snapshot)
	tests := []struct {
		address string
		site    string
		served  bool
	}{
		{"10.20.3.4", "site-a", true},
		{"10.30.0.1", "site-b", false},
		{"172.20.0.1", "site-c", false}, // its primary is no peer of the map
	}
	for _, test := range tests {
		prefix, site, found := table.lookup(netip.MustParseAddr(test.address))
		if !found || site.ref != test.site || site.served != test.served || !prefix.Contains(netip.MustParseAddr(test.address)) {
			t.Errorf("lookup(%s) = %v %+v %t", test.address, prefix, site, found)
		}
	}
	if _, _, found := table.lookup(netip.MustParseAddr("192.168.1.1")); found {
		t.Error("an address outside every Site was found")
	}
	if served := table.servedPrefixes(); len(served) != 1 ||
		!slices.Equal(served[2], []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}) {
		t.Errorf("servedPrefixes() = %v", served)
	}
	if got := routedPrefixesOf(snapshot); len(got) != 3 || got[0] != netip.MustParsePrefix("10.20.0.0/16") {
		t.Errorf("routedPrefixesOf() = %v", got)
	}
	// Overlapping Sites are both in conflict: neither is served.
	snapshot.Routes[1].Prefixes = []netip.Prefix{netip.MustParsePrefix("10.20.5.0/24")}
	snapshot.Routes[1].Primary, snapshot.Routes[1].Status = "router", networkmap.RouteServed
	if served := newRoutedTable(snapshot).servedPrefixes(); len(served) != 0 {
		t.Errorf("overlapping Sites served %v", served)
	}
	if newRoutedTable(networkmap.Snapshot{}) != nil {
		t.Error("a map without Sites has a routed table")
	}
}

func TestPolicyFilterReachesInstalledServedSitesOnly(t *testing.T) {
	t.Parallel()
	filter := newPolicyFilter()
	snapshot := testRoutedSnapshot()
	filter.UpdateNetwork(snapshot)
	self := [4]byte{100, 64, 0, 3}
	toSite := testIPv4TransportPacket(self, [4]byte{10, 20, 0, 5}, 40000, 443, packetmeta.ProtocolTCP, 0x02)
	reply := reverseTestPacket(toSite)
	reply[33] = 0x12
	if filter.Allow(PacketOutbound, toSite) {
		t.Fatal("a Site was reached before the helper installed its prefix")
	}
	filter.SetRoutedInstalled([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("10.30.0.0/16")})
	if !filter.Allow(PacketOutbound, toSite) || !filter.Allow(PacketInbound, reply) {
		t.Fatal("a served, installed Site was not reachable")
	}
	// A Site's host never opens a flow to this node.
	opening := testIPv4TransportPacket([4]byte{10, 20, 0, 5}, self, 443, 18080, packetmeta.ProtocolTCP, 0x02)
	if filter.Allow(PacketInbound, opening) {
		t.Fatal("a Site's host opened a flow")
	}
	if _, unreachable := filter.routedUnreachable(toSite); unreachable {
		t.Fatal("a served Site was reported unreachable")
	}
	toUnserved := testIPv4TransportPacket(self, [4]byte{10, 30, 0, 5}, 40000, 443, packetmeta.ProtocolTCP, 0x02)
	if filter.Allow(PacketOutbound, toUnserved) {
		t.Fatal("an unserved Site was reached")
	}
	if site, unreachable := filter.routedUnreachable(toUnserved); !unreachable || site != "site-b" {
		t.Fatalf("routedUnreachable(unserved) = %q, %t", site, unreachable)
	}
	// Once the helper removes the prefix, its flows end.
	filter.SetRoutedInstalled([]netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")})
	if filter.Allow(PacketInbound, reply) {
		t.Fatal("a flow outlived its route")
	}
	filter.SetRoutedInstalled([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
	if !filter.Allow(PacketOutbound, toSite) || !filter.Allow(PacketInbound, reply) {
		t.Fatal("the reinstalled Site was not reachable")
	}
	// An unrelated map change keeps the flow; a new primary ends it.
	filter.UpdateNetwork(snapshot)
	if !filter.Allow(PacketInbound, reply) {
		t.Fatal("an unchanged map ended a Site flow")
	}
	snapshot.Peers[0].PublicKey = "nodekey:replaced"
	filter.UpdateNetwork(snapshot)
	if filter.Allow(PacketInbound, reply) {
		t.Fatal("a Site flow survived a new key at its router")
	}
}

func TestBuildWireGuardPlanGivesThePrimaryItsServedSites(t *testing.T) {
	t.Parallel()
	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].StableID = "router"
	snapshot.Routes = testRoutedSnapshot().Routes
	plan, err := buildWireGuardPlan(snapshot, privateKey, 41641)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.clearSecrets()
	want := []netip.Prefix{netip.MustParsePrefix("100.64.0.4/32"), netip.MustParsePrefix("10.20.0.0/16")}
	if len(plan.peers) != 1 || !slices.Equal(plan.peers[0].allowedIPs, want) {
		t.Fatalf("peer allowed IPs = %v, want %v", plan.peers[0].allowedIPs, want)
	}
	// The TUN's own routes stay the overlay's: the helper installs Sites.
	if !slices.Equal(plan.routes, []netip.Prefix{netip.MustParsePrefix("100.64.0.4/32")}) {
		t.Fatalf("tun routes = %v", plan.routes)
	}
	if !strings.Contains(string(plan.configuration), "allowed_ip=10.20.0.0/16\n") ||
		strings.Contains(string(plan.configuration), "10.30.0.0") {
		t.Fatal("the configuration does not carry exactly the served Site")
	}
}

type routedTUNOpener struct {
	wireGuardTUNOpener
	mu        sync.Mutex
	requests  [][]netip.Prefix
	refuse    map[netip.Prefix]string
	err       error
	installed []netip.Prefix
}

func (o *routedTUNOpener) SetRoutedRoutes(_ context.Context, routes []netip.Prefix) (netadmin.RoutedResult, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.requests = append(o.requests, slices.Clone(routes))
	if o.err != nil {
		return netadmin.RoutedResult{}, o.err
	}
	result := netadmin.RoutedResult{Installed: []netip.Prefix{}}
	for _, route := range routes {
		if reason, refused := o.refuse[route]; refused {
			result.Refused = append(result.Refused, routesettings.Refusal{Prefix: route, Reason: reason})
			result.RefusedTotal++
			continue
		}
		result.Installed = append(result.Installed, route)
	}
	o.installed = result.Installed
	return result, nil
}

// requests returns the routes asked of the helper so far.
func (o *routedTUNOpener) requested() [][]netip.Prefix {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.requests)
}

func (o *routedTUNOpener) setErr(err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.err = err
}

// waitFor polls condition until it holds or a second passes.
func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWireGuardEngineInstallsSiteRoutesThroughTheHelper(t *testing.T) {
	t.Parallel()
	privateKey, snapshot := testWireGuardSnapshot(t)
	opener := &routedTUNOpener{refuse: map[netip.Prefix]string{
		netip.MustParsePrefix("10.30.0.0/16"): routesettings.ReasonLocalConflict,
	}}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: &fakeWireGuardDevice{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	// A map without Sites never asks: older helpers need not know routes.
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	snapshot.Revision++
	snapshot.Peers[0].StableID = "router"
	snapshot.Routes = testRoutedSnapshot().Routes
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("10.30.0.0/16")}
	waitFor(t, "the routes to be recorded", func() bool { return engine.SubnetRoutes().Requested == 2 })
	if requests := opener.requested(); len(requests) != 1 || !slices.Equal(requests[0], want) {
		t.Fatalf("requests = %v, want every Site's prefixes once", requests)
	}
	status := engine.SubnetRoutes()
	if status.Installed != 1 || status.RefusedTotal != 1 || !status.LocalConflict || status.Error != "" {
		t.Fatalf("SubnetRoutes() = %+v", status)
	}
	// Sites gone remove the routes.
	snapshot.Revision++
	snapshot.Routes = nil
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the routes to be removed", func() bool { return engine.SubnetRoutes().Requested == 0 })
	if requests := opener.requested(); len(requests) != 2 || len(requests[1]) != 0 {
		t.Fatalf("removing Sites = %v", requests)
	}
	// A helper failure leaves nothing reachable and keeps the peers.
	opener.setErr(errors.New("helper unavailable"))
	snapshot.Revision++
	snapshot.Routes = testRoutedSnapshot().Routes
	if state, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil || state == StateFailed {
		t.Fatalf("Apply() with a failing helper = %q, %v", state, err)
	}
	waitFor(t, "the failure to be recorded", func() bool { return engine.SubnetRoutes().Error != "" })
	if status := engine.SubnetRoutes(); status.Installed != 0 {
		t.Fatalf("SubnetRoutes() after failure = %+v", status)
	}
	// Closing forgets the routes: the next device asks again.
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if status := engine.SubnetRoutes(); status.Requested != 0 {
		t.Fatalf("SubnetRoutes() after Close = %+v", status)
	}
}

// blockingRoutedOpener holds the first request until released.
type blockingRoutedOpener struct {
	routedTUNOpener
	started, release chan struct{}
	once             sync.Once
}

func (o *blockingRoutedOpener) SetRoutedRoutes(ctx context.Context, routes []netip.Prefix) (netadmin.RoutedResult, error) {
	first := false
	o.once.Do(func() { first = true })
	if first {
		close(o.started)
		<-o.release
	}
	return o.routedTUNOpener.SetRoutedRoutes(ctx, routes)
}

// A request still in flight when a newer map arrives must never decide what
// the filter admits: the newer request is sent after it, and only its answer
// counts.
func TestWireGuardEngineNeverRecordsAnOlderRoutedRequest(t *testing.T) {
	t.Parallel()
	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].StableID = "router"
	snapshot.Routes = testRoutedSnapshot().Routes[:1]
	opener := &blockingRoutedOpener{started: make(chan struct{}), release: make(chan struct{})}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: &fakeWireGuardDevice{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	<-opener.started
	// Apply does not wait for the helper.
	snapshot.Revision++
	snapshot.Routes = testRoutedSnapshot().Routes[1:]
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	close(opener.release)
	newer := []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")}
	waitFor(t, "the newer request", func() bool { return len(opener.requested()) == 2 })
	waitFor(t, "the newer answer", func() bool {
		engine.filter.mu.Lock()
		defer engine.filter.mu.Unlock()
		_, older := engine.filter.routedInstalled[netip.MustParsePrefix("10.20.0.0/16")]
		_, current := engine.filter.routedInstalled[newer[0]]
		return current && !older
	})
	if requests := opener.requested(); !slices.Equal(requests[1], newer) {
		t.Fatalf("requests = %v", requests)
	}
}

// A withdrawal that fails is sent again until the helper holds nothing.
func TestWireGuardEngineRetriesAFailedWithdrawal(t *testing.T) {
	t.Parallel()
	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].StableID = "router"
	snapshot.Routes = testRoutedSnapshot().Routes
	opener := &routedTUNOpener{}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: &fakeWireGuardDevice{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Slower than the failures it takes to give up, so the retry is seen.
	engine.routed.refresh = 50 * time.Millisecond
	t.Cleanup(func() { _ = engine.Close() })
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the routes", func() bool { return engine.SubnetRoutes().Installed == 2 })
	opener.setErr(errors.New("helper busy"))
	snapshot.Revision++
	snapshot.Routes = nil
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the failed withdrawal", func() bool { return engine.SubnetRoutes().Error != "" })
	opener.setErr(nil)
	failed := len(opener.requested())
	waitFor(t, "the withdrawal to be retried", func() bool {
		requests := opener.requested()
		return len(requests) > failed && engine.SubnetRoutes().Error == "" && len(requests[len(requests)-1]) == 0
	})
	engine.mu.Lock()
	holds := engine.routed.mayHold
	engine.mu.Unlock()
	if holds {
		t.Fatal("the engine still thinks the helper holds routes")
	}
}

func TestWireGuardEngineReportsSubnetRoutesUnsupported(t *testing.T) {
	t.Parallel()
	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].StableID = "router"
	snapshot.Routes = testRoutedSnapshot().Routes
	engine, err := newWireGuardEngine(&wireGuardTUNOpener{}, 41641, &fakeWireGuardFactory{device: &fakeWireGuardDevice{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	if status := engine.SubnetRoutes(); status.Requested != 2 || status.Installed != 0 || status.Error == "" {
		t.Fatalf("SubnetRoutes() = %+v", status)
	}
}

func TestObservedTUNAnswersUnreachableSitesWithinTheLimit(t *testing.T) {
	t.Parallel()
	filter := newPolicyFilter()
	filter.UpdateNetwork(testRoutedSnapshot())
	filter.SetRoutedInstalled([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("10.30.0.0/16")})
	self := [4]byte{100, 64, 0, 3}
	toUnserved := testIPv4TransportPacket(self, [4]byte{10, 30, 0, 5}, 40000, 443, packetmeta.ProtocolTCP, 0x02)
	toServed := testIPv4TransportPacket(self, [4]byte{10, 20, 0, 5}, 40000, 443, packetmeta.ProtocolTCP, 0x02)
	device := &batchTUNDevice{readPackets: [][]byte{toUnserved, toServed}}
	wrapped := &observedTUN{Device: device, filter: filter}
	for range unreachablePerSecond + 3 {
		buffers := [][]byte{make([]byte, 128), make([]byte, 128)}
		if count, err := wrapped.Read(buffers, make([]int, 2), 16); err != nil || count != 1 {
			t.Fatalf("Read() = %d, %v", count, err)
		}
	}
	if len(device.writtenPackets) != unreachablePerSecond {
		t.Fatalf("answers = %d, want the limit %d", len(device.writtenPackets), unreachablePerSecond)
	}
	answer, err := packetmeta.Parse(device.writtenPackets[0])
	if err != nil || answer.Protocol != packetmeta.ProtocolICMPv4 || answer.ICMPType != 3 ||
		answer.Source != netip.MustParseAddr("10.30.0.5") || answer.Destination != netip.MustParseAddr("100.64.0.3") {
		t.Fatalf("answer = %+v, %v", answer, err)
	}
	if answered, limited := filter.unreachable.answered.Load(), filter.unreachable.limited.Load(); answered != unreachablePerSecond ||
		limited != 3 {
		t.Fatalf("answered %d, limited %d", answered, limited)
	}
}

// A Site prefix holding a node's mesh address would let its router speak as
// that node: it is left out of the table, WireGuard and the helper's routes.
func TestRoutedTableLeavesOutPrefixesHoldingMeshAddresses(t *testing.T) {
	t.Parallel()
	snapshot := testRoutedSnapshot()
	snapshot.Routes[0].Prefixes = []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("100.64.0.0/24"),
		netip.MustParsePrefix("100.64.0.4/32"),
	}
	table := newRoutedTable(snapshot)
	for _, address := range []string{"100.64.0.3", "100.64.0.4", "100.64.0.9"} {
		if prefix, _, found := table.lookup(netip.MustParseAddr(address)); found {
			t.Errorf("lookup(%s) found %v", address, prefix)
		}
	}
	if served := table.servedPrefixes()[2]; !slices.Equal(served, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}) {
		t.Errorf("servedPrefixes() = %v", served)
	}
	if got := routedPrefixesOf(snapshot); slices.Contains(got, netip.MustParsePrefix("100.64.0.4/32")) ||
		slices.Contains(got, netip.MustParsePrefix("100.64.0.0/24")) {
		t.Errorf("routedPrefixesOf() = %v", got)
	}
}

func TestUnreachableAnswererKeepsOtherSitesLimitsWhenFull(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	answerer := newUnreachableAnswerer(func() time.Time { return now })
	for site := range maximumUnreachableSites {
		if !answerer.allow(fmt.Sprint(site)) {
			t.Fatalf("site %d was limited", site)
		}
	}
	for range unreachablePerSecond - 1 {
		answerer.allow("0")
	}
	if answerer.allow("new") || answerer.allow("0") {
		t.Fatal("a full table admitted a new Site or reset a limit")
	}
	now = now.Add(time.Second)
	if !answerer.allow("new") || !answerer.allow("0") {
		t.Fatal("expired windows were not freed")
	}
}

// A helper that never accepts the request, such as one with subnet routes
// off, does not keep the worker retrying a withdrawal forever.
func TestWireGuardEngineStopsRetryingAWithdrawalThatKeepsFailing(t *testing.T) {
	t.Parallel()
	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].StableID = "router"
	snapshot.Routes = testRoutedSnapshot().Routes
	opener := &routedTUNOpener{err: errors.New("routed routes unavailable")}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: &fakeWireGuardDevice{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.routed.refresh = time.Millisecond
	t.Cleanup(func() { _ = engine.Close() })
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the failure", func() bool { return engine.SubnetRoutes().Error != "" })
	snapshot.Revision++
	snapshot.Routes = nil
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the worker to stop", func() bool {
		engine.mu.Lock()
		defer engine.mu.Unlock()
		return !engine.routed.running
	})
	if status := engine.SubnetRoutes(); status.Error != "" || status.Requested != 0 {
		t.Fatalf("SubnetRoutes() after giving up = %+v", status)
	}
	sent := len(opener.requested())
	time.Sleep(20 * time.Millisecond)
	if len(opener.requested()) != sent {
		t.Fatal("the worker kept sending after giving up")
	}
}

func TestPolicyFilterRecordsWhatASiteAnswers(t *testing.T) {
	t.Parallel()
	filter := newPolicyFilter()
	now := time.Date(2026, time.October, 19, 14, 0, 0, 0, time.UTC)
	filter.clock = func() time.Time { return now }
	snapshot := testRoutedSnapshot()
	filter.UpdateNetwork(snapshot)
	filter.SetRoutedInstalled([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
	self := [4]byte{100, 64, 0, 3}
	toSite := testIPv4TransportPacket(self, [4]byte{10, 20, 0, 5}, 40000, 443, packetmeta.ProtocolTCP, 0x02)
	reply := reverseTestPacket(toSite)
	reply[33] = 0x12
	if !filter.Allow(PacketOutbound, toSite) {
		t.Fatal("the Site was not reachable")
	}
	sentAt := now
	now = now.Add(time.Second)
	if !filter.Allow(PacketOutbound, toSite) {
		t.Fatal("the Site was not reachable again")
	}
	if got := filter.RoutedActivity(); len(got) != 1 || got[0].Ref != "site-a" || !got[0].WaitingSince.Equal(sentAt) ||
		!got[0].LastSent.Equal(now) || !got[0].LastAnswered.IsZero() {
		t.Fatalf("waiting activity = %+v", got)
	}
	now = now.Add(time.Second)
	if !filter.Allow(PacketInbound, reply) {
		t.Fatal("the reply was refused")
	}
	if got := filter.RoutedActivity(); len(got) != 1 || !got[0].WaitingSince.IsZero() || !got[0].LastAnswered.Equal(now) {
		t.Fatalf("answered activity = %+v", got)
	}
	// Traffic to peers is no Site's; a Site gone from the map is forgotten.
	snapshot.Routes = nil
	filter.UpdateNetwork(snapshot)
	if got := filter.RoutedActivity(); len(got) != 0 {
		t.Fatalf("activity of a removed Site = %+v", got)
	}
}

// A local router choice applies the same map revision with another primary:
// the Site's prefixes move to that peer, and its flows end.
func TestWireGuardEngineMovesASiteToAnotherPrimaryOfTheSameMap(t *testing.T) {
	t.Parallel()
	privateKey, snapshot := testWireGuardSnapshot(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	standby := snapshot.Peers[0]
	standby.ID, standby.StableID = 3, "standby"
	standby.PublicKey = "nodekey:" + hex.EncodeToString(key.PublicKey().Bytes())
	standby.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32")}
	standby.AllowedIPs = standby.Addresses
	snapshot.Peers[0].StableID = "router"
	snapshot.Peers = append(snapshot.Peers, standby)
	snapshot.Routes = []networkmap.SiteRoute{{
		Ref: "site-a", Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Candidates: []string{"router", "standby"}, Primary: "router", Generation: 1, Status: networkmap.RouteServed,
	}}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(&routedTUNOpener{}, 41641, &fakeWireGuardFactory{device: device}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the Site route", func() bool { return engine.SubnetRoutes().Installed == 1 })
	carries := func(peer networkmap.Node) bool {
		engine.mu.Lock()
		defer engine.mu.Unlock()
		state, found := engine.peers[peer.ID]
		return found && slices.Contains(state.allowedIPs, netip.MustParsePrefix("10.20.0.0/16"))
	}
	if !carries(snapshot.Peers[0]) || carries(standby) {
		t.Fatal("the primary does not carry the Site")
	}
	moved := snapshot
	moved.Routes = slices.Clone(snapshot.Routes)
	moved.Routes[0].Primary = "standby"
	configured := len(device.configurations)
	if _, err := engine.Apply(t.Context(), moved, privateKey); err != nil {
		t.Fatal(err)
	}
	if carries(snapshot.Peers[0]) || !carries(standby) {
		t.Fatal("the Site did not move to the chosen router")
	}
	if len(device.configurations) == configured ||
		!strings.Contains(device.configurations[len(device.configurations)-1], "allowed_ip=10.20.0.0/16") {
		t.Fatal("WireGuard was not told of the move")
	}
	if activity := engine.RoutedActivity(); len(activity) != 0 {
		t.Fatalf("activity without traffic = %+v", activity)
	}
}

// A change of the host's networks sends the unchanged request again at once,
// not at the next refresh: what the helper may install depends on them.
func TestWireGuardEngineRechecksSubnetRoutesAtOnce(t *testing.T) {
	t.Parallel()
	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].StableID = "router"
	snapshot.Routes = testRoutedSnapshot().Routes
	opener := &routedTUNOpener{}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: &fakeWireGuardDevice{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.routed.refresh = time.Hour
	t.Cleanup(func() { _ = engine.Close() })
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first request", func() bool { return len(opener.requested()) == 1 })
	engine.RecheckSubnetRoutes()
	waitFor(t, "the recheck", func() bool { return len(opener.requested()) == 2 })
	requests := opener.requested()
	if !slices.Equal(requests[0], requests[1]) {
		t.Fatalf("requests = %v", requests)
	}
	var none *WireGuardEngine
	none.RecheckSubnetRoutes()
}
