//go:build unix

package mobile

import (
	"context"
	"log/slog"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"meshtransit.net/client/internal/dnsconfig"
	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/routesettings"
	"meshtransit.net/client/internal/underlay"
)

func (tun *fakeTUN) domainValues() (search, match string) {
	tun.mu.Lock()
	defer tun.mu.Unlock()
	return tun.search, tun.match
}

func (fixture *platformFixture) opened() int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return len(fixture.devices)
}

func noAnswer(context.Context, []byte) []byte { return nil }

var meshDNS = mobileDNS{on: true, search: []string{"corp.internal"}, match: []string{"corp.internal"}}

func hasResolverRoute(routes string) bool {
	return slices.Contains(strings.Split(routes, ","), "192.0.2.53/32")
}

func TestPlatformTUNPointsDNSAtTheResolver(t *testing.T) {
	t.Parallel()
	fixture, opener := newPlatformFixture(t)
	opener.answer = noAnswer
	// Wanted before any interface: the first one has it.
	if err := opener.setDNS(t.Context(), meshDNS); err != nil {
		t.Fatal(err)
	}
	opened, err := opener.OpenTUN(t.Context(), netadmin.TUNConfig{Addresses: testAddresses, Routes: testRoutes})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Device.Close() })
	if _, isDNS := opened.Device.(*dnsTUN); !isDNS {
		t.Fatalf("the data plane got %T", opened.Device)
	}
	search, match := fixture.provider.domainValues()
	if fixture.provider.dnsValue() != "192.0.2.53" || !hasResolverRoute(fixture.provider.routesValue()) ||
		search != "corp.internal" || match != "corp.internal" || !opener.dnsOnInterface() {
		t.Fatalf("interface dns = %q routes %q search %q match %q", fixture.provider.dnsValue(),
			fixture.provider.routesValue(), search, match)
	}

	// The same DNS makes no new interface; a route change keeps the DNS.
	if err := opener.setDNS(t.Context(), meshDNS); err != nil || fixture.opened() != 1 {
		t.Fatalf("same dns: %v, %d interfaces", err, fixture.opened())
	}
	moved := append(slices.Clone(testRoutes), netip.MustParsePrefix("198.18.0.0/15"))
	if err := opener.ConfigureTUNRoutes(t.Context(), netadmin.TUNConfig{Addresses: testAddresses, Routes: moved}); err != nil {
		t.Fatal(err)
	}
	if fixture.provider.dnsValue() != "192.0.2.53" || !hasResolverRoute(fixture.provider.routesValue()) {
		t.Fatalf("after a route change: dns %q routes %q", fixture.provider.dnsValue(), fixture.provider.routesValue())
	}

	// Off: no DNS, no route to the resolver.
	if err := opener.setDNS(t.Context(), mobileDNS{}); err != nil {
		t.Fatal(err)
	}
	if fixture.provider.dnsValue() != "" || hasResolverRoute(fixture.provider.routesValue()) || opener.dnsOnInterface() {
		t.Fatalf("off: dns %q routes %q", fixture.provider.dnsValue(), fixture.provider.routesValue())
	}
}

// The Internet routed into the VPN keeps the resolver on the interface,
// whatever the host configurator wants, and the resolver knows before the
// new interface carries the routes (DNS design D4 §3.4, review 2 M-A).
func TestPlatformTUNKeepsDNSWhileTheInternetIsRouted(t *testing.T) {
	t.Parallel()
	fixture, opener := newPlatformFixture(t)
	opener.answer = noAnswer
	opened, err := opener.OpenTUN(t.Context(), netadmin.TUNConfig{Addresses: testAddresses, Routes: testRoutes})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Device.Close() })
	if fixture.provider.dnsValue() != "" {
		t.Fatalf("dns before = %q", fixture.provider.dnsValue())
	}
	var routedWhileOpening atomic.Bool
	fresh := fixture.provider.next
	fixture.provider.next = func() (int, error) {
		routedWhileOpening.Store(opener.exitRouted.Load())
		return fresh()
	}
	if err := saveRouteSettings(opener.routeSettings, routesettings.Settings{ExitUse: "World"}); err != nil {
		t.Fatal(err)
	}
	request := netadmin.ExitRouteRequest{Use: true, DNS: [2]netip.Addr{netip.MustParseAddr("100.64.0.9")}}
	if result, err := opener.SetExitRoute(t.Context(), request); err != nil || !result.Routing {
		t.Fatalf("SetExitRoute() = %+v, %v", result, err)
	}
	if !routedWhileOpening.Load() || !opener.exitRouted.Load() {
		t.Fatal("the resolver did not know the Internet was routed while the interface changed")
	}
	// The exit node's resolver is reached through ours, not set on the
	// interface; turning MeshTransit DNS off cannot take ours off.
	if fixture.provider.dnsValue() != "192.0.2.53" || !hasResolverRoute(fixture.provider.routesValue()) {
		t.Fatalf("dns with an exit = %q", fixture.provider.dnsValue())
	}
	if err := opener.setDNS(t.Context(), mobileDNS{}); err != nil || fixture.provider.dnsValue() != "192.0.2.53" {
		t.Fatalf("dns off with an exit = %q, %v", fixture.provider.dnsValue(), err)
	}

	if err := saveRouteSettings(opener.routeSettings, routesettings.Settings{}); err != nil {
		t.Fatal(err)
	}
	if _, err := opener.SetExitRoute(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if !routedWhileOpening.Load() || opener.exitRouted.Load() || fixture.provider.dnsValue() != "" {
		t.Fatalf("after the exit: routed %t while opening %t, dns %q", opener.exitRouted.Load(),
			routedWhileOpening.Load(), fixture.provider.dnsValue())
	}
}

func TestParseHostResolversKeepsAskableServers(t *testing.T) {
	t.Parallel()
	resolvers, err := parseHostResolvers(
		"192.168.1.1@101, fe80::1@101, 127.0.0.1, 100.64.0.1, 192.0.2.53, 8.8.8.8@101, 1.1.1.1@101, 9.9.9.9@101," +
			"10.0.0.1@202, 10.0.0.2@303, 10.0.0.3@404, ::ffff:192.168.1.1@101",
	)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, resolver := range resolvers {
		got = append(got, resolver.Address.String()+"@"+strconv.FormatInt(resolver.Network, 10))
	}
	want := []string{"192.168.1.1:53@101", "8.8.8.8:53@101", "1.1.1.1:53@101", "10.0.0.1:53@202", "10.0.0.2:53@303"}
	if !slices.Equal(got, want) {
		t.Fatalf("resolvers = %v, want %v", got, want)
	}
	for _, bad := range []string{"not-an-ip", "192.168.1.1@x", "192.168.1.1@-1"} {
		if _, err := parseHostResolvers(bad); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
}

// The host configurator waits for the networks' resolvers before pointing
// the device's names at MeshTransit, then keeps it on without them. Not
// parallel: the reported resolvers are process-wide.
func TestMobileDNSHostWaitsForTheNetworksResolvers(t *testing.T) {
	underlay.SetReportedResolvers(nil)
	t.Cleanup(func() { underlay.SetReportedResolvers(nil) })
	fixture, opener := newPlatformFixture(t)
	opener.answer = noAnswer
	opened, err := opener.OpenTUN(t.Context(), netadmin.TUNConfig{Addresses: testAddresses, Routes: testRoutes})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Device.Close() })
	use := &atomic.Bool{}
	use.Store(true)
	host := &mobileDNSHost{opener: opener, use: use}
	plan := dnsconfig.Plan{Enabled: true, SearchDomains: []string{"corp.internal"}}

	if err := host.Apply(t.Context(), plan); err != nil || fixture.provider.dnsValue() != "" {
		t.Fatalf("without resolvers: dns %q, %v", fixture.provider.dnsValue(), err)
	}
	underlay.SetReportedResolvers([]underlay.NetworkResolver{{Address: netip.MustParseAddrPort("192.168.1.1:53")}})
	if err := host.Apply(t.Context(), plan); err != nil || fixture.provider.dnsValue() != "192.0.2.53" {
		t.Fatalf("with resolvers: dns %q, %v", fixture.provider.dnsValue(), err)
	}
	underlay.SetReportedResolvers(nil)
	if err := host.Apply(t.Context(), plan); err != nil || fixture.provider.dnsValue() != "192.0.2.53" {
		t.Fatalf("resolvers gone: dns %q, %v", fixture.provider.dnsValue(), err)
	}
	use.Store(false)
	if err := host.Apply(t.Context(), plan); err != nil || fixture.provider.dnsValue() != "" {
		t.Fatalf("turned off: dns %q, %v", fixture.provider.dnsValue(), err)
	}
}

// A run of the runtime ending leaves the resolver for the next Start; only
// the Engine's Close stops it (code review D4 H1).
func TestDNSControllerOutlivesARun(t *testing.T) {
	t.Parallel()
	_, opener := newPlatformFixture(t)
	controller, err := newDNSController(opener, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := networkmap.Snapshot{Revision: 3}
	if _, err := controller.Apply(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	if err := controller.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Apply(t.Context(), snapshot); err != nil {
		t.Fatalf("Apply() after a run = %v", err)
	}
	if err := controller.shutdown(); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Apply(t.Context(), snapshot); err == nil {
		t.Fatal("a shut down controller applied a map")
	}
}

// Turning MeshTransit DNS off or on applies the last map again and tells
// the daemon, which reports user_off or the digest to Core (DNS design D1b
// Q7).
func TestDNSControllerReportsAChoiceApplied(t *testing.T) {
	t.Parallel()
	_, opener := newPlatformFixture(t)
	controller, err := newDNSController(opener, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controller.shutdown() })
	reapplied := make(chan networkmap.Snapshot, 2)
	controller.OnReapply(func(snapshot networkmap.Snapshot, err error) {
		if err != nil {
			t.Errorf("applying again: %v", err)
		}
		reapplied <- snapshot
	})
	if _, err := controller.Apply(t.Context(), networkmap.Snapshot{Revision: 4}); err != nil {
		t.Fatal(err)
	}
	for _, on := range []bool{false, true} {
		controller.setUse(on)
		select {
		case snapshot := <-reapplied:
			if snapshot.Revision != 4 || controller.UsesMeshDNS() != on {
				t.Fatalf("reapplied revision %d with DNS %t", snapshot.Revision, controller.UsesMeshDNS())
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("turning DNS %t was not reported", on)
		}
	}
}

// Another exit node keeps the interface: its DNS is the resolver either way.
func TestPlatformTUNKeepsTheInterfaceForAnotherExitNode(t *testing.T) {
	t.Parallel()
	fixture, opener := newPlatformFixture(t)
	opener.answer = noAnswer
	opened, err := opener.OpenTUN(t.Context(), netadmin.TUNConfig{Addresses: testAddresses, Routes: testRoutes})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Device.Close() })
	if err := saveRouteSettings(opener.routeSettings, routesettings.Settings{ExitUse: "World"}); err != nil {
		t.Fatal(err)
	}
	for _, resolver := range []string{"100.64.0.9", "100.64.0.10"} {
		request := netadmin.ExitRouteRequest{Use: true, DNS: [2]netip.Addr{netip.MustParseAddr(resolver)}}
		if _, err := opener.SetExitRoute(t.Context(), request); err != nil {
			t.Fatal(err)
		}
	}
	if fixture.opened() != 2 {
		t.Fatalf("%d interfaces for one exit route", fixture.opened())
	}
}

// Only Android answers a zone's failures NXDOMAIN (DNS design D1b §20).
func TestFailuresAsNXDOMAINOnlyOnAndroid(t *testing.T) {
	t.Parallel()
	if failuresAsNXDOMAIN != (runtime.GOOS == "android") {
		t.Fatalf("failuresAsNXDOMAIN = %t on %s", failuresAsNXDOMAIN, runtime.GOOS)
	}
}
