//go:build unix

package mobile

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/routesettings"
)

func TestPlatformTUNSendsTheInternetToTheExitNode(t *testing.T) {
	t.Parallel()
	fixture, opener := newPlatformFixture(t)
	opened, err := opener.OpenTUN(t.Context(), netadmin.TUNConfig{Addresses: testAddresses, Routes: testRoutes})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Device.Close() })
	resolver := netip.MustParseAddr("100.64.0.9")
	request := netadmin.ExitRouteRequest{Use: true, DNS: [2]netip.Addr{resolver}}

	// No pool chosen: meshd's request alone is refused.
	result, err := opener.SetExitRoute(t.Context(), request)
	if err != nil || result.Routing || result.Refused != netadmin.ExitRouteRefusedOff {
		t.Fatalf("SetExitRoute() while off = %+v, %v", result, err)
	}

	if err := saveRouteSettings(opener.routeSettings, routesettings.Settings{ExitUse: "World"}); err != nil {
		t.Fatal(err)
	}
	result, err = opener.SetExitRoute(t.Context(), request)
	if err != nil || !result.Routing || result.Refused != "" {
		t.Fatalf("SetExitRoute() = %+v, %v", result, err)
	}
	if routes := fixture.provider.routesValue(); routes != "100.64.0.0/10,0.0.0.0/0,::/0" {
		t.Fatalf("interface routes = %q", routes)
	}
	if dns := fixture.provider.dnsValue(); dns != "100.64.0.9" {
		t.Fatalf("interface DNS = %q", dns)
	}

	// The LAN allowed: its private subnet stays outside the VPN.
	networks := []netip.Prefix{netip.MustParsePrefix("192.168.1.20/24"), netip.MustParsePrefix("203.0.113.5/24")}
	opener.hosts.networks.Store(&networks)
	if err := saveRouteSettings(opener.routeSettings, routesettings.Settings{ExitUse: "World", ExitAllowLAN: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := opener.SetExitRoute(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	routes := strings.Split(fixture.provider.routesValue(), ",")
	if slices.Contains(routes, "0.0.0.0/0") || !slices.Contains(routes, "192.168.0.0/24") ||
		slices.Contains(routes, "192.168.1.0/24") || slices.Contains(routes, "224.0.0.0/24") ||
		!slices.Contains(routes, "::/1") {
		t.Fatalf("routes with the LAN allowed = %q", routes)
	}

	// Stopping takes the Internet routes and resolvers off.
	if err := saveRouteSettings(opener.routeSettings, routesettings.Settings{}); err != nil {
		t.Fatal(err)
	}
	if result, err := opener.SetExitRoute(t.Context(), netadmin.ExitRouteRequest{}); err != nil || result.Routing {
		t.Fatalf("SetExitRoute() after off = %+v, %v", result, err)
	}
	if routes, dns := fixture.provider.routesValue(), fixture.provider.dnsValue(); routes != "100.64.0.0/10" || dns != "" {
		t.Fatalf("after off routes %q dns %q", routes, dns)
	}
}

func TestPlatformTUNRefusesAResolverOutsideTheMesh(t *testing.T) {
	t.Parallel()
	_, opener := newPlatformFixture(t)
	opened, err := opener.OpenTUN(t.Context(), netadmin.TUNConfig{Addresses: testAddresses, Routes: testRoutes})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Device.Close() })
	if err := saveRouteSettings(opener.routeSettings, routesettings.Settings{ExitUse: "World"}); err != nil {
		t.Fatal(err)
	}
	request := netadmin.ExitRouteRequest{Use: true, DNS: [2]netip.Addr{netip.MustParseAddr("8.8.8.8")}}
	if result, err := opener.SetExitRoute(t.Context(), request); err == nil || result.Routing {
		t.Fatalf("SetExitRoute() with a public resolver = %+v, %v", result, err)
	}
}

func TestInternetRoutesCoverAllButTheExcluded(t *testing.T) {
	t.Parallel()
	excluded := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("fd00:1::/64")}
	routes := internetRoutes(excluded)
	for _, probe := range []string{"1.1.1.1", "192.168.0.1", "192.168.2.1", "255.255.255.255", "2001:db8::1", "fd00:2::1"} {
		address := netip.MustParseAddr(probe)
		covered := 0
		for _, route := range routes {
			if route.Contains(address) {
				covered++
			}
		}
		if covered != 1 {
			t.Errorf("%s covered by %d routes, want 1", probe, covered)
		}
	}
	for _, probe := range []string{"192.168.1.1", "fd00:1::5"} {
		for _, route := range routes {
			if route.Contains(netip.MustParseAddr(probe)) {
				t.Errorf("%s is excluded but %s covers it", probe, route)
			}
		}
	}
	if len(routes) != 24+64 {
		t.Fatalf("%d routes, want %d", len(routes), 24+64)
	}
}
