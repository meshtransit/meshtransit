//go:build unix

package mobile

import (
	"errors"
	"net/netip"
	"testing"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/routesettings"
)

func TestPlatformTUNInstallsAdmittedSubnetRoutes(t *testing.T) {
	t.Parallel()
	fixture, opener := newPlatformFixture(t)
	opened, err := opener.OpenTUN(t.Context(), netadmin.TUNConfig{Addresses: testAddresses, Routes: testRoutes})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Device.Close() })
	site := netip.MustParsePrefix("10.35.0.0/17")
	lan := netip.MustParsePrefix("192.168.1.0/24")
	public := netip.MustParsePrefix("203.0.113.0/24")
	requested := []netip.Prefix{site, lan, public}

	// Off by default: nothing reaches the interface.
	result, err := opener.SetRoutedRoutes(t.Context(), requested)
	if err != nil || len(result.Installed) != 0 || result.RefusedTotal != 3 {
		t.Fatalf("SetRoutedRoutes() while off = %+v, %v", result, err)
	}
	if _, routes, _ := fixture.provider.last(); routes != "100.64.0.0/10" {
		t.Fatalf("routes while off = %q", routes)
	}

	if err := saveRouteSettings(opener.routeSettings, routesettings.Settings{AcceptRoutes: true}); err != nil {
		t.Fatal(err)
	}
	networks := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	opener.hosts.networks.Store(&networks)
	result, err = opener.SetRoutedRoutes(t.Context(), requested)
	if err != nil || len(result.Installed) != 1 || result.Installed[0] != site || result.RefusedTotal != 2 {
		t.Fatalf("SetRoutedRoutes() = %+v, %v", result, err)
	}
	reasons := map[netip.Prefix]string{}
	for _, refusal := range result.Refused {
		reasons[refusal.Prefix] = refusal.Reason
	}
	if reasons[lan] != routesettings.ReasonLocalConflict || reasons[public] != routesettings.ReasonPublic {
		t.Fatalf("refusals = %v", reasons)
	}
	if _, routes, _ := fixture.provider.last(); routes != "100.64.0.0/10,10.35.0.0/17" {
		t.Fatalf("interface routes = %q", routes)
	}
	if !fixture.device(0).isClosed() {
		t.Fatal("the first interface stayed open")
	}

	// The same request changes nothing; an overlay change keeps the routes.
	if _, err := opener.SetRoutedRoutes(t.Context(), requested); err != nil {
		t.Fatal(err)
	}
	wider := append([]netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")}, testRoutes...)
	if err := opener.ConfigureTUNRoutes(t.Context(), netadmin.TUNConfig{Addresses: testAddresses, Routes: wider}); err != nil {
		t.Fatal(err)
	}
	if _, routes, _ := fixture.provider.last(); routes != "100.64.0.0/10,198.18.0.0/15,10.35.0.0/17" {
		t.Fatalf("interface routes after an overlay change = %q", routes)
	}

	// Turned off again, the next request takes the routes off.
	if err := saveRouteSettings(opener.routeSettings, routesettings.Settings{}); err != nil {
		t.Fatal(err)
	}
	if result, err := opener.SetRoutedRoutes(t.Context(), requested); err != nil || len(result.Installed) != 0 {
		t.Fatalf("SetRoutedRoutes() after off = %+v, %v", result, err)
	}
	if _, routes, _ := fixture.provider.last(); routes != "100.64.0.0/10,198.18.0.0/15" {
		t.Fatalf("interface routes after off = %q", routes)
	}
}

func TestPlatformTUNSubnetRoutesNeedAnOpenTUN(t *testing.T) {
	t.Parallel()
	_, opener := newPlatformFixture(t)
	if _, err := opener.SetRoutedRoutes(t.Context(), nil); !errors.Is(err, errNoTUN) {
		t.Fatalf("SetRoutedRoutes() before OpenTUN error = %v", err)
	}
}

func TestValidateRoutedConfig(t *testing.T) {
	t.Parallel()
	if err := validateRoutedConfig([]netip.Prefix{netip.MustParsePrefix("10.35.0.0/17")}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"0.0.0.0/0", "100.64.0.0/16", "10.35.0.1/17", "127.0.0.0/8"} {
		if validateRoutedConfig([]netip.Prefix{netip.MustParsePrefix(bad)}) == nil {
			t.Errorf("validateRoutedConfig(%s) accepted", bad)
		}
	}
}

// A route holding a DNS server or gateway of the phone's networks stays off
// the interface: the system's own traffic to it would enter the VPN.
func TestPlatformTUNRefusesRoutesHoldingNetworkServers(t *testing.T) {
	t.Parallel()
	fixture, opener := newPlatformFixture(t)
	opened, err := opener.OpenTUN(t.Context(), netadmin.TUNConfig{Addresses: testAddresses, Routes: testRoutes})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Device.Close() })
	if err := saveRouteSettings(opener.routeSettings, routesettings.Settings{AcceptRoutes: true}); err != nil {
		t.Fatal(err)
	}
	servers := []netip.Addr{netip.MustParseAddr("10.35.0.2")}
	opener.hosts.servers.Store(&servers)
	site := netip.MustParsePrefix("10.35.0.0/17")
	other := netip.MustParsePrefix("10.40.0.0/16")
	result, err := opener.SetRoutedRoutes(t.Context(), []netip.Prefix{site, other})
	if err != nil || len(result.Installed) != 1 || result.Installed[0] != other ||
		len(result.Refused) != 1 || result.Refused[0] != (routesettings.Refusal{Prefix: site, Reason: routesettings.ReasonLocalConflict}) {
		t.Fatalf("SetRoutedRoutes() = %+v, %v", result, err)
	}
	if _, routes, _ := fixture.provider.last(); routes != "100.64.0.0/10,10.40.0.0/16" {
		t.Fatalf("interface routes = %q", routes)
	}
}
