//go:build integration && linux

package netadmin

import (
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
)

// TestKernelRoutedConfigurerIntegration installs subnet routes in their own
// table and checks the kernel's choice: meshd's uid keeps the main table,
// every other uid reaches the mesh interface; removing the routes removes
// the rules.
func TestKernelRoutedConfigurerIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	const name, meshdUID, otherUID = "meshit1", uint32(4242), uint32(4343)
	file, _, err := (kernelTUNCreator{}).Open(name, 1280, 0,
		[]netip.Prefix{netip.MustParsePrefix("100.127.255.249/32")}, []netip.Prefix{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	options := RoutedOptions{SettingsPath: "/unused", Table: 5267, Priority: 5400}
	desired := routedState{
		Routes: []netip.Prefix{netip.MustParsePrefix("10.200.0.0/24"), netip.MustParsePrefix("fc99::/64")},
		Throws: []netip.Prefix{netip.MustParsePrefix("10.200.0.53/32")},
	}
	configurer := kernelRoutedConfigurer{}
	if _, _, err := configurer.ReplaceRouted(name, options, meshdUID, routedState{}, desired); err != nil {
		t.Fatalf("ReplaceRouted() error = %v", err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	routeVia := func(destination string, uid uint32) (int, error) {
		routes, err := netlink.RouteGetWithOptions(net.ParseIP(destination), &netlink.RouteGetOptions{UID: &uid})
		if err != nil || len(routes) == 0 {
			return 0, err
		}
		return routes[0].LinkIndex, nil
	}
	if index, err := routeVia("10.200.0.5", otherUID); err != nil || index != link.Attrs().Index {
		t.Fatalf("another uid reaches 10.200.0.5 through link %d, error %v; want %d", index, err, link.Attrs().Index)
	}
	if index, _ := routeVia("10.200.0.5", meshdUID); index == link.Attrs().Index {
		t.Fatal("meshd's uid reached the routed table")
	}
	// A system resolver inside the route keeps the host's own path.
	if index, _ := routeVia("10.200.0.53", otherUID); index == link.Attrs().Index {
		t.Fatal("the pinned resolver was routed into the mesh")
	}
	// The host's own routes leave the mesh interface out; the container's
	// attached network is listed as connected.
	local, err := (kernelHostRouting{}).LocalRoutes(name)
	if err != nil {
		t.Fatalf("LocalRoutes() error = %v", err)
	}
	connected := false
	for _, route := range local {
		if route.Prefix.Bits() == 0 || route.Prefix.Addr().IsLinkLocalUnicast() {
			t.Fatalf("LocalRoutes() listed %v", route)
		}
		connected = connected || route.Connected
	}
	if !connected {
		t.Fatalf("LocalRoutes() = %+v, want the attached network", local)
	}
	// Dropping the pin routes the resolver through the mesh again.
	unpinned := routedState{Routes: desired.Routes}
	if _, _, err := configurer.ReplaceRouted(name, options, meshdUID, desired, unpinned); err != nil {
		t.Fatal(err)
	}
	if index, err := routeVia("10.200.0.53", otherUID); err != nil || index != link.Attrs().Index {
		t.Fatalf("unpinned resolver goes through link %d, error %v", index, err)
	}
	if _, _, err := configurer.ReplaceRouted(name, options, meshdUID, unpinned, desired); err != nil {
		t.Fatal(err)
	}
	// A route removed behind the helper's back, or a stray one, is put
	// right by the next request.
	if err := netlink.RouteDel(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       prefixIPNet(netip.MustParsePrefix("10.200.0.0/24")), Table: options.Table, Scope: netlink.SCOPE_LINK,
	}); err != nil {
		t.Fatal(err)
	}
	stray := &netlink.Route{
		LinkIndex: link.Attrs().Index, Dst: prefixIPNet(netip.MustParsePrefix("10.201.0.0/24")),
		Table: options.Table, Scope: netlink.SCOPE_LINK,
	}
	if err := netlink.RouteAdd(stray); err != nil {
		t.Fatal(err)
	}
	installed, refused, err := configurer.ReplaceRouted(name, options, meshdUID, desired, desired)
	if err != nil || len(refused) != 0 || !slices.Equal(installed.Routes, desired.Routes) {
		t.Fatalf("ReplaceRouted() after drift = %+v, %v, %v", installed, refused, err)
	}
	if index, err := routeVia("10.200.0.5", otherUID); err != nil || index != link.Attrs().Index {
		t.Fatalf("the removed route was not restored: link %d, error %v", index, err)
	}
	if index, _ := routeVia("10.201.0.5", otherUID); index == link.Attrs().Index {
		t.Fatal("a stray route stayed in the routed table")
	}
	// Applying the same routes again changes nothing and keeps one rule.
	if _, _, err := configurer.ReplaceRouted(name, options, meshdUID, desired, desired); err != nil {
		t.Fatalf("ReplaceRouted() again error = %v", err)
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleListFiltered(family, &netlink.Rule{Priority: options.Priority}, netlink.RT_FILTER_PRIORITY)
		if err != nil || len(rules) != 1 || !rules[0].Invert {
			t.Fatalf("family %d routed rules = %+v, error %v", family, rules, err)
		}
	}
	// Clearing removes the routes and the rule, as a restart does.
	if _, _, err := configurer.ReplaceRouted(name, options, meshdUID, desired, routedState{}); err != nil {
		t.Fatalf("ReplaceRouted(nothing) error = %v", err)
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		left, err := netlink.RuleListFiltered(family, &netlink.Rule{Priority: options.Priority}, netlink.RT_FILTER_PRIORITY)
		routes, routeErr := netlink.RouteListFiltered(family, &netlink.Route{Table: options.Table}, netlink.RT_FILTER_TABLE)
		if err != nil || routeErr != nil || len(left) != 0 || len(routes) != 0 {
			t.Fatalf("family %d keeps %d rules and %d routes, errors %v %v", family, len(left), len(routes), err, routeErr)
		}
	}
	if index, _ := routeVia("10.200.0.5", otherUID); index == link.Attrs().Index {
		t.Fatal("the routed route outlived its removal")
	}
	// Clearing with the interface gone still removes the rule.
	if _, _, err := configurer.ReplaceRouted(name, options, meshdUID, routedState{}, desired); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := configurer.Clear(options, meshdUID); err != nil {
		t.Fatalf("Clear() without the interface error = %v", err)
	}
	if left, _ := netlink.RuleListFiltered(netlink.FAMILY_V4, &netlink.Rule{Priority: options.Priority},
		netlink.RT_FILTER_PRIORITY); len(left) != 0 {
		t.Fatalf("a rule outlived its interface: %+v", left)
	}
}
