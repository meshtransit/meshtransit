//go:build integration && linux

package netadmin

import (
	"net"
	"net/netip"
	"os"
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
	desired := []netip.Prefix{netip.MustParsePrefix("10.200.0.0/24"), netip.MustParsePrefix("fc99::/64")}
	configurer := kernelRoutedConfigurer{}
	if err := configurer.ReplaceRouted(name, options, meshdUID, nil, desired); err != nil {
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
	// Applying the same routes again changes nothing and keeps one rule.
	if err := configurer.ReplaceRouted(name, options, meshdUID, desired, desired); err != nil {
		t.Fatalf("ReplaceRouted() again error = %v", err)
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleListFiltered(family, &netlink.Rule{Priority: options.Priority}, netlink.RT_FILTER_PRIORITY)
		if err != nil || len(rules) != 1 || !rules[0].Invert {
			t.Fatalf("family %d routed rules = %+v, error %v", family, rules, err)
		}
	}
	// Clearing removes the routes and the rule, as a restart does.
	if err := configurer.ReplaceRouted(name, options, meshdUID, desired, nil); err != nil {
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
	if err := configurer.ReplaceRouted(name, options, meshdUID, nil, desired); err != nil {
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
