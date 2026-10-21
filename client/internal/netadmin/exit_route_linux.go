//go:build linux

package netadmin

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"meshtransit.net/client/internal/captive"
)

const (
	// exitRulePriorities is how many rule priorities the exit route takes,
	// from RoutedOptions.ExitPriority (exit node design §6.1.1): replies
	// to connections opened from outside, DHCP, sockets bound to an
	// interface, then everything but meshd into the exit table.
	exitRulePriorities = 4
	// exitUnreachableMetric is the metric of the exit table's unreachable
	// default: once the TUN is gone its default route goes with it, and a
	// lookup stops here instead of falling through to the main table.
	exitUnreachableMetric = 4096
	// exitRouteMetric is the metric of the exit table's other routes, set
	// so the kernel keeps it as given (IPv6 would take 1024).
	exitRouteMetric = 1
	// exitInboundMark marks connections opened from outside the host and
	// its packets: their replies leave by the host's own routes.
	exitInboundMark uint32 = 0x20000000
	// maximumExitInterfaces and maximumExitSubnets bound what the exit
	// route keeps out of the mesh; a host with more keeps the first.
	maximumExitInterfaces = 32
	maximumExitSubnets    = 64
)

type kernelExitRouteConfigurer struct {
	options RoutedOptions
	uid     uint32
	// sysctlRoot is /proc/sys.
	sysctlRoot string
	// installed is what the last Replace installed; nil before one, after
	// Clear, and after a failed one.
	installed *installedExit
}

// validMarkSetting makes the reverse path check of packets from outside use
// their mark, as wg-quick does: a connection opened from outside is checked
// against the main table, never the exit table, so the host stays reachable
// also while the TUN is gone and the exit table holds only unreachable.
const validMarkSetting = "net/ipv4/conf/all/src_valid_mark"

func newKernelExitRouteConfigurer(options RoutedOptions, uid uint32) *kernelExitRouteConfigurer {
	return &kernelExitRouteConfigurer{options: options, uid: uid, sysctlRoot: "/proc/sys"}
}

// exitSubnet is an attached subnet kept out of the mesh, and its interface.
type exitSubnet struct {
	prefix netip.Prefix
	link   int
}

// exitHost is what the exit route follows of the host: the mesh interface,
// the other interfaces sockets may bind to, the local bridges without a
// physical port (containers, VMs) and their subnets, and the private
// subnets attached to the other interfaces.
type exitHost struct {
	meshIndex  int
	interfaces []string
	bridges    []string
	bridged    []exitSubnet
	lan        []exitSubnet
	// own are the host's addresses outside the mesh: replies from them
	// (to connections opened from outside, pings) leave by the host's
	// own routes, also while the TUN is gone.
	own []netip.Addr
}

// localBridgePorts are the kinds of bridge port that never reach another
// machine: a bridge with only these (containers, VMs) is local, one with any
// other port (a NIC, a bond, a VLAN) is a LAN.
var localBridgePorts = []string{"veth", "tuntap", "dummy"}

// readExitHost reads the host's interfaces and their addresses; meshIndex
// is -1 while the mesh interface name does not exist.
func readExitHost(name string) (exitHost, error) {
	links, err := dumped(netlink.LinkList)
	if err != nil {
		return exitHost{}, fmt.Errorf("listing interfaces: %w", err)
	}
	host := exitHost{meshIndex: -1}
	physicalPort := map[int]bool{}
	for _, link := range links {
		attributes := link.Attrs()
		if attributes == nil {
			continue
		}
		if name != "" && attributes.Name == name {
			host.meshIndex = attributes.Index
		}
		if attributes.MasterIndex > 0 && !slices.Contains(localBridgePorts, link.Type()) {
			physicalPort[attributes.MasterIndex] = true
		}
	}
	bridgeIndex := map[int]bool{}
	for _, link := range links {
		attributes := link.Attrs()
		if attributes == nil || attributes.Index == host.meshIndex || attributes.Flags&net.FlagLoopback != 0 ||
			attributes.MasterIndex > 0 || !validSysctlInterface(attributes.Name) {
			continue
		}
		if link.Type() == "bridge" && !physicalPort[attributes.Index] {
			bridgeIndex[attributes.Index] = true
			host.bridges = append(host.bridges, attributes.Name)
		}
		host.interfaces = append(host.interfaces, attributes.Name)
	}
	addresses, err := dumped(func() ([]netlink.Addr, error) { return netlink.AddrList(nil, netlink.FAMILY_ALL) })
	if err != nil {
		return exitHost{}, fmt.Errorf("listing addresses: %w", err)
	}
	for _, address := range addresses {
		if address.IPNet == nil || address.LinkIndex == host.meshIndex {
			continue
		}
		prefix, ok := netipPrefix(address.IPNet)
		if !ok || prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() && prefix.Addr().Is6() {
			continue // IPv6 link-local sockets name their interface
		}
		own, valid := netip.AddrFromSlice(address.IP)
		if valid && len(host.own) < maximumExitInterfaces {
			// The address itself: prefix holds the subnet it is in.
			host.own = append(host.own, own.Unmap())
		}
		subnet := exitSubnet{prefix: prefix, link: address.LinkIndex}
		if bridgeIndex[address.LinkIndex] {
			host.bridged = append(host.bridged, subnet)
		} else if ExitLANSubnet(prefix) {
			host.lan = append(host.lan, subnet)
		}
	}
	host.interfaces = boundedSorted(host.interfaces, maximumExitInterfaces)
	host.bridges = boundedSorted(host.bridges, maximumExitInterfaces)
	host.bridged = uniqueSubnets(host.bridged)
	host.lan = uniqueSubnets(host.lan)
	return host, nil
}

func boundedSorted(names []string, maximum int) []string {
	slices.Sort(names)
	names = slices.Compact(names)
	return names[:min(len(names), maximum)]
}

// uniqueSubnets keeps the first interface of each subnet, at most
// maximumExitSubnets, sorted.
func uniqueSubnets(subnets []exitSubnet) []exitSubnet {
	slices.SortStableFunc(subnets, func(first, second exitSubnet) int {
		return compareRoutedPrefixes(first.prefix, second.prefix)
	})
	subnets = slices.CompactFunc(subnets, func(first, second exitSubnet) bool { return first.prefix == second.prefix })
	return subnets[:min(len(subnets), maximumExitSubnets)]
}

// Stamp identifies the interfaces and subnets the exit route follows.
func (configurer *kernelExitRouteConfigurer) Stamp(name string) string {
	host, err := readExitHost(name)
	if err != nil {
		return "unknown"
	}
	return fmt.Sprintf("%d %v %v %v %v", host.meshIndex, host.interfaces, host.bridges, host.bridged, host.lan)
}

// Replace installs the kill switch first, then the exit table, then its
// rules, the one sending everything but meshd into the table last: no
// packet ever meets the table half built, and none leaves outside the mesh
// but by the kill switch's exceptions.
func (configurer *kernelExitRouteConfigurer) Replace(name string, ipv6, allowLAN bool, window *exitCaptive) (
	string, error,
) {
	configurer.installed = nil
	host, err := readExitHost(name)
	if err != nil {
		return "", err
	}
	holes, err := readCaptiveHoles(host.meshIndex, window)
	if err != nil {
		return "", err
	}
	ruleset := exitKillSwitch{
		Table: configurer.options.ExitNftTable, Interface: name, UID: configurer.uid,
		Inner: append([]string{"lo"}, host.bridges...), Captive: holes,
	}
	if name != "" {
		ruleset.Inner = append(ruleset.Inner, name)
	}
	var lan []exitSubnet
	if allowLAN {
		lan = host.lan
		for _, subnet := range lan {
			ruleset.LAN = append(ruleset.LAN, subnet.prefix)
		}
		ruleset.LAN = append(ruleset.LAN, ExitLANMulticast...)
	}
	nftRules, err := replaceExitKillSwitch(ruleset)
	if err != nil {
		return "", err
	}
	if err := configurer.validateMarks(); err != nil {
		return "", err
	}
	routes, err := replaceExitTable(configurer.options.ExitTable, host, lan, ipv6)
	if err != nil {
		return "", err
	}
	rules := exitRules(configurer.options, configurer.uid, host.interfaces, host.own)
	rules = append(rules, captiveRouteRules(configurer.options.ExitPriority+2, holes)...)
	if err := replaceRulesAt(configurer.options.ExitPriority, exitRulePriorities, rules); err != nil {
		return "", err
	}
	configurer.installed = &installedExit{
		rules: rules, routes: routes, nftRules: nftRules, lan: ruleset.LAN, captive: captiveKeys(holes),
	}
	return holes.openedName(), nil
}

// readCaptiveHoles finds where a window opens: in each family, the interface
// of the main table's default route with the lowest metric (where the
// host's own packets to the Internet would go without the exit node), other
// than the mesh's, and its addresses but link-local ones. Nil without a
// window.
func readCaptiveHoles(meshIndex int, window *exitCaptive) (*captiveHoles, error) {
	if window == nil {
		return nil, nil
	}
	holes := &captiveHoles{portals: window.Portals, remaining: window.Remaining}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := dumped(func() ([]netlink.Route, error) {
			return netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
		})
		if familyUnsupported(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("listing default routes: %w", err)
		}
		best := -1
		for index, route := range routes {
			prefix, ok := netipPrefix(route.Dst)
			if (route.Dst != nil && (!ok || prefix.Bits() != 0)) || route.Type != unix.RTN_UNICAST ||
				route.LinkIndex <= 0 || route.LinkIndex == meshIndex {
				continue
			}
			if best < 0 || route.Priority < routes[best].Priority {
				best = index
			}
		}
		if best < 0 {
			continue
		}
		link, err := netlink.LinkByIndex(routes[best].LinkIndex)
		if err != nil {
			return nil, fmt.Errorf("reading the default route's interface: %w", err)
		}
		addresses, err := dumped(func() ([]netlink.Addr, error) { return netlink.AddrList(link, family) })
		if err != nil {
			return nil, fmt.Errorf("listing the default route's addresses: %w", err)
		}
		opening := captiveOpening{name: link.Attrs().Name}
		for _, address := range addresses {
			own, ok := netip.AddrFromSlice(address.IP)
			own = own.Unmap()
			if ok && !own.IsLinkLocalUnicast() && !own.IsLoopback() && len(opening.addresses) < maximumCaptiveAddresses {
				opening.addresses = append(opening.addresses, own)
			}
		}
		if len(opening.addresses) != 0 && validHostInterfaceName(opening.name) {
			holes.openings = append(holes.openings, opening)
		}
	}
	return holes, nil
}

// openedName is the interface a window opens, IPv4's first; empty without
// one.
func (holes *captiveHoles) openedName() string {
	if holes == nil || len(holes.openings) == 0 {
		return ""
	}
	return holes.openings[0].name
}

// replaceExitTable makes the exit table hold exactly the unreachable
// defaults, the defaults into the mesh, and the routes that keep the local
// bridges' and allowed LAN subnets on their interfaces, and returns their
// keys (exitRouteKey). Routes are added before stale ones go, so the table
// is never empty.
func replaceExitTable(table int, host exitHost, lan []exitSubnet, ipv6 bool) (map[string]bool, error) {
	onLink := func(index int, destination *net.IPNet) *netlink.Route {
		return &netlink.Route{
			LinkIndex: index, Dst: destination, Table: table, Scope: netlink.SCOPE_LINK, Type: unix.RTN_UNICAST,
			Priority: exitRouteMetric,
		}
	}
	desired := []*netlink.Route{exitUnreachable(table, false), exitUnreachable(table, true)}
	if host.meshIndex >= 0 {
		desired = append(desired, onLink(host.meshIndex, defaultRoute(false)))
		if ipv6 {
			desired = append(desired, onLink(host.meshIndex, defaultRoute(true)))
		}
	}
	for _, subnet := range append(slices.Clone(host.bridged), lan...) {
		desired = append(desired, onLink(subnet.link, prefixIPNet(subnet.prefix.Masked())))
	}
	kept := map[string]bool{}
	for _, route := range desired {
		family := netlink.FAMILY_V4
		if route.Dst.IP.To4() == nil {
			family = netlink.FAMILY_V6
		}
		if err := netlink.RouteReplace(route); err != nil {
			if family == netlink.FAMILY_V6 && familyUnsupported(err) {
				continue // no IPv6 here: nothing of it can leak either
			}
			return nil, fmt.Errorf("adding exit route %s: %w", route.Dst, err)
		}
		kept[exitRouteKey(family, *route)] = true
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := dumped(func() ([]netlink.Route, error) {
			return netlink.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		})
		if familyUnsupported(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("listing exit routes: %w", err)
		}
		for index := range routes {
			if kept[exitRouteKey(family, routes[index])] {
				continue
			}
			if err := netlink.RouteDel(&routes[index]); err != nil && !errors.Is(err, unix.ESRCH) {
				return nil, fmt.Errorf("removing stale exit route: %w", err)
			}
		}
	}
	return kept, nil
}

func exitUnreachable(table int, ipv6 bool) *netlink.Route {
	return &netlink.Route{
		Dst: defaultRoute(ipv6), Table: table, Type: unix.RTN_UNREACHABLE, Priority: exitUnreachableMetric,
	}
}

func defaultRoute(ipv6 bool) *net.IPNet {
	if ipv6 {
		return &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	}
	return &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}
}

// exitRouteKey identifies a route of the exit table by what makes it
// distinct: its family, destination, type, interface and metric. The
// kernel lists a default route with no destination, and puts an IPv6
// unreachable route on the loopback interface, so neither counts.
func exitRouteKey(family int, route netlink.Route) string {
	destination := "default"
	if route.Dst != nil {
		if prefix, ok := netipPrefix(route.Dst); ok && prefix.Bits() != 0 {
			destination = prefix.String()
		}
	}
	link := route.LinkIndex
	if route.Type == unix.RTN_UNREACHABLE {
		link = 0
	}
	return fmt.Sprintf("%d %s %d %d %d", family, destination, route.Type, link, route.Priority)
}

// exitRules are, per family: replies to connections opened from outside
// (by their mark, or by the host's own source address), DHCP and sockets
// bound to one of interfaces follow the main table; then everything but
// meshd looks up the exit table. A packet that picks a host address as its
// source on purpose also follows the main table, where the kill switch
// drops it.
func exitRules(options RoutedOptions, uid uint32, interfaces []string, own []netip.Addr) []*netlink.Rule {
	var rules []*netlink.Rule
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		mask := exitInboundMark
		inbound := netlink.NewRule()
		inbound.Family, inbound.Priority, inbound.Table = family, options.ExitPriority, unix.RT_TABLE_MAIN
		inbound.Mark, inbound.Mask = exitInboundMark, &mask
		dhcp := netlink.NewRule()
		dhcp.Family, dhcp.Priority, dhcp.Table = family, options.ExitPriority+1, unix.RT_TABLE_MAIN
		dhcp.IPProto = unix.IPPROTO_UDP
		dhcp.Sport, dhcp.Dport = netlink.NewRulePortRange(68, 68), netlink.NewRulePortRange(67, 67)
		if family == unix.AF_INET6 {
			dhcp.Sport, dhcp.Dport = netlink.NewRulePortRange(546, 546), netlink.NewRulePortRange(547, 547)
		}
		rules = append(rules, inbound, dhcp)
		for _, address := range own {
			if address.Is4() != (family == unix.AF_INET) {
				continue
			}
			fromOwn := netlink.NewRule()
			fromOwn.Family, fromOwn.Priority, fromOwn.Table = family, options.ExitPriority, unix.RT_TABLE_MAIN
			fromOwn.Src = prefixIPNet(netip.PrefixFrom(address, address.BitLen()))
			rules = append(rules, fromOwn)
		}
		for _, name := range interfaces {
			bound := netlink.NewRule()
			bound.Family, bound.Priority, bound.Table = family, options.ExitPriority+2, unix.RT_TABLE_MAIN
			bound.OifName = name
			rules = append(rules, bound)
		}
		everything := netlink.NewRule()
		everything.Family, everything.Priority, everything.Table = family, options.ExitPriority+3, options.ExitTable
		everything.UIDRange, everything.Invert = netlink.NewRuleUIDRange(uid, uid), true
		rules = append(rules, everything)
	}
	return rules
}

// replaceRulesAt makes the count priorities from first hold exactly rules,
// which are in priority order: each is added before the stale ones at its
// priority go, and the last priority's last.
func replaceRulesAt(first, count int, rules []*netlink.Rule) error {
	for priority := first; priority < first+count; priority++ {
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			var wanted []*netlink.Rule
			for _, rule := range rules {
				if rule.Priority == priority && rule.Family == family {
					wanted = append(wanted, rule)
				}
			}
			if err := replaceRulesOf(family, priority, wanted); err != nil {
				return err
			}
		}
	}
	return nil
}

func replaceRulesOf(family, priority int, wanted []*netlink.Rule) error {
	installed, err := dumped(func() ([]netlink.Rule, error) {
		return netlink.RuleListFiltered(family, &netlink.Rule{Priority: priority}, netlink.RT_FILTER_PRIORITY)
	})
	if familyUnsupported(err) && family == unix.AF_INET6 {
		return nil // no IPv6 here: no IPv6 rule is needed
	}
	if err != nil {
		return fmt.Errorf("listing exit policy rules: %w", err)
	}
	// The kernel deletes the first rule at the priority that has every
	// attribute of the one named, so a stale rule with fewer (another
	// program's "lookup main") takes one of the wanted rules instead: each
	// round adds what is missing, then deletes one stale rule, until none
	// is left. Wanted rules are added before anything goes.
	for range len(installed) + len(wanted) + 2 {
		for _, rule := range wanted {
			if slices.ContainsFunc(installed, func(other netlink.Rule) bool { return sameExitRule(other, *rule) }) {
				continue
			}
			if err := netlink.RuleAdd(rule); err != nil {
				return fmt.Errorf("adding exit policy rule %d: %w", rule.Priority, err)
			}
		}
		installed, err = dumped(func() ([]netlink.Rule, error) {
			return netlink.RuleListFiltered(family, &netlink.Rule{Priority: priority}, netlink.RT_FILTER_PRIORITY)
		})
		if err != nil {
			return fmt.Errorf("listing exit policy rules: %w", err)
		}
		stale := slices.IndexFunc(installed, func(rule netlink.Rule) bool {
			return !slices.ContainsFunc(wanted, func(other *netlink.Rule) bool { return sameExitRule(rule, *other) })
		})
		if stale < 0 {
			return nil
		}
		if err := netlink.RuleDel(&installed[stale]); err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("removing stale exit policy rule %d: %w", priority, err)
		}
		installed, err = dumped(func() ([]netlink.Rule, error) {
			return netlink.RuleListFiltered(family, &netlink.Rule{Priority: priority}, netlink.RT_FILTER_PRIORITY)
		})
		if err != nil {
			return fmt.Errorf("listing exit policy rules: %w", err)
		}
	}
	return fmt.Errorf("exit policy rules at %d keep changing", priority)
}

// sameExitRule compares what the exit rules set.
func sameExitRule(installed, wanted netlink.Rule) bool {
	sameMask := (installed.Mask == nil) == (wanted.Mask == nil) &&
		(installed.Mask == nil || *installed.Mask == *wanted.Mask)
	samePorts := func(first, second *netlink.RulePortRange) bool {
		return (first == nil) == (second == nil) && (first == nil || *first == *second)
	}
	sameUIDs := (installed.UIDRange == nil) == (wanted.UIDRange == nil) &&
		(installed.UIDRange == nil || *installed.UIDRange == *wanted.UIDRange)
	samePrefix := func(first, second *net.IPNet) bool {
		return (first == nil) == (second == nil) && (first == nil || first.String() == second.String())
	}
	return installed.Table == wanted.Table && installed.Mark == wanted.Mark && sameMask &&
		samePrefix(installed.Src, wanted.Src) && samePrefix(installed.Dst, wanted.Dst) &&
		installed.IPProto == wanted.IPProto && samePorts(installed.Sport, wanted.Sport) &&
		samePorts(installed.Dport, wanted.Dport) && strings.TrimRight(installed.OifName, "\x00") == wanted.OifName &&
		strings.TrimRight(installed.IifName, "\x00") == wanted.IifName && installed.Invert == wanted.Invert && sameUIDs
}

// validMarkRecord is where the helper keeps src_valid_mark as it was before
// it turned it on, next to its router state in its runtime directory, so a
// helper that crashed, or meshnetd --release-exit, puts it back; the file
// goes with a reboot, as the setting does. Empty without a state path.
func validMarkRecord(options RoutedOptions) string {
	if options.StatePath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(options.StatePath), "exit-valid-mark")
}

// validateMarks turns src_valid_mark on, recording what it was first.
func (configurer *kernelExitRouteConfigurer) validateMarks() error {
	path := filepath.Join(configurer.sysctlRoot, validMarkSetting)
	current, err := readSysctl(path)
	if err != nil {
		return err
	}
	if current == "1" {
		return nil
	}
	if record := validMarkRecord(configurer.options); record != "" {
		// Best effort: without the record only a crashed helper leaves the
		// setting on, as wg-quick always does.
		_ = os.WriteFile(record, []byte(current), 0o600)
	}
	return writeSysctl(path, "1")
}

// restoreValidMark puts src_valid_mark back as recorded, unless someone
// changed it since.
func restoreValidMark(options RoutedOptions, sysctlRoot string) {
	record := validMarkRecord(options)
	if record == "" {
		return
	}
	previous, err := os.ReadFile(record) //nolint:gosec // G304: the helper's own runtime file
	if err != nil {
		return
	}
	if value := strings.TrimSpace(string(previous)); value == "0" || value == "2" {
		restoreSysctl(filepath.Join(sysctlRoot, validMarkSetting), "1", value)
	}
	_ = os.Remove(record)
}

// Present reports whether the kill switch is installed and, after a
// Replace, whether the kernel still holds what it installed.
func (configurer *kernelExitRouteConfigurer) Present() (bool, error) {
	present, err := servedTablePresent(configurer.options.ExitNftTable)
	if err != nil || !present || configurer.installed == nil {
		return present, err
	}
	return configurer.installed.intact(configurer.options)
}

// Clear removes the rule into the exit table first, then the other rules
// and the table's routes, and the kill switch last, whatever a previous run
// left: the priorities, table and nftables table are this helper's alone.
func (configurer *kernelExitRouteConfigurer) Clear() error {
	configurer.installed = nil
	return clearExitRoute(configurer.options)
}

func clearExitRoute(options RoutedOptions) error {
	var failures []error
	for priority := options.ExitPriority + exitRulePriorities - 1; priority >= options.ExitPriority; priority-- {
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			if err := replaceRulesOf(family, priority, nil); err != nil {
				failures = append(failures, err)
			}
		}
	}
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := dumped(func() ([]netlink.Route, error) {
			return netlink.RouteListFiltered(family, &netlink.Route{Table: options.ExitTable}, netlink.RT_FILTER_TABLE)
		})
		if familyUnsupported(err) {
			continue
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("listing exit routes: %w", err))
			continue
		}
		for index := range routes {
			if err := netlink.RouteDel(&routes[index]); err != nil && !errors.Is(err, unix.ESRCH) {
				failures = append(failures, fmt.Errorf("removing exit route: %w", err))
			}
		}
	}
	if len(failures) != 0 {
		// The kill switch stays while anything of the route may remain.
		return errors.Join(failures...)
	}
	if err := deleteServedTable(options.ExitNftTable); err != nil {
		return err
	}
	restoreValidMark(options, "/proc/sys")
	return nil
}

// ReleaseExitRoute removes what a helper with options installed to route
// the host through an exit node, as root does when that helper is gone and
// its kill switch keeps the host offline (exit node design §6.4).
func ReleaseExitRoute(options RoutedOptions) error {
	if options.ExitTable == 0 || !validExitRouteOptions(options) {
		return errors.New("netadmin: exit route options are invalid")
	}
	if err := clearExitRoute(options); err != nil {
		return err
	}
	if options.CaptiveWindowPath != "" {
		return captive.CloseWindow(options.CaptiveWindowPath)
	}
	return nil
}
