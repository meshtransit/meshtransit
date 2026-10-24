//go:build linux

package netadmin

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"slices"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"meshtransit.net/client/internal/routesettings"
)

// validPlatformRoutedOptions requires a table of the helper's own, its rule
// priority, to forward, an nftables table and a state file, and to use an
// exit node, its own table, rules and kill switch table.
func validPlatformRoutedOptions(options RoutedOptions) bool {
	return validRoutingTable(options.Table) && options.Priority > 0 && options.Priority < 32766 &&
		(options.NftTable == "" || (validNftTableName(options.NftTable) && filepath.IsAbs(options.StatePath))) &&
		validExitRouteOptions(options)
}

func validRoutingTable(table int) bool {
	// As int64: 1<<31 overflows int on 32-bit builds (TD-CLI-68).
	return table > 0 && int64(table) < 1<<31 && (table < 253 || table > 255)
}

// validExitRouteOptions requires, when the host may use an exit node, a
// table of its own, four rule priorities after the routed one, and a kill
// switch table other than the router's.
func validExitRouteOptions(options RoutedOptions) bool {
	if options.ExitTable == 0 {
		return options.ExitPriority == 0 && options.ExitNftTable == ""
	}
	return validRoutingTable(options.ExitTable) && options.ExitTable != options.Table &&
		options.ExitPriority > options.Priority && options.ExitPriority+exitRulePriorities <= 32766 &&
		validNftTableName(options.ExitNftTable) && options.ExitNftTable != options.NftTable
}

// validNftTableName accepts a short table name of letters, digits, '_' and
// '-'.
func validNftTableName(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	for _, character := range name {
		allowed := character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' ||
			character == '-'
		if !allowed {
			return false
		}
	}
	return true
}

type kernelRoutedConfigurer struct{}

// ReplaceRouted installs desired in the routed table on the interface, with
// the policy rule that keeps meshd out of it, and returns what is installed.
// It compares desired with the kernel's table, not with current, so a route
// removed behind the helper's back is installed again and anything else in
// the table is removed. A route the kernel refuses is reported, not fatal:
// the others stay. With nothing desired it clears the table and removes the
// rule, also when the interface is already gone.
func (configurer kernelRoutedConfigurer) ReplaceRouted(name string, options RoutedOptions, uid uint32,
	_, desired routedState,
) (routedState, []routesettings.Refusal, error) {
	if len(desired.Routes) == 0 {
		return routedState{}, nil, configurer.Clear(options, uid)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return routedState{}, nil, fmt.Errorf("finding tun link for routed routes: %w", err)
	}
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 || link.Type() != "tuntap" {
		return routedState{}, nil, errors.New("routed route target is invalid")
	}
	index := link.Attrs().Index
	// The rule comes first: meshd's sockets must never see the table.
	if err := ensureRules(routedRules(options, uid)); err != nil {
		return routedState{}, nil, err
	}
	installed, err := installedRouted(options.Table, index)
	if err != nil {
		return routedState{}, nil, err
	}
	throwRoute := func(prefix netip.Prefix) *netlink.Route {
		return &netlink.Route{Dst: prefixIPNet(prefix), Table: options.Table, Type: unix.RTN_THROW}
	}
	tunRoute := func(prefix netip.Prefix) *netlink.Route {
		return &netlink.Route{LinkIndex: index, Dst: prefixIPNet(prefix), Table: options.Table, Scope: netlink.SCOPE_LINK}
	}
	// Throws come before the routes that contain them and go after them, so
	// a resolver never follows a route into the mesh; a route whose resolver
	// could not be pinned is not installed.
	throws, throwRefusals := addRoutes(installed.Throws, desired.Throws, throwRoute)
	wanted, refused := withoutUnpinned(desired.Routes, throwRefusals)
	// Stale routes go before new ones are added: a route replaced by another
	// prefix leaves a gap of a few calls, but a failed add never has to undo
	// a removal.
	if err := removeRoutes(prefixDifference(installed.Routes, wanted), tunRoute); err != nil {
		return routedState{}, nil, err
	}
	routes, routeRefusals := addRoutes(installed.Routes, wanted, tunRoute)
	if err := removeRoutes(prefixDifference(installed.Throws, desired.Throws), throwRoute); err != nil {
		return routedState{}, nil, err
	}
	return routedState{Routes: routes, Throws: throws}, append(refused, routeRefusals...), nil
}

// installedRouted reads the routed table: routes on the interface and throw
// routes. Anything else there is removed: the table belongs to the helper.
func installedRouted(table, linkIndex int) (routedState, error) {
	var state routedState
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if familyUnsupported(err) {
			continue
		}
		if err != nil {
			return routedState{}, fmt.Errorf("listing routed routes: %w", err)
		}
		for index := range routes {
			route := &routes[index]
			prefix, ok := netipPrefix(route.Dst)
			switch {
			case ok && route.Type == unix.RTN_THROW:
				state.Throws = append(state.Throws, prefix)
			case ok && route.Type == unix.RTN_UNICAST && route.LinkIndex == linkIndex:
				state.Routes = append(state.Routes, prefix)
			default:
				if err := netlink.RouteDel(route); err != nil && !errors.Is(err, unix.ESRCH) {
					return routedState{}, fmt.Errorf("removing stray routed route: %w", err)
				}
			}
		}
	}
	return state, nil
}

// addRoutes installs each desired prefix not yet installed and returns the
// desired ones now installed, sorted; those the kernel refuses are reported.
func addRoutes(installed, desired []netip.Prefix, route func(netip.Prefix) *netlink.Route) (
	[]netip.Prefix, []routesettings.Refusal,
) {
	kept := prefixIntersection(desired, installed)
	var refused []routesettings.Refusal
	for _, prefix := range prefixDifference(desired, installed) {
		if err := netlink.RouteReplace(route(prefix)); err != nil {
			reason := routesettings.ReasonInstallFailed
			if familyUnsupported(err) {
				reason = routesettings.ReasonFamilyUnavailable
			}
			refused = append(refused, routesettings.Refusal{Prefix: prefix, Reason: reason})
			continue
		}
		kept = append(kept, prefix)
	}
	slices.SortFunc(kept, compareRoutedPrefixes)
	return kept, refused
}

// removeRoutes removes prefixes; one already gone is removed.
func removeRoutes(prefixes []netip.Prefix, route func(netip.Prefix) *netlink.Route) error {
	for _, prefix := range prefixes {
		if err := netlink.RouteDel(route(prefix)); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("removing routed route: %w", err)
		}
	}
	return nil
}

// maximumLocalRoutes bounds the host routes the checks compare against. A
// host with more, such as one holding a full Internet table, is no
// consumer the checks can keep safe cheaply: it installs no routes.
const maximumLocalRoutes = 16384

var errTooManyLocalRoutes = errors.New("too many local routes to check subnet routes against")

// resolverFiles hold the system resolvers: the host's, and the upstream
// servers systemd-resolved learned when it answers on a stub address.
var resolverFiles = []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"}

type kernelHostRouting struct{}

// LocalRoutes returns the main table's routes but default routes and those
// on the mesh interface; scope link routes are attached networks.
func (kernelHostRouting) LocalRoutes(meshInterface string) ([]LocalRoute, error) {
	meshIndex := -1
	if link, err := netlink.LinkByName(meshInterface); err == nil && link.Attrs() != nil {
		meshIndex = link.Attrs().Index
	}
	var local []LocalRoute
	tooMany := false
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		// Iterated rather than listed: a host with a full Internet table
		// stops at the bound instead of holding every route in memory.
		err := netlink.RouteListFilteredIter(family, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE,
			func(route netlink.Route) bool {
				if route.Dst == nil || route.LinkIndex == meshIndex {
					return true
				}
				prefix, ok := netipPrefix(route.Dst)
				if !ok || prefix.Bits() == 0 || prefix.Addr().IsLinkLocalUnicast() || prefix.Addr().IsMulticast() {
					return true
				}
				if len(local) == maximumLocalRoutes {
					tooMany = true
					return false
				}
				local = append(local, LocalRoute{Prefix: prefix, Connected: route.Scope == netlink.SCOPE_LINK})
				return true
			})
		if tooMany {
			return nil, errTooManyLocalRoutes
		}
		if familyUnsupported(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("listing local routes: %w", err)
		}
	}
	return local, nil
}

// Resolvers returns the nameservers of the system resolver files.
func (kernelHostRouting) Resolvers() []netip.Addr { return readResolvers(resolverFiles) }

func netipPrefix(network *net.IPNet) (netip.Prefix, bool) {
	address, ok := netip.AddrFromSlice(network.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	bits, _ := network.Mask.Size()
	return netip.PrefixFrom(address.Unmap(), bits).Masked(), true
}

// familyUnsupported reports an error a kernel without that address family
// (IPv6 disabled) answers: there is nothing of that family to keep or
// remove.
func familyUnsupported(err error) bool {
	return errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EOPNOTSUPP)
}

// Clear removes every route of the routed table and this helper's policy
// rule, whatever a previous run of the helper left: the table and rule
// belong to this helper alone.
func (kernelRoutedConfigurer) Clear(options RoutedOptions, uid uint32) error {
	var failures []error
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: options.Table}, netlink.RT_FILTER_TABLE)
		if familyUnsupported(err) {
			continue
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("listing routed routes: %w", err))
			continue
		}
		for index := range routes {
			if err := netlink.RouteDel(&routes[index]); err != nil && !errors.Is(err, unix.ESRCH) {
				failures = append(failures, fmt.Errorf("removing routed route: %w", err))
			}
		}
	}
	// The rule goes last: until the table is empty it keeps meshd out.
	return errors.Join(append(failures, removeRules(routedRules(options, uid)))...)
}

// routedRules are, for IPv4 and IPv6, one rule: every user but meshd's
// looks up the routed table at the configured priority. meshd's sockets
// skip it and follow the host's own policy routing unchanged.
func routedRules(options RoutedOptions, uid uint32) []*netlink.Rule {
	rules := make([]*netlink.Rule, 0, 2)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rule := netlink.NewRule()
		rule.Family, rule.Priority, rule.Table = family, options.Priority, options.Table
		rule.UIDRange, rule.Invert = netlink.NewRuleUIDRange(uid, uid), true
		rules = append(rules, rule)
	}
	return rules
}

func ensureRules(rules []*netlink.Rule) error {
	for _, rule := range rules {
		exists, err := ruleExists(rule)
		if familyUnsupported(err) && rule.Family == unix.AF_INET6 {
			continue // no IPv6 here: no IPv6 route can be installed either
		}
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if err := netlink.RuleAdd(rule); err != nil {
			return fmt.Errorf("adding routed policy rule %d: %w", rule.Priority, err)
		}
	}
	return nil
}

func removeRules(rules []*netlink.Rule) error {
	var failures []error
	for _, rule := range rules {
		exists, err := ruleExists(rule)
		if familyUnsupported(err) {
			continue
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if exists {
			if err := netlink.RuleDel(rule); err != nil {
				failures = append(failures, fmt.Errorf("removing routed policy rule %d: %w", rule.Priority, err))
			}
		}
	}
	return errors.Join(failures...)
}

// ruleExists reports whether this exact rule is installed: same priority,
// family, table, inversion and uid range.
func ruleExists(rule *netlink.Rule) (bool, error) {
	filter := &netlink.Rule{Priority: rule.Priority}
	installed, err := netlink.RuleListFiltered(rule.Family, filter, netlink.RT_FILTER_PRIORITY)
	if err != nil {
		return false, fmt.Errorf("listing routed policy rules: %w", err)
	}
	for _, other := range installed {
		if other.Table == rule.Table && other.Invert == rule.Invert && other.UIDRange != nil &&
			*other.UIDRange == *rule.UIDRange {
			return true, nil
		}
	}
	return false, nil
}
