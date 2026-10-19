//go:build linux

package netadmin

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type kernelRoutedConfigurer struct{}

// ReplaceRouted installs desired in the routed table on the interface, with
// the policy rule that keeps meshd out of it, removing current routes no
// longer desired. With nothing desired it clears the table and removes the
// rule, also when the interface is already gone.
func (configurer kernelRoutedConfigurer) ReplaceRouted(name string, options RoutedOptions, uid uint32,
	current, desired []netip.Prefix) error {
	if len(desired) == 0 {
		return configurer.Clear(options, uid)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("finding tun link for routed routes: %w", err)
	}
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 || link.Type() != "tuntap" {
		return errors.New("routed route target is invalid")
	}
	// The rule comes first: meshd's sockets must never see the table.
	if err := ensureRules(routedRules(options, uid)); err != nil {
		return err
	}
	return applyRouteDiff(current, desired, func(prefix netip.Prefix, add bool) error {
		route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixIPNet(prefix), Table: options.Table,
			Scope: netlink.SCOPE_LINK}
		if add {
			return netlink.RouteReplace(route)
		}
		if err := netlink.RouteDel(route); err != nil && !errors.Is(err, unix.ESRCH) {
			return err
		}
		return nil
	})
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
