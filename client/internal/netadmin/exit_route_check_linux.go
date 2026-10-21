package netadmin

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// installedExit is what Replace installed and Present checks the kernel
// still holds (exit_rule_tampered, exit node design §6.1.1): the rules at
// the exit priorities, the exit table's routes, and how many rules the kill
// switch has.
type installedExit struct {
	rules    []*netlink.Rule
	routes   map[string]bool
	nftRules int
	// lan are the subnets the kill switch lets through: its lan4 and lan6
	// sets must hold exactly their ranges.
	lan []netip.Prefix
	// captive are a captive portal window's holes by set, as elementKeys
	// names them: the sets hold no others (the kernel drops them as the
	// window ends).
	captive map[string][]string
}

// intact reports whether the kernel holds what installed records: every rule
// at the exit priorities and none other, the unreachable defaults and no
// route the helper did not add, and the kill switch with as many rules. A
// route the kernel removed with its interface is no change: Stamp applies
// the request again for that.
func (installed *installedExit) intact(options RoutedOptions) (bool, error) {
	count, err := nftRuleCount(options.ExitNftTable)
	if err != nil || count != installed.nftRules {
		return false, err
	}
	for _, set := range []struct {
		name string
		ipv4 bool
	}{{"lan4", true}, {"lan6", false}} {
		held, err := nftSetElements(options.ExitNftTable, set.name)
		if err != nil {
			return false, err
		}
		if !slices.Equal(held, elementKeys(intervalElements(installed.lan, set.ipv4))) {
			return false, nil // a range added to what the kill switch lets through
		}
	}
	for _, set := range []string{"captive4", "captive6", "portal4", "portal6"} {
		held, err := nftSetElements(options.ExitNftTable, set)
		if err != nil {
			return false, err
		}
		for _, key := range held {
			if !slices.Contains(installed.captive[set], key) {
				return false, nil // a hole no window opened
			}
		}
	}
	for priority := options.ExitPriority; priority < options.ExitPriority+exitRulePriorities; priority++ {
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			present, err := dumped(func() ([]netlink.Rule, error) {
				return netlink.RuleListFiltered(family, &netlink.Rule{Priority: priority}, netlink.RT_FILTER_PRIORITY)
			})
			if familyUnsupported(err) && family == unix.AF_INET6 {
				continue
			}
			if err != nil {
				return false, fmt.Errorf("listing exit policy rules: %w", err)
			}
			wanted := 0
			for _, rule := range installed.rules {
				if rule.Priority != priority || rule.Family != family {
					continue
				}
				wanted++
				if !slices.ContainsFunc(present, func(other netlink.Rule) bool { return sameExitRule(other, *rule) }) {
					return false, nil
				}
			}
			if len(present) != wanted {
				return false, nil
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
			return false, fmt.Errorf("listing exit routes: %w", err)
		}
		unreachable := false
		for _, route := range routes {
			key := exitRouteKey(family, route)
			if !installed.routes[key] {
				return false, nil // another program's route in the exit table
			}
			unreachable = unreachable || route.Type == unix.RTN_UNREACHABLE
		}
		if !unreachable {
			return false, nil
		}
	}
	return true, nil
}

// nftRuleCount counts the rules of the inet table name.
func nftRuleCount(name string) (int, error) {
	conn, err := nftables.New()
	if err != nil {
		return 0, fmt.Errorf("opening nftables: %w", err)
	}
	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: name}
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return 0, fmt.Errorf("listing kill switch chains: %w", err)
	}
	count := 0
	for _, chain := range chains {
		if chain.Table == nil || chain.Table.Name != name {
			continue
		}
		rules, err := conn.GetRules(table, chain)
		if err != nil {
			return 0, fmt.Errorf("listing kill switch rules: %w", err)
		}
		count += len(rules)
	}
	return count, nil
}

// nftSetElements returns the elements of set name in the inet table, as
// elementKeys does.
func nftSetElements(table, name string) ([]string, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("opening nftables: %w", err)
	}
	set, err := conn.GetSetByName(&nftables.Table{Family: nftables.TableFamilyINet, Name: table}, name)
	if err != nil {
		return nil, fmt.Errorf("reading kill switch set %s: %w", name, err)
	}
	elements, err := conn.GetSetElements(set)
	if err != nil {
		return nil, fmt.Errorf("reading kill switch set %s: %w", name, err)
	}
	return elementKeys(elements), nil
}

// elementKeys names each element by its key and whether it ends a range,
// sorted.
func elementKeys(elements []nftables.SetElement) []string {
	keys := make([]string, 0, len(elements))
	for _, element := range elements {
		keys = append(keys, fmt.Sprintf("%s/%t", hex.EncodeToString(element.Key), element.IntervalEnd))
	}
	slices.Sort(keys)
	return keys
}
