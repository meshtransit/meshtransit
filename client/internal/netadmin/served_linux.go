//go:build linux

package netadmin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"meshtransit.net/client/internal/overlayframe"
	"meshtransit.net/client/internal/routesettings"
)

// ReasonNoRoute refuses a served prefix the host has no route to outside
// the mesh (health no_route).
const ReasonNoRoute = "no_route"

// kernelServedConfigurer forwards into served prefixes: IPv4 forwarding on
// the TUN and the interfaces towards the Sites only, IPv6 forwarding for the
// host when a Site needs it, and one nftables table that keeps forwarding to
// the mesh's traffic (design §8.1, §8.2).
type kernelServedConfigurer struct {
	table string
	// statePath records the forwarding settings changed and their previous
	// values before they change, so even a helper that crashed restores
	// them when it starts again.
	statePath  string
	sysctlRoot string
	// installed identifies the ruleset last installed, so a refresh that
	// changes nothing leaves the table as it is.
	installed string
	// forwarding are the interfaces forwarding was last needed on, and
	// hostIPv6 whether host-wide IPv6 forwarding was.
	forwarding []string
	hostIPv6   bool
	// tunIndex is the TUN the self-test addresses are routed into.
	tunIndex int
}

// selfTestRouteProtocol marks the helper's own self-test routes, so it
// never replaces or removes a route an administrator added for the same
// address (a private rtnetlink protocol value).
const selfTestRouteProtocol = netlink.RouteProtocol(0xb4)

// forwardingState holds the previous values of the host settings the helper
// changed.
type forwardingState struct {
	IPv4Forwarding map[string]string `json:"ipv4_forwarding,omitempty"`
	IPv6Forwarding string            `json:"ipv6_forwarding,omitempty"`
	AcceptRA       map[string]string `json:"accept_ra,omitempty"`
}

func newKernelServedConfigurer(options RoutedOptions) *kernelServedConfigurer {
	return &kernelServedConfigurer{table: options.NftTable, statePath: options.StatePath, sysctlRoot: "/proc/sys"}
}

// ReplaceServed forwards into entries and returns those it serves; one the
// host has no route to outside the mesh is refused.
func (configurer *kernelServedConfigurer) ReplaceServed(name string, self []netip.Prefix, mtu int,
	entries []routesettings.ServedEntry,
) ([]routesettings.ServedEntry, []routesettings.Refusal, error) {
	if len(entries) == 0 {
		return nil, nil, configurer.Clear()
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, nil, fmt.Errorf("finding tun link for served routes: %w", err)
	}
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 || link.Type() != "tuntap" {
		return nil, nil, errors.New("served route interface is invalid")
	}
	served, refused, egress, ipv6 := routableEntries(entries, link.Attrs().Index)
	if len(served) == 0 {
		return nil, refused, configurer.Clear()
	}
	state, err := configurer.loadState()
	if err != nil {
		return nil, nil, err
	}
	interfaces := append([]string{name}, egress...)
	if err := configurer.forward(&state, interfaces, ipv6); err != nil {
		return nil, nil, err
	}
	// Diagnostic only: a self-test route that cannot be installed never
	// stops forwarding, Problems reports it.
	routeSelfTest(link.Attrs().Index, ipv6)
	configurer.tunIndex = link.Attrs().Index
	ruleset := servedRuleset{
		Table: configurer.table, Interface: name, Self: self, MTU: mtu,
		GuardIPv6: state.IPv6Forwarding != "",
	}
	for _, entry := range served {
		ruleset.Served = append(ruleset.Served, entry.Prefix)
		if entry.Masquerade {
			ruleset.Masquerade = append(ruleset.Masquerade, entry.Prefix)
		}
	}
	for _, guarded := range slices.Sorted(maps.Keys(state.IPv4Forwarding)) {
		if guarded != name {
			ruleset.Guarded = append(ruleset.Guarded, guarded)
		}
	}
	fingerprint := fmt.Sprintf("%+v", ruleset)
	if present, err := configurer.Present(); err != nil || !present || fingerprint != configurer.installed {
		configurer.installed = ""
		if err := replaceServedTable(ruleset); err != nil {
			return nil, nil, err
		}
		configurer.installed = fingerprint
	}
	configurer.forwarding, configurer.hostIPv6 = interfaces, ipv6
	return served, refused, nil
}

// selfTestRoutes are the host routes that bring answers to the self-test
// addresses back into the TUN at index instead of out by the default route.
func selfTestRoutes(index int) []*netlink.Route {
	return []*netlink.Route{
		{
			LinkIndex: index, Dst: prefixIPNet(netip.PrefixFrom(overlayframe.SelfTestIPv4, 32)), Scope: netlink.SCOPE_LINK,
			Protocol: selfTestRouteProtocol,
		},
		{
			LinkIndex: index, Dst: prefixIPNet(netip.PrefixFrom(overlayframe.SelfTestIPv6, 128)), Scope: netlink.SCOPE_LINK,
			Protocol: selfTestRouteProtocol,
		},
	}
}

// routeSelfTest routes the self-test addresses into the TUN at index, the
// IPv6 one only while a Site is IPv6, unless another route for them exists.
func routeSelfTest(index int, ipv6 bool) {
	routes := selfTestRoutes(index)
	ensureSelfTestRoute(routes[0])
	if ipv6 {
		ensureSelfTestRoute(routes[1])
	} else {
		removeSelfTestRoute(routes[1])
	}
}

// selfTestRoutesOf lists the main table's routes to route's destination.
func selfTestRoutesOf(route *netlink.Route) ([]netlink.Route, error) {
	family := netlink.FAMILY_V4
	if route.Dst.IP.To4() == nil {
		family = netlink.FAMILY_V6
	}
	return netlink.RouteListFiltered(family, &netlink.Route{Dst: route.Dst, Table: unix.RT_TABLE_MAIN},
		netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
}

// ensureSelfTestRoute installs route unless a route the helper does not own
// exists for its destination.
func ensureSelfTestRoute(route *netlink.Route) {
	existing, err := selfTestRoutesOf(route)
	if err != nil || slices.ContainsFunc(existing, func(other netlink.Route) bool {
		return other.Protocol != selfTestRouteProtocol
	}) {
		return
	}
	_ = netlink.RouteReplace(route)
}

// removeSelfTestRoute deletes the helper's own routes to route's
// destination, and no other.
func removeSelfTestRoute(route *netlink.Route) {
	existing, err := selfTestRoutesOf(route)
	if err != nil {
		return
	}
	for _, other := range existing {
		if other.Protocol == selfTestRouteProtocol {
			_ = netlink.RouteDel(&other)
		}
	}
}

// selfTestRouted reports whether the IPv4 self-test address, and the IPv6
// one when a Site is IPv6, are routed into the TUN by the helper's routes.
func (configurer *kernelServedConfigurer) selfTestRouted() bool {
	routes := selfTestRoutes(configurer.tunIndex)
	wanted := routes[:1]
	if configurer.hostIPv6 {
		wanted = routes
	}
	for _, route := range wanted {
		existing, err := selfTestRoutesOf(route)
		if err != nil || len(existing) != 1 || existing[0].Protocol != selfTestRouteProtocol ||
			existing[0].LinkIndex != configurer.tunIndex {
			return false
		}
	}
	return true
}

// Problems reports a missing table and forwarding something turned off.
func (configurer *kernelServedConfigurer) Problems() []string {
	if configurer.installed == "" {
		return nil
	}
	var problems []string
	if present, err := configurer.Present(); err != nil || !present {
		problems = append(problems, ProblemRulesMissing)
	}
	off := false
	for _, name := range configurer.forwarding {
		value, err := readSysctl(configurer.sysctl("net/ipv4/conf", name, "forwarding"))
		if err == nil && value != "1" {
			off = true
		}
	}
	if configurer.hostIPv6 {
		if value, err := readSysctl(configurer.sysctl("net/ipv6/conf", "all", "forwarding")); err == nil && value != "1" {
			off = true
		}
	}
	if off {
		problems = append(problems, ProblemForwardingOff)
	}
	if !configurer.selfTestRouted() {
		problems = append(problems, ProblemSelfTestUnrouted)
	}
	return problems
}

// SelfTestPackets reads the table's self-test counter.
func (configurer *kernelServedConfigurer) SelfTestPackets() (uint64, bool) {
	if configurer.installed == "" {
		return 0, false
	}
	packets, err := readSelfTestCounter(configurer.table)
	return packets, err == nil
}

// Conntrack reads the kernel's connection tracking use.
func (configurer *kernelServedConfigurer) Conntrack() (int, int) {
	count, countErr := readSysctl(filepath.Join(configurer.sysctlRoot, "net/netfilter/nf_conntrack_count"))
	maximum, maximumErr := readSysctl(filepath.Join(configurer.sysctlRoot, "net/netfilter/nf_conntrack_max"))
	used, usedErr := strconv.Atoi(count)
	limit, limitErr := strconv.Atoi(maximum)
	if errors.Join(countErr, maximumErr, usedErr, limitErr) != nil || used < 0 || limit <= 0 {
		return 0, 0
	}
	return used, limit
}

// routableEntries keeps the entries the host routes outside the mesh, with
// the interfaces those routes leave by, and whether any is IPv6.
func routableEntries(entries []routesettings.ServedEntry, meshIndex int) (
	[]routesettings.ServedEntry, []routesettings.Refusal, []string, bool,
) {
	var served []routesettings.ServedEntry
	var refused []routesettings.Refusal
	var egress []string
	ipv6 := false
	for _, entry := range entries {
		routes, err := netlink.RouteGet(entry.Prefix.Addr().AsSlice())
		if err != nil || len(routes) == 0 || routes[0].LinkIndex <= 0 || routes[0].LinkIndex == meshIndex {
			refused = append(refused, routesettings.Refusal{Prefix: entry.Prefix, Reason: ReasonNoRoute})
			continue
		}
		out, err := netlink.LinkByIndex(routes[0].LinkIndex)
		// The host's own addresses are no Site to forward into.
		if err != nil || out.Attrs() == nil || !validSysctlInterface(out.Attrs().Name) ||
			routes[0].Type == unix.RTN_LOCAL || out.Attrs().Flags&net.FlagLoopback != 0 {
			refused = append(refused, routesettings.Refusal{Prefix: entry.Prefix, Reason: ReasonNoRoute})
			continue
		}
		served = append(served, entry)
		if entry.Prefix.Addr().Is4() {
			egress = append(egress, out.Attrs().Name)
		} else {
			ipv6 = true
		}
	}
	slices.Sort(egress)
	return served, refused, slices.Compact(egress), ipv6
}

// forward turns IPv4 forwarding on for interfaces (the kernel checks the
// interface a packet arrives on, so the TUN and the way back both need it)
// and IPv6 forwarding for the host when ipv6, which the kernel only offers
// host-wide. Settings no longer needed get their previous values back.
func (configurer *kernelServedConfigurer) forward(state *forwardingState, interfaces []string, ipv6 bool) error {
	for _, name := range interfaces {
		path := configurer.sysctl("net/ipv4/conf", name, "forwarding")
		current, err := readSysctl(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue // gone since its route was read: the next apply refuses its prefixes
		}
		if err != nil {
			return err
		}
		if _, recorded := state.IPv4Forwarding[name]; recorded {
			// Something reset it, such as a network manager: set it again.
			if current != "1" {
				if err := writeSysctl(path, "1"); err != nil {
					return err
				}
			}
			continue
		}
		if current == "1" {
			continue // already forwarding: not the helper's to guard or restore
		}
		if state.IPv4Forwarding == nil {
			state.IPv4Forwarding = map[string]string{}
		}
		state.IPv4Forwarding[name] = current
		if err := configurer.saveState(*state); err != nil {
			return err
		}
		if err := writeSysctl(path, "1"); err != nil {
			return err
		}
	}
	for _, name := range slices.Sorted(maps.Keys(state.IPv4Forwarding)) {
		if slices.Contains(interfaces, name) {
			continue
		}
		restoreSysctl(configurer.sysctl("net/ipv4/conf", name, "forwarding"), "1", state.IPv4Forwarding[name])
		delete(state.IPv4Forwarding, name)
	}
	if !ipv6 && state.IPv6Forwarding != "" {
		configurer.restoreIPv6(state)
	}
	// Saved before IPv6 changes anything, so the file never lists a
	// setting already restored.
	if err := configurer.saveState(*state); err != nil {
		return err
	}
	if ipv6 {
		return configurer.forwardIPv6(state)
	}
	return nil
}

// forwardIPv6 turns host-wide IPv6 forwarding on. A forwarding host ignores
// router advertisements unless accept_ra is 2, so interfaces taking their
// configuration from them keep it.
func (configurer *kernelServedConfigurer) forwardIPv6(state *forwardingState) error {
	all := configurer.sysctl("net/ipv6/conf", "all", "forwarding")
	if state.IPv6Forwarding != "" {
		// Already the helper's: set again what something reset.
		for name := range state.AcceptRA {
			path := configurer.sysctl("net/ipv6/conf", name, "accept_ra")
			if value, err := readSysctl(path); err == nil && value != "2" {
				if err := writeSysctl(path, "2"); err != nil {
					return err
				}
			}
		}
		if value, err := readSysctl(all); err != nil || value == "1" {
			return err
		}
		return writeSysctl(all, "1")
	}
	previous, err := readSysctl(all)
	if err != nil || previous == "1" {
		return err
	}
	state.IPv6Forwarding, state.AcceptRA = previous, map[string]string{}
	entries, err := os.ReadDir(filepath.Join(configurer.sysctlRoot, "net/ipv6/conf"))
	if err != nil {
		return fmt.Errorf("listing ipv6 interfaces: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "all" || name == "default" || !validSysctlInterface(name) {
			continue
		}
		if value, err := readSysctl(configurer.sysctl("net/ipv6/conf", name, "accept_ra")); err == nil && value == "1" {
			state.AcceptRA[name] = value
		}
	}
	if err := configurer.saveState(*state); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(state.AcceptRA)) {
		if err := writeSysctl(configurer.sysctl("net/ipv6/conf", name, "accept_ra"), "2"); err != nil {
			return err
		}
	}
	return writeSysctl(all, "1")
}

func (configurer *kernelServedConfigurer) restoreIPv6(state *forwardingState) {
	restoreSysctl(configurer.sysctl("net/ipv6/conf", "all", "forwarding"), "1", state.IPv6Forwarding)
	for name, previous := range state.AcceptRA {
		restoreSysctl(configurer.sysctl("net/ipv6/conf", name, "accept_ra"), "2", previous)
	}
	state.IPv6Forwarding, state.AcceptRA = "", nil
}

// Present reports whether the router table is still installed.
func (configurer *kernelServedConfigurer) Present() (bool, error) {
	return servedTablePresent(configurer.table)
}

// Clear removes the table and gives every setting the helper changed its
// previous value back, also those a previous run left.
func (configurer *kernelServedConfigurer) Clear() error {
	configurer.installed, configurer.forwarding, configurer.hostIPv6, configurer.tunIndex = "", nil, false, 0
	for _, route := range selfTestRoutes(0) {
		removeSelfTestRoute(route)
	}
	err := deleteServedTable(configurer.table)
	state, loadErr := configurer.loadState()
	if loadErr != nil {
		return errors.Join(err, loadErr)
	}
	for name, previous := range state.IPv4Forwarding {
		restoreSysctl(configurer.sysctl("net/ipv4/conf", name, "forwarding"), "1", previous)
	}
	if state.IPv6Forwarding != "" {
		configurer.restoreIPv6(&state)
	}
	if removeErr := os.Remove(configurer.statePath); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
		err = errors.Join(err, fmt.Errorf("removing router state: %w", removeErr))
	}
	return err
}

func (configurer *kernelServedConfigurer) sysctl(directory, name, setting string) string {
	return filepath.Join(configurer.sysctlRoot, directory, name, setting)
}

func (configurer *kernelServedConfigurer) loadState() (forwardingState, error) {
	content, err := os.ReadFile(configurer.statePath)
	if errors.Is(err, fs.ErrNotExist) {
		return forwardingState{}, nil
	}
	if err != nil {
		return forwardingState{}, fmt.Errorf("reading router state: %w", err)
	}
	var state forwardingState
	if err := json.Unmarshal(content, &state); err != nil || !state.valid() {
		// A damaged file restores nothing, but must not stop the helper:
		// kept aside for an administrator, it is replaced by a new one.
		if renameErr := os.Rename(configurer.statePath, configurer.statePath+".bad"); renameErr != nil {
			return forwardingState{}, fmt.Errorf("setting aside a damaged router state: %w", renameErr)
		}
		return forwardingState{}, nil
	}
	return state, nil
}

// valid accepts interface names safe as paths and the values the helper
// ever records.
func (state forwardingState) valid() bool {
	for name, value := range state.IPv4Forwarding {
		if !validSysctlInterface(name) || (value != "0" && value != "1") {
			return false
		}
	}
	for name, value := range state.AcceptRA {
		if !validSysctlInterface(name) || (value != "0" && value != "1" && value != "2") {
			return false
		}
	}
	return state.IPv6Forwarding == "" || state.IPv6Forwarding == "0" || state.IPv6Forwarding == "1"
}

// saveState writes the state atomically, readable by root only.
func (configurer *kernelServedConfigurer) saveState(state forwardingState) error {
	content, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary := configurer.statePath + ".tmp"
	if err := os.WriteFile(temporary, content, 0o600); err != nil {
		return fmt.Errorf("writing router state: %w", err)
	}
	if err := os.Rename(temporary, configurer.statePath); err != nil {
		return fmt.Errorf("writing router state: %w", err)
	}
	return nil
}

func readSysctl(path string) (string, error) {
	content, err := os.ReadFile(path) //nolint:gosec // G304: a fixed /proc/sys path for a validated interface
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	return strings.TrimSpace(string(content)), nil
}

func writeSysctl(path, value string) error {
	if err := os.WriteFile(path, []byte(value), 0o644); err != nil { //nolint:gosec // G306: a /proc/sys setting
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// restoreSysctl puts previous back unless someone changed the setting from
// what the helper set; an interface already gone needs nothing.
func restoreSysctl(path, set, previous string) {
	if current, err := readSysctl(path); err == nil && current == set {
		_ = writeSysctl(path, previous)
	}
}

// validSysctlInterface accepts a kernel interface name that is safe as one
// /proc/sys path element.
func validSysctlInterface(name string) bool {
	return name != "" && len(name) < 16 && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}
