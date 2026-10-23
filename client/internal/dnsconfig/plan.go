// Package dnsconfig compiles validated network maps into deterministic DNS
// plans without depending on a control-protocol or operating-system backend.
package dnsconfig

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"meshtransit.net/client/internal/networkmap"
)

var ErrInvalid = errors.New("dnsconfig: invalid plan")

const maxAddressesPerHost = 32

// sharedZone holds the share names of Cores that predate the configurable
// DNS suffix. One locally authoritative route covers all of them, so the
// number of shares never reaches the host's route limit, and an unknown
// shared name is answered NXDOMAIN instead of leaving for the host's
// resolvers. A current Core names shares under shared.<suffix>, which its
// own suffix route already covers.
const sharedZone = "shared.mesh"

// Plan is an immutable-by-convention DNS configuration ready for a local
// resolver and an operating-system configurator.
type Plan struct {
	Revision uint64
	Enabled  bool
	// Configured is a map that carries DNS, perhaps none at all: Core
	// leaves this Device's DNS to its host (DNS design D5b).
	Configured       bool
	DefaultResolvers []netip.AddrPort
	// Root is the root zone (DNS design D1b): every name no route holds goes
	// to its resolvers, with its failure mode. It is not among Routes, which
	// the host routes by domain.
	Root              *Route
	FallbackResolvers []netip.AddrPort
	Routes            []Route
	SearchDomains     []string
	Hosts             []Host
	// Aliases are the CNAMEs of names an administrator set (DNS design D2),
	// sorted by name.
	Aliases []Alias
	// Interior are the names, sorted, that only hold other names under a
	// route the node answers itself: they exist, so they get no data, not
	// NXDOMAIN (RFC 8020).
	Interior []string
	Reverse  []Reverse
	// IgnoredRoutes counts locally answered routes control sent for the
	// root, which would hide every name the host resolves elsewhere; they
	// are not installed.
	IgnoredRoutes int
	// Exit, while the node sends its Internet traffic through an exit node,
	// makes this resolver the host's default and sends every name it does
	// not answer or route to a private resolver to the exit node's DNS
	// forwarder (exit node design §7.1).
	Exit *ExitDNS
}

// ExitDNS is the DNS of the exit node in use.
type ExitDNS struct {
	// Resolvers are its forwarder's overlay addresses; empty while no exit
	// node carries the traffic: names are then answered SERVFAIL, never
	// asked of the host's own resolvers.
	Resolvers []netip.AddrPort
	// IPv6 is whether the exit node carries IPv6; otherwise AAAA questions
	// are answered with no data, so applications use IPv4 at once.
	IPv6 bool
}

// exitDNSPort is the port consumers ask the exit node's forwarder on.
const exitDNSPort = 53

// exitDNSOf returns the DNS of the exit node snapshot's local choice uses.
func exitDNSOf(snapshot networkmap.Snapshot) *ExitDNS {
	route := snapshot.ExitRoute
	if route == nil {
		return nil
	}
	exit := &ExitDNS{Resolvers: []netip.AddrPort{}, IPv6: route.IPv6}
	for _, address := range snapshot.ExitResolvers() {
		exit.Resolvers = append(exit.Resolvers, netip.AddrPortFrom(address, exitDNSPort))
	}
	return exit
}

// Route is one canonical suffix and its ordered resolver set. An empty
// Resolvers slice marks a locally authoritative suffix, unless Unavailable:
// a forward zone none of whose resolvers can be used now. FailOpen sends a
// forward zone's names to the host's own resolvers (the exit node's
// forwarder while one is in use) when no resolver answers or none can be
// used; otherwise they are answered SERVFAIL (DNS design D1 §5.3).
type Route struct {
	Suffix      string
	Resolvers   []netip.AddrPort
	Unavailable bool
	FailOpen    bool
}

// local reports whether the node answers the route's names itself.
func (route Route) local() bool { return len(route.Resolvers) == 0 && !route.Unavailable }

// RoutesAllNames reports a plan whose resolver answers every name the host
// has: a root zone, an exit node, or default resolvers. The host then sends
// it every name, whether the root zone can be used now or not, so a zone
// that fails closed never falls back to the host silently (DNS design D1b
// §4).
func (plan Plan) RoutesAllNames() bool {
	return plan.Root != nil || plan.Exit != nil || len(plan.DefaultResolvers) != 0
}

// Host groups all address records for one canonical DNS name.
type Host struct {
	Name      string
	Addresses []netip.Addr
}

// Alias is one CNAME: Name answers with Target.
type Alias struct {
	Name   string
	Target string
}

// hostZone reports a route of a zone that leaves the names it does not
// hold to the host (DNS design D2 §5.2), or of a forward zone that fails
// open with no resolver left: neither is routed to the node as a whole.
func (route Route) hostZone() bool {
	return route.Unavailable && route.FailOpen && len(route.Resolvers) == 0
}

// Reverse maps one address to its canonical name. The node derives them from
// the address records of its own Network's zone (the zone its own name is
// in): Core sends forward records only.
type Reverse struct {
	Address netip.Addr
	Name    string
}

// Compile turns one already-validated network snapshot into a deterministic,
// defensively-owned DNS plan. It rejects ambiguous local names and ensures
// every local record is covered by a locally authoritative route.
func Compile(snapshot networkmap.Snapshot) (Plan, error) {
	plan := Plan{Revision: snapshot.Revision, Exit: exitDNSOf(snapshot)}
	if snapshot.DNS == nil {
		plan.Enabled = plan.Exit != nil
		return plan, nil
	}

	config := snapshot.DNS
	plan.Configured = true
	plan.DefaultResolvers = resolverAddresses(config.Resolvers)
	plan.FallbackResolvers = resolverAddresses(config.FallbackResolvers)
	plan.Routes = make([]Route, 0, len(config.Routes))
	var hostZones []string
	for _, route := range config.Routes {
		// The root zone: forwarded, or unavailable; one the node would
		// answer itself would hide every name the host resolves elsewhere.
		if route.Suffix == "." {
			root := Route{
				Suffix: ".", Resolvers: resolverAddresses(route.Resolvers),
				Unavailable: route.Unavailable, FailOpen: route.FailOpen,
			}
			if root.local() {
				plan.IgnoredRoutes++
				continue
			}
			plan.Root = &root
			continue
		}
		// The root, or a suffix of the Internet (com, co.uk), answered
		// locally would hide every name under it, which Core never asks
		// for. A private zone keeps its route on one label (lan, corp): a
		// zone that answers NXDOMAIN, or fails closed, never falls to the
		// host's DNS.
		if len(route.Resolvers) == 0 && !route.Unavailable && internetSuffix(route.Suffix) {
			plan.IgnoredRoutes++
			continue
		}
		// A zone that leaves its other names to the host is not routed to
		// the node: each of its names gets a route of its own below, and
		// the host's own DNS (per link) answers the rest.
		if candidate := (Route{
			Unavailable: route.Unavailable, FailOpen: route.FailOpen,
			Resolvers: resolverAddresses(route.Resolvers),
		}); candidate.hostZone() {
			hostZones = append(hostZones, route.Suffix)
			continue
		}
		plan.Routes = append(plan.Routes, Route{
			Suffix:      route.Suffix,
			Resolvers:   resolverAddresses(route.Resolvers),
			Unavailable: route.Unavailable,
			FailOpen:    route.FailOpen,
		})
	}
	plan.SearchDomains = append([]string(nil), config.SearchDomains...)

	hosts := make(map[string][]netip.Addr)
	for _, record := range config.Records {
		if record.Type == networkmap.DNSRecordCNAME {
			plan.Aliases = append(plan.Aliases, Alias{Name: record.Name, Target: record.Target})
			continue
		}
		if err := addHostAddress(hosts, record.Name, record.Address); err != nil {
			return Plan{}, err
		}
	}
	slices.SortFunc(plan.Aliases, func(left, right Alias) int { return strings.Compare(left.Name, right.Name) })

	hostNames := make([]string, 0, len(hosts))
	for name := range hosts {
		hostNames = append(hostNames, name)
	}
	sort.Strings(hostNames)
	pointed := reverseRecords(&plan, hosts, hostNames, ownZone(snapshot.Self.Name))
	for _, name := range hostNames {
		addresses := hosts[name]
		if len(addresses) > maxAddressesPerHost {
			return Plan{}, fmt.Errorf(
				"%w: host %q has more than %d addresses",
				ErrInvalid,
				name,
				maxAddressesPerHost,
			)
		}
		slices.SortFunc(addresses, func(left, right netip.Addr) int {
			return left.Compare(right)
		})
		plan.Hosts = append(plan.Hosts, Host{Name: name, Addresses: addresses})
		if !locallyAuthoritative(plan.Routes, name) && dnsSuffixContains(sharedZone, name) && name != sharedZone &&
			!hasRouteSuffix(plan.Routes, sharedZone) {
			plan.Routes = append(plan.Routes, Route{Suffix: sharedZone, Resolvers: []netip.AddrPort{}})
		}
		if _, ownName := pointed[name]; ownName && !locallyAuthoritative(plan.Routes, name) {
			return Plan{}, fmt.Errorf(
				"%w: name %q of the node's own zone has no locally authoritative route",
				ErrInvalid,
				name,
			)
		}
	}
	routeNames(&plan, hostNames, hostZones)
	sort.Slice(plan.Routes, func(left, right int) bool {
		return plan.Routes[left].Suffix < plan.Routes[right].Suffix
	})
	sort.Slice(plan.Reverse, func(left, right int) bool {
		return plan.Reverse[left].Address.Compare(plan.Reverse[right].Address) < 0
	})
	for _, domain := range plan.SearchDomains {
		if !plan.RoutesAllNames() && !hasRoute(plan.Routes, domain) {
			return Plan{}, fmt.Errorf(
				"%w: search domain %q has no resolver route",
				ErrInvalid,
				domain,
			)
		}
	}
	plan.Enabled = plan.RoutesAllNames() || len(plan.Routes) != 0 ||
		len(plan.SearchDomains) != 0 || len(plan.Hosts) != 0 || len(plan.Aliases) != 0 || plan.Exit != nil

	return plan, nil
}

func resolverAddresses(resolvers []networkmap.DNSResolver) []netip.AddrPort {
	addresses := make([]netip.AddrPort, len(resolvers))
	for index, resolver := range resolvers {
		addresses[index] = resolver.Address
	}

	return addresses
}

func addHostAddress(hosts map[string][]netip.Addr, name string, address netip.Addr) error {
	for _, existing := range hosts[name] {
		if existing == address {
			return fmt.Errorf("%w: duplicate address for %q", ErrInvalid, name)
		}
	}
	hosts[name] = append(hosts[name], address)

	return nil
}

// ownZone returns the zone the node's own name is in (its name without the
// first label), or "" when the name has no parent below the root.
func ownZone(selfName string) string {
	name, err := canonicalNodeName(selfName)
	if err != nil {
		return ""
	}
	_, zone, found := strings.Cut(name, ".")
	if !found {
		return ""
	}
	return zone
}

// reverseRecords adds a pointer for every address of a name under zone;
// an address two such names share points to the first in name order. It
// returns the names that got pointers.
func reverseRecords(plan *Plan, hosts map[string][]netip.Addr, sortedNames []string,
	zone string,
) map[string]struct{} {
	pointed := make(map[string]struct{})
	if zone == "" {
		return pointed
	}
	seen := make(map[netip.Addr]struct{})
	for _, name := range sortedNames {
		if name == zone || !dnsSuffixContains(zone, name) {
			continue
		}
		pointed[name] = struct{}{}
		for _, address := range hosts[name] {
			if _, taken := seen[address]; taken {
				continue
			}
			seen[address] = struct{}{}
			plan.Reverse = append(plan.Reverse, Reverse{Address: address, Name: name})
		}
	}
	return pointed
}

func canonicalNodeName(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(raw, "."))
	if name == "" || len(name) > 253 || strings.HasSuffix(name, ".") {
		return "", errors.New("name is empty or too long")
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("label is malformed")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') && character != '-' {
				return "", errors.New("label contains an unsupported character")
			}
		}
	}

	return name, nil
}

func locallyAuthoritative(routes []Route, name string) bool {
	bestLength := -1
	local := false
	for _, route := range routes {
		if !dnsSuffixContains(route.Suffix, name) || len(route.Suffix) < bestLength {
			continue
		}
		bestLength = len(route.Suffix)
		local = route.local()
	}

	return bestLength >= 0 && local
}

func dnsSuffixContains(suffix, name string) bool {
	return suffix == "." || name == suffix || strings.HasSuffix(name, "."+suffix)
}

func hasRouteSuffix(routes []Route, suffix string) bool {
	return slices.ContainsFunc(routes, func(route Route) bool { return route.Suffix == suffix })
}

func hasRoute(routes []Route, name string) bool {
	return slices.ContainsFunc(routes, func(route Route) bool {
		return dnsSuffixContains(route.Suffix, name)
	})
}

// routeNames gives the names the node answers the routes they need, and
// finds the interior names. A name under a route of the node needs none of
// its own (DNS design D2 §5.2), however many names a zone holds. A name of
// a zone that leaves its other names to the host gets a route of its own,
// unavailable and failing open, so the node answers it and the host's DNS
// the types the node does not hold. Any other name gets a route the node
// answers itself.
func routeNames(plan *Plan, hostNames, hostZones []string) {
	names := make([]string, 0, len(hostNames)+len(plan.Aliases))
	names = append(names, hostNames...)
	for _, alias := range plan.Aliases {
		names = append(names, alias.Name)
	}
	slices.Sort(names)
	hostZones = splitHostZones(plan, hostZones, names)
	routed := make(map[string]struct{}, len(plan.Routes))
	for _, route := range plan.Routes {
		routed[route.Suffix] = struct{}{}
	}
	var added []Route
	for _, name := range names {
		route, covered := mostSpecificRoute(plan.Routes, name)
		inHostZone := slices.ContainsFunc(hostZones, func(zone string) bool {
			return dnsSuffixContains(zone, name) && (!covered || len(zone) > len(route.Suffix))
		})
		if _, exists := routed[name]; exists || (covered && !inHostZone) {
			continue
		}
		routed[name] = struct{}{}
		if inHostZone {
			added = append(added, Route{Suffix: name, Resolvers: []netip.AddrPort{}, Unavailable: true, FailOpen: true})
			continue
		}
		added = append(added, Route{Suffix: name, Resolvers: []netip.AddrPort{}})
	}
	plan.Routes = append(plan.Routes, added...)
	plan.Interior = interiorNames(plan.Routes, names)
}

// interiorNames are the ancestors of names, down to the route the node
// answers itself that covers them, that are not names themselves.
func interiorNames(routes []Route, names []string) []string {
	own := make(map[string]struct{}, len(names))
	for _, name := range names {
		own[name] = struct{}{}
	}
	interior := make(map[string]struct{})
	for _, name := range names {
		route, covered := mostSpecificRoute(routes, name)
		if !covered || !route.local() || route.Suffix == "." {
			continue
		}
		for parent := name; parent != route.Suffix; {
			_, rest, found := strings.Cut(parent, ".")
			if !found {
				break
			}
			parent = rest
			if _, isName := own[parent]; !isName {
				interior[parent] = struct{}{}
			}
		}
	}
	sorted := make([]string, 0, len(interior))
	for name := range interior {
		sorted = append(sorted, name)
	}
	slices.Sort(sorted)
	return sorted
}

// internetSuffix reports the root or a public suffix ICANN delegates,
// wildcard rules included (ck under *.ck): the suffix of a name just below
// it is itself, or that name. home.arpa is the home network's (RFC 8375).
func internetSuffix(suffix string) bool {
	if suffix == "." {
		return true
	}
	if suffix == "home.arpa" || strings.HasSuffix(suffix, ".home.arpa") {
		return false
	}
	probe := "probe." + suffix
	public, icann := publicsuffix.PublicSuffix(probe)
	return icann && (public == suffix || public == probe)
}

// maxNameRoutedDomains bounds the domains a plan asks the host to route
// once zones that leave their other names to the host route their names one
// by one: every platform takes at most 256, search domains included (DNS
// design D2 §3.4).
const maxNameRoutedDomains = 200

// splitHostZones returns the zones that leave their other names to the host
// whose names alone are routed to the node; every other one keeps a route
// of its own, unavailable and failing open (as a forward zone that lost its
// resolvers in D1): the node answers its names and asks the host's network
// resolvers for the rest. A zone keeps its route when another route already
// covers it (its other names would get that route's answer), when it is or
// holds a search domain (the host routes searched domains to the node
// anyway), when its names would pass maxNameRoutedDomains (a forward zone
// of 2,000 names that lost its resolvers must not fail the host's whole
// DNS), or under a root zone: the host sends the node every name then, and
// the zone's other names must reach the network's resolvers, not the root
// zone's (DNS design D1b §5.1).
func splitHostZones(plan *Plan, hostZones, names []string) []string {
	slices.Sort(hostZones)
	budget := maxNameRoutedDomains - len(plan.Routes) - len(plan.SearchDomains)
	var split []string
	for _, zone := range hostZones {
		inZone := 0
		for _, name := range names {
			if dnsSuffixContains(zone, name) {
				inZone++
			}
		}
		_, covered := mostSpecificRoute(plan.Routes, zone)
		searched := slices.ContainsFunc(plan.SearchDomains, func(domain string) bool {
			return dnsSuffixContains(zone, domain) || dnsSuffixContains(domain, zone)
		})
		if covered || searched || inZone > budget || plan.Root != nil {
			plan.Routes = append(plan.Routes, Route{
				Suffix: zone, Resolvers: []netip.AddrPort{}, Unavailable: true,
				FailOpen: true,
			})
			budget--
			continue
		}
		budget -= inZone
		split = append(split, zone)
	}
	return split
}
