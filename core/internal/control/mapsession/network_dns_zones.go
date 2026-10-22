package mapsession

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/shared/internet"
)

// Bounds of the DNS zones of one map (DNS design D1 §3.5).
const (
	MaximumDNSZones         = 256
	MaximumDNSZoneResolvers = 4
	MaximumDNSZoneGroups    = 16
	// MaximumDNSSearchDomains counts the Network's own zone.
	MaximumDNSSearchDomains = 8
)

// dnsPort is the port of Internet resolvers and the default of Devices.
const dnsPort = 53

// DNSZone is one active zone of the Network as maps see it. Only a forward
// zone has resolvers.
type DNSZone struct {
	Zone       int64 // internal reference
	Domain     string
	OtherNames DNSOtherNames
	FailOpen   bool
	// Groups are the Device Groups the zone is sent to; empty: every
	// Device of the Network.
	Groups []int64
	// SearchPosition orders the zone among the search domains; 0: none.
	SearchPosition int
	Resolvers      []DNSZoneResolver
}

// DNSZoneResolver is one resolver of a zone: a Device of the Network, with
// whether it may serve (active and Workspace-owned), or an Internet
// address. A Device that no longer exists has no internal reference.
type DNSZoneResolver struct {
	Device   int64
	NodeID   node.ID
	Eligible bool
	Address  netip.Addr
	Port     uint16
}

// DNSZoneRoute is one zone a Device asks resolvers for (mtcp-v1 §7.3). No
// resolver: the zone is unavailable and the Device applies its failure
// mode.
type DNSZoneRoute struct {
	Domain         string
	OtherNames     DNSOtherNames
	FailOpen       bool
	SearchPosition int
	Resolvers      []DNSResolverRoute // in the zone's order
}

// DNSResolverRoute is one resolver of a zone route: a peer of the map by
// NodeID, or an Internet Address.
type DNSResolverRoute struct {
	NodeID  node.ID
	Address netip.Addr
	Port    uint16
}

// DNSZones returns the zones the Device asks resolvers for, sorted by
// domain.
func (view RouteView) DNSZones() []DNSZoneRoute {
	cloned := make([]DNSZoneRoute, len(view.dnsZones))
	for index, zone := range view.dnsZones {
		zone.Resolvers = slices.Clone(zone.Resolvers)
		cloned[index] = zone
	}
	return cloned
}

// indexDNSZones validates and indexes the Network's DNS zones into index:
// each resolver Device's zones, the rules that may admit UDP to it, and the
// Devices each zone is sent to, as consumers of its resolvers. keysOf lists
// the selectors a Device belongs to, whatever their deadlines.
func (index *routeIndex) indexDNSZones(params NetworkPolicyParams, keysOf func(int64) []selectorKey) bool {
	if len(params.DNSZones) > MaximumDNSZones {
		return false
	}
	index.zoneList = cloneDNSZones(params.DNSZones)
	slices.SortFunc(index.zoneList, func(first, second DNSZone) int { return strings.Compare(first.Domain, second.Domain) })
	index.resolverZones = make(map[int64][]int)
	seen := make(map[int64]struct{}, len(index.zoneList))
	for position, zone := range index.zoneList {
		if !validDNSZone(zone) {
			return false
		}
		if _, duplicate := seen[zone.Zone]; duplicate {
			return false
		}
		seen[zone.Zone] = struct{}{}
		for _, resolver := range zone.Resolvers {
			if resolver.Device > 0 {
				index.resolverZones[resolver.Device] = append(index.resolverZones[resolver.Device], position)
			}
		}
	}
	// The rules that may admit UDP to a resolver Device: found through the
	// selectors resolvers belong to, not by expanding every rule.
	byKey := make(map[selectorKey][]int64)
	for resolver := range index.resolverZones {
		for _, key := range append(keysOf(resolver), selectorKey{kind: SelectorDevice, id: resolver}) {
			byKey[key] = append(byKey[key], resolver)
		}
	}
	// Indexed by the rule's source too, so checking one consumer costs its
	// own selectors, not every rule to the resolver.
	index.resolverRules = make(map[int64]map[selectorKey][]int)
	for position, rule := range params.Rules {
		if rule.Protocol != policy.ProtocolUDP {
			continue
		}
		source := selectorKey{kind: rule.SourceKind, id: rule.SourceRef}
		for _, resolver := range byKey[selectorKey{kind: rule.DestinationKind, id: rule.DestinationRef}] {
			if index.resolverRules[resolver] == nil {
				index.resolverRules[resolver] = make(map[selectorKey][]int)
			}
			index.resolverRules[resolver][source] = append(index.resolverRules[resolver][source], position)
		}
	}
	return true
}

// dnsConsumers lists each resolver Device's consumers in a fixed order,
// whatever their liveness, membership deadlines or rules: the Devices each
// of its zones is sent to, without that zone's own resolver Devices (a
// resolver of one zone still consumes the others). Only the first
// index.consumers of each list can be within the cut, so each list is
// truncated there: the first entries of a sorted union come only from the
// first entries of each list. devices is sorted.
func (index *routeIndex) dnsConsumers(devices []int64) map[int64][]int64 {
	byZone := make([][]int64, len(index.zoneList))
	for position, zone := range index.zoneList {
		if zone.Domain == "." || !slices.ContainsFunc(zone.Resolvers, func(resolver DNSZoneResolver) bool {
			return resolver.Device > 0
		}) {
			continue
		}
		var consumers []int64
		if len(zone.Groups) == 0 {
			consumers = make([]int64, 0, min(len(devices), index.consumers+len(zone.Resolvers)))
			for _, device := range devices {
				if len(consumers) == index.consumers {
					break
				}
				if !zone.resolves(device) {
					consumers = append(consumers, device)
				}
			}
		} else {
			for _, group := range zone.Groups {
				consumers = append(consumers, index.members(SelectorDeviceGroup, group)...)
			}
			slices.Sort(consumers)
			consumers = slices.DeleteFunc(slices.Compact(consumers), zone.resolves)
		}
		byZone[position] = consumers[:min(len(consumers), index.consumers)]
	}
	byResolver := make(map[int64][]int64, len(index.resolverZones))
	for resolver, zones := range index.resolverZones {
		if len(zones) == 1 {
			byResolver[resolver] = byZone[zones[0]]
			continue
		}
		var consumers []int64
		for _, position := range zones {
			consumers = append(consumers, byZone[position]...)
		}
		slices.Sort(consumers)
		consumers = slices.Compact(consumers)
		byResolver[resolver] = consumers[:min(len(consumers), index.consumers)]
	}
	return byResolver
}

// resolves reports whether device is one of the zone's resolver Devices.
func (zone DNSZone) resolves(device int64) bool {
	return slices.ContainsFunc(zone.Resolvers, func(resolver DNSZoneResolver) bool { return resolver.Device == device })
}

// receives reports whether the zone is sent to device at now.
func (inner *networkPolicy) receives(zone DNSZone, device int64, now time.Time) bool {
	if zone.resolves(device) {
		return false
	}
	if len(zone.Groups) == 0 {
		return true
	}
	return slices.ContainsFunc(zone.Groups, func(group int64) bool {
		return inner.selects(SelectorDeviceGroup, group, device, now)
	})
}

// admitsDNS reports whether an active rule admits UDP from consumer to the
// resolver Device on port at now. Being peers is not enough: a rule for
// another service, or the other way, also makes them peers.
func (inner *networkPolicy) admitsDNS(consumer, resolver int64, port uint16, now time.Time) bool {
	rules := inner.routes.resolverRules[resolver]
	if len(rules) == 0 {
		return false
	}
	admits := func(key selectorKey) bool {
		for _, position := range rules[key] {
			rule := inner.rules[position]
			if coversPort(rule.Ports, port) && inner.selects(rule.DestinationKind, rule.DestinationRef, resolver, now) &&
				inner.selects(rule.SourceKind, rule.SourceRef, consumer, now) {
				return true
			}
		}
		return false
	}
	if admits(selectorKey{kind: SelectorDevice, id: consumer}) {
		return true
	}
	for key := range inner.memberOf[consumer] {
		if admits(key) {
			return true
		}
	}
	return false
}

// resolverServes reports whether a resolver Device can serve now: it may
// serve, is live and no exit node (which takes port 53 on its mesh address
// for its own forwarder).
func (inner *networkPolicy) resolverServes(resolver DNSZoneResolver, now time.Time) bool {
	_, exitNode := inner.routes.exitOf[resolver.Device]
	return resolver.Device > 0 && resolver.Eligible && !exitNode && inner.live(resolver.Device, now)
}

// consumerDNSZones adds the zones self asks resolvers for: each zone sent
// to it, with the resolvers it may use now. A resolver Device is used when
// it serves, a rule admits UDP from self to its port, its map holds self
// within the peer limit, and self's map holds it: resolver Devices share the
// routers' part of the peer limit with the Sites' routers and the exit nodes
// in routers. They are then needed peers. The root zone waits for D1b. A
// zone of one name another zone sent holds is answered in that one.
func (inner *networkPolicy) consumerDNSZones(view *RouteView, self int64, now time.Time,
	routers map[node.ID]struct{}) {
	index := inner.routes
	for _, zone := range index.zoneList {
		if zone.Domain == "." || !inner.receives(zone, self, now) {
			continue
		}
		if len(view.dnsZones) == MaximumDNSZones {
			view.omitted++
			continue
		}
		route := DNSZoneRoute{Domain: zone.Domain, OtherNames: zone.OtherNames, FailOpen: zone.FailOpen,
			SearchPosition: zone.SearchPosition}
		for _, resolver := range zone.Resolvers {
			if resolver.Address.IsValid() {
				route.Resolvers = append(route.Resolvers, DNSResolverRoute{Address: resolver.Address, Port: resolver.Port})
				continue
			}
			position, found := slices.BinarySearch(index.static[resolver.Device], self)
			if !inner.resolverServes(resolver, now) || !found || position >= index.consumers ||
				!inner.admitsDNS(self, resolver.Device, resolver.Port, now) {
				continue
			}
			if _, known := routers[resolver.NodeID]; !known {
				if len(routers) >= index.routerLimit {
					continue
				}
				routers[resolver.NodeID] = struct{}{}
			}
			route.Resolvers = append(route.Resolvers, DNSResolverRoute{NodeID: resolver.NodeID, Port: resolver.Port})
			view.resolvers = append(view.resolvers, resolver.NodeID)
		}
		view.dnsZones = append(view.dnsZones, route)
	}
	view.dnsZones = index.withoutNestedNameZones(view.dnsZones)
}

// withoutNestedNameZones leaves out the route of a zone kind host whose only
// name is its apex when another of routes holds its domain (DNS design D3
// §4.2): its name is answered in that zone, so the name's other types go to
// that zone's resolvers, never to the host's DNS. Zones kind host of several
// names keep their routes (TD-CORE-83).
func (index *routeIndex) withoutNestedNameZones(routes []DNSZoneRoute) []DNSZoneRoute {
	if len(index.nameZones) == 0 || len(routes) < 2 {
		return routes
	}
	domains := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		domains[route.Domain] = struct{}{}
	}
	nested := func(route DNSZoneRoute) bool {
		if _, single := index.nameZones[route.Domain]; !single {
			return false
		}
		for parent := route.Domain; ; {
			_, rest, found := strings.Cut(parent, ".")
			if !found {
				return false
			}
			if _, held := domains[rest]; held {
				return true
			}
			parent = rest
		}
	}
	if !slices.ContainsFunc(routes, nested) {
		return routes
	}
	return slices.DeleteFunc(slices.Clone(routes), nested)
}

// servedDNS adds the consumers self answers as a resolver Device: those of
// its zones that use it, within the peer limit.
func (inner *networkPolicy) servedDNS(view *RouteView, self int64, now time.Time) {
	index := inner.routes
	zones := index.resolverZones[self]
	if len(zones) == 0 {
		return
	}
	// The zones self serves now, each with its port.
	type served struct {
		zone DNSZone
		port uint16
	}
	var serving []served
	for _, position := range zones {
		zone := index.zoneList[position]
		if zone.Domain == "." {
			continue
		}
		for _, resolver := range zone.Resolvers {
			if resolver.Device == self && inner.resolverServes(resolver, now) {
				serving = append(serving, served{zone: zone, port: resolver.Port})
			}
		}
	}
	if len(serving) == 0 {
		return
	}
	static := index.static[self]
	for _, consumer := range static[:min(len(static), index.consumers)] {
		if !inner.live(consumer, now) {
			continue
		}
		if slices.ContainsFunc(serving, func(value served) bool {
			return inner.receives(value.zone, consumer, now) && inner.admitsDNS(consumer, self, value.port, now)
		}) {
			view.dnsConsumers = append(view.dnsConsumers, inner.devices[consumer].NodeID)
		}
	}
}

// coversPort reports whether one of ranges holds port.
func coversPort(ranges []policy.PortRange, port uint16) bool {
	return slices.ContainsFunc(ranges, func(portRange policy.PortRange) bool {
		return portRange.First() <= port && port <= portRange.Last()
	})
}

// validDNSZone checks one zone as read: a domain, up to 4 distinct
// resolvers each a Device on port 53 or 1024-65535 or an Internet address
// on port 53, up to 16 groups. A zone whose resolvers the store dropped
// keeps its route, unavailable.
func validDNSZone(zone DNSZone) bool {
	if zone.Zone <= 0 || zone.Domain == "" || len(zone.Domain) > 253 || zone.SearchPosition < 0 ||
		zone.OtherNames < DNSOtherForward || zone.OtherNames > DNSOtherHost ||
		(zone.OtherNames != DNSOtherForward && (len(zone.Resolvers) != 0 || zone.Domain == ".")) ||
		len(zone.Resolvers) > MaximumDNSZoneResolvers ||
		len(zone.Groups) > MaximumDNSZoneGroups || slices.ContainsFunc(zone.Groups, func(group int64) bool {
		return group <= 0
	}) {
		return false
	}
	for position, resolver := range zone.Resolvers {
		switch {
		case resolver.Address.IsValid():
			if resolver.Device != 0 || resolver.NodeID.IsValid() || resolver.Eligible || resolver.Port != dnsPort ||
				!internet.Contains(resolver.Address) {
				return false
			}
		case resolver.NodeID.IsValid():
			if resolver.Device < 0 || (resolver.Device == 0 && resolver.Eligible) ||
				(resolver.Port != dnsPort && resolver.Port < 1024) {
				return false
			}
		default:
			return false
		}
		if slices.ContainsFunc(zone.Resolvers[:position], func(other DNSZoneResolver) bool {
			return other.Address == resolver.Address && other.NodeID == resolver.NodeID
		}) {
			return false
		}
	}
	return true
}

func (index *routeIndex) equalDNSZones(other *routeIndex) bool {
	return slices.EqualFunc(index.zoneList, other.zoneList, func(first, second DNSZone) bool {
		return first.Zone == second.Zone && first.Domain == second.Domain && first.OtherNames == second.OtherNames &&
			first.FailOpen == second.FailOpen &&
			slices.Equal(first.Groups, second.Groups) && first.SearchPosition == second.SearchPosition &&
			slices.Equal(first.Resolvers, second.Resolvers)
	})
}

func equalDNSZoneRoute(first, second DNSZoneRoute) bool {
	return first.Domain == second.Domain && first.OtherNames == second.OtherNames && first.FailOpen == second.FailOpen &&
		first.SearchPosition == second.SearchPosition && slices.Equal(first.Resolvers, second.Resolvers)
}

func cloneDNSZones(zones []DNSZone) []DNSZone {
	cloned := make([]DNSZone, len(zones))
	for index, zone := range zones {
		zone.Groups, zone.Resolvers = slices.Clone(zone.Groups), slices.Clone(zone.Resolvers)
		cloned[index] = zone
	}
	return cloned
}

// compareSearchZones orders zones as search domains: by position, then
// domain.
func compareSearchZones(first, second DNSZoneRoute) int {
	return cmp.Or(cmp.Compare(first.SearchPosition, second.SearchPosition),
		strings.Compare(first.Domain, second.Domain))
}
