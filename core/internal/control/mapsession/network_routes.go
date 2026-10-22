package mapsession

import (
	"cmp"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

// RouteStatus tells a consumer what it may do with a Site (mtcp-v1 §7.6).
type RouteStatus uint8

const (
	// RouteStatusUnknown is the invalid zero value.
	RouteStatusUnknown RouteStatus = iota
	// RouteServed means forward through the primary.
	RouteServed
	// RouteUnserved means granted, but no router can serve now.
	RouteUnserved
	// RouteConflict means the Site overlaps another Site granted to the node.
	RouteConflict
	// RouteCapacity means the primary's map cannot hold the node.
	RouteCapacity
)

// Bounds of the routes of one map (mtcp-v1 §14).
const (
	MaximumRouteSites        = 1024
	MaximumRoutePrefixes     = 4096
	MaximumRouteSitePrefixes = 1024
	MaximumRouteCandidates   = 32
	MaximumRouteRouters      = 256
)

// RouteProbe is an address a router checks inside its Site.
type RouteProbe struct {
	Address netip.Addr
	TCP     bool
	Port    uint16
}

// RouteSite is one active Site of the Network as maps see it.
type RouteSite struct {
	Site int64 // internal reference
	Ref  string
	// Name is the Site's display name; empty before schema 195.
	Name       string
	Prefixes   []netip.Prefix
	Masquerade bool
	Probes     []RouteProbe
	// Elected is true once Core elected the Site's primary (schema 193):
	// then Primary is its Device (0: no router can serve), and before it the
	// first active router by priority is.
	Elected bool
	Primary int64
}

// RouteRouter is one router row of an active Site, with the facts that
// decide whether it can serve.
type RouteRouter struct {
	Site           int64
	Device         int64
	NodeID         node.ID
	Priority       int
	Active         bool // false: draining
	WorkspaceOwned bool
	Offered        []netip.Prefix
}

// RouteRule is one rule of the active release whose destination is a Site,
// its source named by selector.
type RouteRule struct {
	ID         policy.RuleID
	SourceKind SelectorKind
	SourceRef  int64
	Site       int64
	Prefixes   []netip.Prefix
	Protocol   policy.Protocol
	Ports      []policy.PortRange
}

// SiteRoute is one Site a consumer may reach.
type SiteRoute struct {
	Ref        string
	Name       string
	Prefixes   []netip.Prefix
	Candidates []node.ID
	Primary    node.ID // zero: none
	Generation int64
	Status     RouteStatus
}

// ServedSite is one Site a router forwards to.
type ServedSite struct {
	Ref        string
	Prefixes   []netip.Prefix
	Masquerade bool
	Probes     []RouteProbe
}

// RoutedInbound admits the consumers of one rule into part of a served
// Site.
type RoutedInbound struct {
	Sources  []node.ID
	Prefixes []netip.Prefix
	Protocol policy.Protocol
	Ports    []policy.PortRange
}

// RouteView is what one Device's map carries about subnet routes: the Sites
// it may reach as a consumer, the Sites it serves as a router with the
// traffic it admits into them, and the peers routes add to its map. Its
// zero value carries nothing.
type RouteView struct {
	sites   []SiteRoute
	served  []ServedSite
	inbound []RoutedInbound
	// peers are the Devices routes make peers of the map: a consumer's
	// candidates (routers), a router's consumers within its limit. A peer
	// limit never removes them.
	routers   []node.ID
	consumers []node.ID
	// Exit Pools (mtcp-v1 §7.7): the pools it may use as a consumer, the
	// pool it serves as an exit node with the traffic it admits, and the
	// peers they add: a consumer's candidates, an exit node's consumers.
	exits         []ExitPoolRoute
	servedExits   []ServedExit
	exitInbound   []ExitInbound
	exitNodes     []node.ID
	exitConsumers []node.ID
	// DNS zones (DNS design D1): the zones it asks resolvers for, and the
	// peers they add: a consumer's resolver Devices, a resolver Device's
	// consumers.
	dnsZones     []DNSZoneRoute
	resolvers    []node.ID
	dnsConsumers []node.ID
	// DNS names (DNS design D2): the positions of the names it may see in
	// the Network's name table, shared by every map of one read, and the
	// Devices they point at, which a limited map keeps after shares.
	nameTable   []DNSNameRoute
	dnsNames    []int32
	nameTargets []node.ID
	// omitted counts Sites, Exit Pools and DNS zones left out by the bounds
	// of one map.
	omitted int
}

// Sites returns the Sites the Device may reach, sorted by reference.
func (view RouteView) Sites() []SiteRoute { return cloneSiteRoutes(view.sites) }

// Served returns the Sites the Device serves, sorted by reference.
func (view RouteView) Served() []ServedSite { return cloneServedSites(view.served) }

// Inbound returns the routed traffic the Device admits as a router.
func (view RouteView) Inbound() []RoutedInbound {
	cloned := make([]RoutedInbound, len(view.inbound))
	for index, rule := range view.inbound {
		rule.Sources, rule.Prefixes, rule.Ports = slices.Clone(rule.Sources), slices.Clone(rule.Prefixes),
			slices.Clone(rule.Ports)
		cloned[index] = rule
	}
	return cloned
}

// Peers returns the Devices routes, Exit Pools and DNS zones add to the
// map, sorted.
func (view RouteView) Peers() []node.ID {
	peers := append(slices.Clone(view.routers), view.consumers...)
	peers = append(append(peers, view.exitNodes...), view.exitConsumers...)
	peers = append(append(peers, view.resolvers...), view.dnsConsumers...)
	slices.SortFunc(peers, compareNodeIDs)
	return slices.Compact(peers)
}

// ForCapabilities is forCapabilities for a store completing a snapshot with
// the capabilities its session already declared.
func (view RouteView) ForCapabilities(capabilities RouteCapabilities) RouteView {
	view = view.forCapabilities(capabilities.Routes, capabilities.Router)
	if !capabilities.Exits {
		view.exits, view.exitNodes = nil, nil
	}
	if !capabilities.ExitRouter {
		view.servedExits, view.exitInbound, view.exitConsumers = nil, nil, nil
	}
	// A resolver Device answers whatever its client: its consumers stay.
	if !capabilities.DNSForward {
		view.dnsZones, view.resolvers = nil, nil
	}
	// Zones that are not forward and names reach only clients that apply
	// them (dns.records1): another would answer their names wrongly.
	if !capabilities.DNSRecords {
		view.nameTable, view.dnsNames, view.nameTargets = nil, nil, nil
		view.dnsZones = slices.DeleteFunc(slices.Clone(view.dnsZones), func(zone DNSZoneRoute) bool {
			return zone.OtherNames != DNSOtherForward
		})
		if len(view.dnsZones) == 0 {
			view.dnsZones = nil
		}
	}
	return view
}

// RouteCapabilities are the route capabilities of a session (Request.Routes,
// Request.Router, Request.Exits, Request.ExitRouter, Request.DNSForward and
// Request.DNSRecords).
type RouteCapabilities struct {
	Routes, Router, Exits, ExitRouter, DNSForward, DNSRecords bool
}

// forCapabilities keeps what a session can use: the Sites to reach when it
// takes routes, the Sites to serve with their traffic and consumers when it
// can route (mtcp-v1 §7.6). Neither: none of it, peers included.
func (view RouteView) forCapabilities(routes, router bool) RouteView {
	if !routes {
		view.sites, view.routers = nil, nil
	}
	if !router {
		view.served, view.inbound, view.consumers = nil, nil, nil
	}
	return view
}

// Omitted counts Sites the bounds of one map left out.
func (view RouteView) Omitted() int { return view.omitted }

// IsEmpty reports a view that carries nothing.
func (view RouteView) IsEmpty() bool {
	return len(view.sites) == 0 && len(view.served) == 0 && len(view.inbound) == 0 &&
		len(view.routers) == 0 && len(view.consumers) == 0 && len(view.exits) == 0 &&
		len(view.servedExits) == 0 && len(view.exitInbound) == 0 && len(view.exitNodes) == 0 &&
		len(view.exitConsumers) == 0 && len(view.dnsZones) == 0 && len(view.resolvers) == 0 &&
		len(view.dnsConsumers) == 0 && len(view.dnsNames) == 0 && len(view.nameTargets) == 0
}

// Equal reports whether two views carry the same routes.
func (view RouteView) Equal(other RouteView) bool {
	return slices.EqualFunc(view.sites, other.sites, equalSiteRoute) &&
		slices.EqualFunc(view.served, other.served, equalServedSite) &&
		slices.EqualFunc(view.inbound, other.inbound, equalRoutedInbound) &&
		slices.Equal(view.routers, other.routers) && slices.Equal(view.consumers, other.consumers) &&
		slices.EqualFunc(view.exits, other.exits, equalExitPoolRoute) &&
		slices.EqualFunc(view.servedExits, other.servedExits, equalServedExit) &&
		slices.EqualFunc(view.exitInbound, other.exitInbound, equalExitInbound) &&
		slices.Equal(view.exitNodes, other.exitNodes) && slices.Equal(view.exitConsumers, other.exitConsumers) &&
		slices.EqualFunc(view.dnsZones, other.dnsZones, equalDNSZoneRoute) &&
		slices.Equal(view.resolvers, other.resolvers) && slices.Equal(view.dnsConsumers, other.dnsConsumers) &&
		view.equalDNSNames(other) && slices.Equal(view.nameTargets, other.nameTargets) &&
		view.omitted == other.omitted
}

// routeIndex is a Network's routes, indexed once per read for every map.
type routeIndex struct {
	revision int64
	sites    map[int64]*routeSiteEntry
	bySite   map[int64][]int   // site -> rule indexes
	routes   map[int64][]int64 // router device -> sites it is a router of
	nodes    map[int64]node.ID // router device -> public identity
	static   map[int64][]int64 // router device -> its consumers, sorted
	ruleList []RouteRule       // as read, for Equal
	routers  []RouteRouter     // as read, for Equal
	siteList []RouteSite       // as read, for Equal
	limit    int               // peer limit the consumer cut uses
	// routerLimit is how many routers one map reaches, and consumers how
	// many consumers a router keeps: together at most the peer limit, so a
	// peer limit never cuts a peer routes need.
	routerLimit, consumers int
	members                func(SelectorKind, int64) []int64
	// Exit Pools: pools by internal reference, rule indexes by pool, the
	// pool of each exit node, and the evidence as read, for Equal.
	pools     map[int64]*exitPoolEntry
	byPool    map[int64][]int
	exitOf    map[int64]int64
	poolList  []ExitPool
	exitNodes []ExitNode
	exitRules []ExitRule
	// DNS zones: as read and sorted by domain, the zones of each resolver
	// Device, and the positions of the policy rules that may admit UDP to
	// it.
	zoneList      []DNSZone
	resolverZones map[int64][]int
	resolverRules map[int64]map[selectorKey][]int // resolver -> rule source -> rule positions
	// DNS names: as read and sorted by name, each name's zone position, the
	// names by name, and every rule's position by its source.
	nameList      []DNSName
	nameRoutes    []DNSNameRoute  // what each name sends, for every map
	nameKeys      [][]selectorKey // a Device name's target selectors, whatever their deadlines
	nameZone      []int
	nameByFQDN    map[string]int
	nameZones     map[string]struct{} // domains of the zones kind host whose only name is their apex
	rulesBySource map[selectorKey][]int
}

type routeSiteEntry struct {
	site    RouteSite
	routers []RouteRouter // by priority, then Device
	primary RouteRouter   // the elected or first active router; zero Device: none
}

// newRouteIndex validates and indexes one Network's routes. Rules naming an
// unknown Site grant nothing; routers of an unknown Site are ignored.
// members lists a selector's Devices and keysOf a Device's selectors,
// whatever their deadlines.
func newRouteIndex(params NetworkPolicyParams, members func(SelectorKind, int64) []int64,
	keysOf func(int64) []selectorKey) (*routeIndex, bool) {
	if len(params.Sites) == 0 && len(params.RouteRouters) == 0 && len(params.RouteRules) == 0 &&
		len(params.ExitPools) == 0 && len(params.ExitNodes) == 0 && len(params.ExitRules) == 0 &&
		len(params.DNSZones) == 0 && len(params.DNSNames) == 0 {
		return nil, true
	}
	if params.RouteRevision <= 0 || params.RoutePeerLimit <= 0 || len(params.Sites) > MaximumRouteSites {
		return nil, false
	}
	index := &routeIndex{
		revision: params.RouteRevision, limit: params.RoutePeerLimit, members: members,
		routerLimit: min(MaximumRouteRouters, params.RoutePeerLimit/2),
		consumers:   params.RoutePeerLimit - min(MaximumRouteRouters, params.RoutePeerLimit/2),
		sites:       make(map[int64]*routeSiteEntry, len(params.Sites)), bySite: make(map[int64][]int),
		routes: make(map[int64][]int64), nodes: make(map[int64]node.ID), static: make(map[int64][]int64),
		ruleList: cloneRouteRules(params.RouteRules), routers: cloneRouteRouters(params.RouteRouters),
		siteList: cloneRouteSites(params.Sites),
	}
	for _, value := range index.siteList {
		if value.Site <= 0 || value.Ref == "" || len(value.Ref) > 64 || len(value.Prefixes) == 0 {
			return nil, false
		}
		if _, duplicate := index.sites[value.Site]; duplicate {
			return nil, false
		}
		index.sites[value.Site] = &routeSiteEntry{site: value}
	}
	for _, router := range index.routers {
		entry := index.sites[router.Site]
		if router.Device <= 0 || !router.NodeID.IsValid() {
			return nil, false
		}
		if entry == nil {
			continue
		}
		entry.routers = append(entry.routers, router)
		index.routes[router.Device] = append(index.routes[router.Device], router.Site)
		index.nodes[router.Device] = router.NodeID
	}
	for _, entry := range index.sites {
		slices.SortFunc(entry.routers, func(first, second RouteRouter) int {
			return cmp.Or(cmp.Compare(first.Priority, second.Priority), cmp.Compare(first.Device, second.Device))
		})
		entry.primary = siteRoutePrimary(entry.site, entry.routers)
	}
	if !index.indexExits(params) || !index.indexDNSZones(params, keysOf) || !index.indexDNSNames(params, keysOf) {
		return nil, false
	}
	for position, rule := range index.ruleList {
		if !rule.ID.IsValid() || !rule.SourceKind.valid() || rule.SourceRef <= 0 || len(rule.Prefixes) == 0 {
			return nil, false
		}
		if _, known := index.sites[rule.Site]; known {
			index.bySite[rule.Site] = append(index.bySite[rule.Site], position)
		}
	}
	// Each router's and exit node's consumers in a fixed order, whatever
	// their liveness or membership deadlines: a consumer finds its place
	// without building the router's map, and both cut at the same place. One
	// list per Site or pool, shared by its routers or exit nodes; a Device
	// serving several merges theirs. The routers of a Site are never its
	// consumers, nor the exit nodes of a pool.
	bySiteConsumers := make(map[int64][]int64, len(index.sites))
	for site, entry := range index.sites {
		var consumers []int64
		for _, position := range index.bySite[site] {
			rule := index.ruleList[position]
			if rule.SourceKind == SelectorDevice {
				consumers = append(consumers, rule.SourceRef)
				continue
			}
			consumers = append(consumers, members(rule.SourceKind, rule.SourceRef)...)
		}
		slices.Sort(consumers)
		consumers = slices.Compact(consumers)
		bySiteConsumers[site] = slices.DeleteFunc(consumers, func(consumer int64) bool {
			return slices.ContainsFunc(entry.routers, func(router RouteRouter) bool { return router.Device == consumer })
		})
	}
	byPoolConsumers := index.poolConsumers()
	serving := make(map[int64][][]int64, len(index.routes)+len(index.exitOf))
	for device, sites := range index.routes {
		for _, site := range sites {
			serving[device] = append(serving[device], bySiteConsumers[site])
		}
	}
	for device, pool := range index.exitOf {
		serving[device] = append(serving[device], byPoolConsumers[pool])
	}
	devices := make([]int64, len(params.Devices))
	for position, device := range params.Devices {
		devices[position] = device.Device
	}
	slices.Sort(devices)
	for device, consumers := range index.dnsConsumers(devices) {
		serving[device] = append(serving[device], consumers)
	}
	for device, lists := range serving {
		if len(lists) == 1 {
			index.static[device] = lists[0]
			continue
		}
		var consumers []int64
		for _, list := range lists {
			consumers = append(consumers, list...)
		}
		slices.Sort(consumers)
		index.static[device] = slices.Compact(consumers)
	}
	return index, true
}

// equal reports whether two indexes hold the same evidence, read in order.
func (index *routeIndex) equal(other *routeIndex) bool {
	if index == nil || other == nil {
		return index == other
	}
	return index.revision == other.revision && index.limit == other.limit &&
		slices.EqualFunc(index.siteList, other.siteList, equalRouteSite) &&
		slices.EqualFunc(index.routers, other.routers, equalRouteRouter) &&
		slices.EqualFunc(index.ruleList, other.ruleList, equalRouteRule) && index.equalExits(other) &&
		index.equalDNSZones(other) && index.equalDNSNames(other)
}

// serves reports whether a router can serve its Site now: its Device is
// live, Workspace-owned and offers every prefix of the Site itself.
func (inner *networkPolicy) serves(router RouteRouter, entry *routeSiteEntry, now time.Time) bool {
	return router.Device > 0 && router.WorkspaceOwned && inner.live(router.Device, now) &&
		coversAll(router.Offered, entry.site.Prefixes)
}

// routesFor expands the Network's routes for self at now.
func (inner *networkPolicy) routesFor(self int64, now time.Time) RouteView {
	if inner.routes == nil || !inner.live(self, now) {
		return RouteView{}
	}
	view := RouteView{}
	routers := make(map[node.ID]struct{})
	inner.consumerRoutes(&view, self, now, routers)
	inner.servedRoutes(&view, self, now)
	inner.consumerExits(&view, self, now, routers)
	inner.servedExits(&view, self, now)
	inner.consumerDNSZones(&view, self, now, routers)
	inner.servedDNS(&view, self, now)
	inner.consumerDNSNames(&view, self, now)
	for _, peers := range []*[]node.ID{&view.routers, &view.consumers, &view.exitNodes, &view.exitConsumers,
		&view.resolvers, &view.dnsConsumers, &view.nameTargets} {
		slices.SortFunc(*peers, compareNodeIDs)
		*peers = slices.Compact(*peers)
	}
	return view
}

// consumerRoutes adds the Sites self may reach.
func (inner *networkPolicy) consumerRoutes(view *RouteView, self int64, now time.Time,
	routers map[node.ID]struct{}) {
	index := inner.routes
	granted := make(map[int64][]netip.Prefix)
	for _, rule := range index.ruleList {
		entry := index.sites[rule.Site]
		if entry == nil || slices.Contains(index.routes[self], rule.Site) ||
			!inner.selects(rule.SourceKind, rule.SourceRef, self, now) {
			continue
		}
		granted[rule.Site] = append(granted[rule.Site], intersectPrefixes(rule.Prefixes, entry.site.Prefixes)...)
	}
	sites := make([]SiteRoute, 0, len(granted))
	capacity := make(map[string]bool, len(granted))
	for site, prefixes := range granted {
		entry := index.sites[site]
		prefixes = outermostPrefixes(prefixes)
		if len(prefixes) == 0 {
			continue
		}
		route := SiteRoute{Ref: entry.site.Ref, Name: entry.site.Name, Prefixes: prefixes, Generation: index.revision,
			Status: RouteUnserved}
		for _, router := range entry.routers {
			route.Candidates = append(route.Candidates, router.NodeID)
		}
		if primary := entry.primary; primary.Device > 0 {
			route.Primary = primary.NodeID
			if inner.serves(primary, entry, now) {
				route.Status = RouteServed
				position, _ := slices.BinarySearch(index.static[primary.Device], self)
				capacity[route.Ref] = position >= index.consumers
			}
		}
		sites = append(sites, route)
	}
	slices.SortFunc(sites, func(first, second SiteRoute) int { return cmp.Compare(first.Ref, second.Ref) })
	markRouteConflicts(sites)
	prefixes := 0
	for _, route := range sites {
		if route.Status == RouteServed && capacity[route.Ref] {
			route.Status = RouteCapacity
		}
		added := 0
		for _, candidate := range route.Candidates {
			if _, known := routers[candidate]; !known {
				added++
			}
		}
		if len(view.sites) == MaximumRouteSites || prefixes+len(route.Prefixes) > MaximumRoutePrefixes ||
			len(route.Prefixes) > MaximumRouteSitePrefixes ||
			len(routers)+added > index.routerLimit || len(route.Candidates) > MaximumRouteCandidates {
			view.omitted++
			continue
		}
		prefixes += len(route.Prefixes)
		for _, candidate := range route.Candidates {
			routers[candidate] = struct{}{}
		}
		view.sites = append(view.sites, route)
	}
	for _, route := range view.sites {
		for _, candidate := range route.Candidates {
			if device, known := inner.byNode[candidate]; known && inner.live(device, now) {
				view.routers = append(view.routers, candidate)
			}
		}
	}
}

// servedRoutes adds the Sites self serves as a router and the traffic it
// admits into them: from its consumers within the peer limit.
func (inner *networkPolicy) servedRoutes(view *RouteView, self int64, now time.Time) {
	index := inner.routes
	sites := index.routes[self]
	if len(sites) == 0 {
		return
	}
	static := index.static[self]
	within := func(consumer int64) bool {
		position, found := slices.BinarySearch(static, consumer)
		return found && position < index.consumers
	}
	served := make([]ServedSite, 0, len(sites))
	for _, site := range sites {
		entry := index.sites[site]
		router := RouteRouter{}
		for _, candidate := range entry.routers {
			if candidate.Device == self {
				router = candidate
			}
		}
		if !inner.serves(router, entry, now) {
			continue
		}
		served = append(served, ServedSite{Ref: entry.site.Ref, Prefixes: outermostPrefixes(entry.site.Prefixes),
			Masquerade: entry.site.Masquerade, Probes: slices.Clone(entry.site.Probes)})
	}
	slices.SortFunc(served, func(first, second ServedSite) int { return cmp.Compare(first.Ref, second.Ref) })
	prefixes := 0
	kept := make(map[string]int64, len(served))
	var keptPrefixes []netip.Prefix
	for _, site := range served {
		// Served Sites never overlap (mtcp-v1 §7.6): of two that do, the
		// router serves the first by reference.
		if len(view.served) == MaximumRouteSites || prefixes+len(site.Prefixes) > MaximumRoutePrefixes ||
			len(site.Prefixes) > MaximumRouteSitePrefixes || overlapsAny(site.Prefixes, keptPrefixes) {
			view.omitted++
			continue
		}
		prefixes += len(site.Prefixes)
		keptPrefixes = append(keptPrefixes, site.Prefixes...)
		view.served = append(view.served, site)
		kept[site.Ref] = 0
	}
	for _, site := range sites {
		entry := index.sites[site]
		if _, serving := kept[entry.site.Ref]; !serving {
			continue
		}
		for _, position := range index.bySite[site] {
			rule := index.ruleList[position]
			destinations := intersectPrefixes(rule.Prefixes, entry.site.Prefixes)
			if len(destinations) == 0 {
				continue
			}
			var sources []node.ID
			_ = inner.eachSelected(rule.SourceKind, rule.SourceRef, now, func(consumer int64) error {
				if consumer != self && inner.live(consumer, now) && within(consumer) {
					sources = append(sources, inner.devices[consumer].NodeID)
				}
				return nil
			})
			if len(sources) == 0 {
				continue
			}
			slices.SortFunc(sources, compareNodeIDs)
			sources = slices.Compact(sources)
			view.inbound = append(view.inbound, RoutedInbound{Sources: sources, Prefixes: outermostPrefixes(destinations),
				Protocol: rule.Protocol, Ports: slices.Clone(rule.Ports)})
			view.consumers = append(view.consumers, sources...)
		}
	}
}

// markRouteConflicts marks every Site whose prefixes overlap another's:
// both, since the node could not tell which router a packet is for.
func markRouteConflicts(sites []SiteRoute) {
	type entry struct {
		prefix netip.Prefix
		site   int
	}
	var entries []entry
	for position, route := range sites {
		for _, prefix := range route.Prefixes {
			entries = append(entries, entry{prefix, position})
		}
	}
	slices.SortFunc(entries, func(first, second entry) int { return comparePrefixes(first.prefix, second.prefix) })
	var open []entry
	for _, current := range entries {
		for len(open) > 0 && !containsPrefix(open[len(open)-1].prefix, current.prefix) {
			open = open[:len(open)-1]
		}
		for _, outer := range open {
			if outer.site != current.site {
				sites[outer.site].Status, sites[current.site].Status = RouteConflict, RouteConflict
			}
		}
		open = append(open, current)
	}
}

// intersectPrefixes returns the part of granted inside owned: each granted
// prefix inside an owned one, and each owned prefix inside a granted one.
func intersectPrefixes(granted, owned []netip.Prefix) []netip.Prefix {
	var result []netip.Prefix
	for _, grant := range granted {
		for _, prefix := range owned {
			switch {
			case containsPrefix(prefix, grant):
				result = append(result, grant)
			case containsPrefix(grant, prefix):
				result = append(result, prefix)
			}
		}
	}
	return result
}

// outermostPrefixes sorts prefixes and drops those inside another.
func outermostPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	sorted := slices.Clone(prefixes)
	slices.SortFunc(sorted, comparePrefixes)
	result := make([]netip.Prefix, 0, len(sorted))
	for _, prefix := range sorted {
		if len(result) > 0 && containsPrefix(result[len(result)-1], prefix) {
			continue
		}
		result = append(result, prefix)
	}
	return result
}

func overlapsAny(prefixes, others []netip.Prefix) bool {
	return slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool {
		return slices.ContainsFunc(others, prefix.Overlaps)
	})
}

func coversAll(offered, wanted []netip.Prefix) bool {
	return !slices.ContainsFunc(wanted, func(prefix netip.Prefix) bool {
		return !slices.ContainsFunc(offered, func(outer netip.Prefix) bool { return containsPrefix(outer, prefix) })
	})
}

func containsPrefix(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

func comparePrefixes(first, second netip.Prefix) int {
	return cmp.Or(first.Addr().Compare(second.Addr()), cmp.Compare(first.Bits(), second.Bits()))
}

func equalSiteRoute(first, second SiteRoute) bool {
	return first.Ref == second.Ref && slices.Equal(first.Prefixes, second.Prefixes) &&
		slices.Equal(first.Candidates, second.Candidates) && first.Primary == second.Primary &&
		first.Generation == second.Generation && first.Status == second.Status
}

func equalServedSite(first, second ServedSite) bool {
	return first.Ref == second.Ref && slices.Equal(first.Prefixes, second.Prefixes) &&
		first.Masquerade == second.Masquerade && slices.Equal(first.Probes, second.Probes)
}

func equalRoutedInbound(first, second RoutedInbound) bool {
	return slices.Equal(first.Sources, second.Sources) && slices.Equal(first.Prefixes, second.Prefixes) &&
		first.Protocol == second.Protocol && slices.Equal(first.Ports, second.Ports)
}

func equalRouteSite(first, second RouteSite) bool {
	return first.Site == second.Site && first.Ref == second.Ref && slices.Equal(first.Prefixes, second.Prefixes) &&
		first.Masquerade == second.Masquerade && slices.Equal(first.Probes, second.Probes)
}

func equalRouteRouter(first, second RouteRouter) bool {
	return first.Site == second.Site && first.Device == second.Device && first.NodeID == second.NodeID &&
		first.Priority == second.Priority && first.Active == second.Active &&
		first.WorkspaceOwned == second.WorkspaceOwned && slices.Equal(first.Offered, second.Offered)
}

func equalRouteRule(first, second RouteRule) bool {
	return first.ID == second.ID && first.SourceKind == second.SourceKind && first.SourceRef == second.SourceRef &&
		first.Site == second.Site && slices.Equal(first.Prefixes, second.Prefixes) &&
		first.Protocol == second.Protocol && slices.Equal(first.Ports, second.Ports)
}

func cloneSiteRoutes(routes []SiteRoute) []SiteRoute {
	cloned := make([]SiteRoute, len(routes))
	for index, route := range routes {
		route.Prefixes, route.Candidates = slices.Clone(route.Prefixes), slices.Clone(route.Candidates)
		cloned[index] = route
	}
	return cloned
}

func cloneServedSites(sites []ServedSite) []ServedSite {
	cloned := make([]ServedSite, len(sites))
	for index, site := range sites {
		site.Prefixes, site.Probes = slices.Clone(site.Prefixes), slices.Clone(site.Probes)
		cloned[index] = site
	}
	return cloned
}

// siteRoutePrimary is the elected router while it is an active router of the
// Site, none when Core elected none, and otherwise the first active router
// by priority: the election lags a router change by one sweep.
func siteRoutePrimary(site RouteSite, routers []RouteRouter) RouteRouter {
	if site.Elected {
		if site.Primary == 0 {
			return RouteRouter{}
		}
		for _, router := range routers {
			if router.Device == site.Primary && router.Active {
				return router
			}
		}
	}
	for _, router := range routers {
		if router.Active {
			return router
		}
	}
	return RouteRouter{}
}

func cloneRouteSites(sites []RouteSite) []RouteSite {
	cloned := make([]RouteSite, len(sites))
	for index, site := range sites {
		site.Prefixes, site.Probes = slices.Clone(site.Prefixes), slices.Clone(site.Probes)
		cloned[index] = site
	}
	return cloned
}

func cloneRouteRouters(routers []RouteRouter) []RouteRouter {
	cloned := make([]RouteRouter, len(routers))
	for index, router := range routers {
		router.Offered = slices.Clone(router.Offered)
		cloned[index] = router
	}
	return cloned
}

func cloneRouteRules(rules []RouteRule) []RouteRule {
	cloned := make([]RouteRule, len(rules))
	for index, rule := range rules {
		rule.Prefixes, rule.Ports = slices.Clone(rule.Prefixes), slices.Clone(rule.Ports)
		cloned[index] = rule
	}
	return cloned
}

// withRouteCapabilities keeps the routes the session can use, and so the
// peers they add (Snapshot.Routes), and remembers the capabilities so a
// refresh can filter before it builds (Snapshot.RouteCapabilities).
func (snapshot Snapshot) withRouteCapabilities(request Request) (Snapshot, error) {
	capabilities := RouteCapabilities{Routes: request.Routes(), Router: request.Router(), Exits: request.Exits(),
		ExitRouter: request.ExitRouter(), DNSForward: request.DNSForward(), DNSRecords: request.DNSRecords()}
	routes := snapshot.routes.ForCapabilities(capabilities)
	if routes.Equal(snapshot.routes) {
		snapshot.routeCapabilities, snapshot.routeCapabilitiesKnown = capabilities, true
		return snapshot, nil
	}
	params := snapshot.params()
	params.Routes = routes
	next, err := NewSnapshot(params)
	if err != nil {
		return Snapshot{}, err
	}
	next.relayGrant, next.peerLimit, next.relayZones = snapshot.relayGrant, snapshot.peerLimit, snapshot.relayZones
	next.routeCapabilities, next.routeCapabilitiesKnown = capabilities, true
	return next, nil
}

// RouteCapabilities returns the route capabilities of the snapshot's
// session, when its session set them.
func (snapshot Snapshot) RouteCapabilities() (RouteCapabilities, bool) {
	return snapshot.routeCapabilities, snapshot.routeCapabilitiesKnown
}
