package mapsession

import (
	"slices"
	"strings"
)

// Bounds of the DNS routes one map makes a client set (DNS design D3 §4.3).
// The client's helper refuses a whole DNS configuration past 256 domains or
// 16 KiB of them, search domains included; what is left over is for the
// routes the client adds itself (the root for default resolvers or an exit
// node, the shared zone).
const (
	maximumDNSRouteDomains = 256 - 8
	maximumDNSRouteBytes   = 16<<10 - 512
	// clientNameRoutedDomains is the client's own bound on the domains it
	// routes before it routes a zone's names one by one (client dnsconfig
	// maxNameRoutedDomains).
	clientNameRoutedDomains = 200
)

// clientDNSRoutes is what a map's DNS configuration makes a client route,
// before names: the domains it routes whole in the order sent (the mesh
// suffix, then the zones), the search domains, and the zones that leave
// their other names to the host, sorted.
type clientDNSRoutes struct {
	routes, search, host []string
}

// cost returns the domains, and their bytes, the client's helper gets for
// names, the names of the configuration's records and CNAMEs, once each. It
// follows the client (dnsconfig Compile, splitHostZones, routeNames and
// buildResolvedConfig): a zone leaving its other names to the host is
// routed whole when a route or search domain covers or meets it, or when
// its names pass what is left of clientNameRoutedDomains; else each of its
// names gets a route of its own, as does a name no route holds. A name a
// route holds more closely than any such zone costs nothing.
func (config clientDNSRoutes) cost(names []string) (int, int) {
	routed := make(map[string]struct{}, len(config.routes)+len(config.host))
	for _, route := range config.routes {
		routed[route] = struct{}{}
	}
	host := make(map[string]int, len(config.host))
	for _, zone := range config.host {
		host[zone] = 0
	}
	for _, name := range names {
		for suffix := range dnsAncestors(name) {
			if count, found := host[suffix]; found {
				host[suffix] = count + 1
			}
		}
	}
	searched := make(map[string]struct{}, len(config.search))
	for _, domain := range config.search {
		for suffix := range dnsAncestors(domain) {
			searched[suffix] = struct{}{}
		}
	}
	budget := clientNameRoutedDomains - len(config.routes) - len(config.search)
	split := make(map[string]struct{}, len(config.host))
	for _, zone := range config.host {
		_, meets := searched[zone]
		if dnsHolds(routed, zone) || meets || slices.ContainsFunc(config.search, func(domain string) bool {
			return dnsSuffixContains(zone, domain)
		}) || host[zone] > budget {
			routed[zone] = struct{}{}
			budget--
			continue
		}
		budget -= host[zone]
		split[zone] = struct{}{}
	}
	domains := make(map[string]struct{}, len(config.search)+len(routed)+len(names))
	bytes := 0
	add := func(domain string) {
		if _, counted := domains[domain]; !counted {
			domains[domain] = struct{}{}
			bytes += len(domain)
		}
	}
	for _, domain := range config.search {
		add(domain)
	}
	for route := range routed {
		add(route)
	}
	for _, name := range names {
		if needsOwnRoute(name, routed, split) {
			add(name)
		}
	}
	return len(domains), bytes
}

// fits reports whether names keep the client within the route budget.
func (config clientDNSRoutes) fits(names []string) bool {
	domains, bytes := config.cost(names)
	return domains <= maximumDNSRouteDomains && bytes <= maximumDNSRouteBytes
}

// needsOwnRoute reports a name the client routes on its own: one a zone
// split into its names holds more closely than any route, or that no route
// holds.
func needsOwnRoute(name string, routed, split map[string]struct{}) bool {
	if _, exact := routed[name]; exact {
		return false
	}
	for suffix := range dnsAncestors(name) {
		if _, found := split[suffix]; found {
			return true
		}
		if _, found := routed[suffix]; found {
			return false
		}
	}
	return true
}

// dnsHolds reports whether one of domains is name or holds it.
func dnsHolds(domains map[string]struct{}, name string) bool {
	for suffix := range dnsAncestors(name) {
		if _, found := domains[suffix]; found {
			return true
		}
	}
	return false
}

// dnsAncestors yields name, then each domain that holds it, the shortest
// last, without the root.
func dnsAncestors(name string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for suffix := name; ; {
			if !yield(suffix) {
				return
			}
			_, rest, found := strings.Cut(suffix, ".")
			if !found || rest == "" {
				return
			}
			suffix = rest
		}
	}
}

func dnsSuffixContains(suffix, name string) bool {
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}

// leavesToHost reports a zone the client does not route as a whole by
// itself: one that leaves its other names to the host, or a forward zone
// that fails open with no resolver left.
func (zone DNSForwardZone) leavesToHost() bool {
	return zone.OtherNames == DNSOtherHost ||
		(zone.OtherNames == DNSOtherForward && zone.FailOpen && len(zone.Resolvers) == 0)
}

// routeBudget keeps the routes the client takes whole within the budget,
// in a fixed order: the mesh names (suffix and the Network's zone, always
// within it), the zones routed whole by domain, then the other search
// domains. A zone past it is left out with its search domain (OverBudget
// counts them); left returns the domains of those zones. The zones that
// leave their other names to the host, and the names, come after
// (keepAdminNames).
func (view *DNSView) routeBudget() (config clientDNSRoutes, left map[string]struct{}) {
	seen := make(map[string]struct{})
	domains, bytes := 0, 0
	add := func(domain string) bool {
		if _, counted := seen[domain]; counted {
			return true
		}
		if domains+1 > maximumDNSRouteDomains || bytes+len(domain) > maximumDNSRouteBytes {
			return false
		}
		seen[domain] = struct{}{}
		domains, bytes = domains+1, bytes+len(domain)
		return true
	}
	left = make(map[string]struct{})
	if view.localSuffix != "" && add(view.localSuffix) {
		config.routes = append(config.routes, view.localSuffix)
	}
	if view.searchDomain != "" {
		add(view.searchDomain)
	}
	view.zones = slices.DeleteFunc(view.zones, func(zone DNSForwardZone) bool {
		switch {
		case zone.leavesToHost():
			config.host = append(config.host, zone.Domain)
		case add(zone.Domain):
			config.routes = append(config.routes, zone.Domain)
		default:
			left[zone.Domain] = struct{}{}
			view.overBudget++
			return true
		}
		return false
	})
	view.searchDomains = slices.DeleteFunc(view.searchDomains, func(domain string) bool {
		if _, gone := left[domain]; gone {
			return true
		}
		if !add(domain) {
			view.overBudget++
			return true
		}
		return false
	})
	config.search = view.SearchDomains()
	slices.Sort(config.host)
	return config, left
}

// adminName is one name an administrator set that the view may carry: an
// address record or a CNAME.
type adminName struct {
	record DNSRecord
	alias  *DNSAlias
}

func (name adminName) fqdn() string {
	if name.alias != nil {
		return name.alias.Name
	}
	return name.record.Name
}

// keepAdminNames adds names, in name order, within the route budget. A
// name under a zone the budget left out goes (no zone answers it). A name a
// zone routed whole holds always stays; the others stay in name order while
// the client's routes fit, and past that go whole. When even none of them
// fits, the zones that leave their other names to the host go too, the last
// by domain first. OverBudget counts what goes.
func (view *DNSView) keepAdminNames(config clientDNSRoutes, left map[string]struct{}, names []adminName) {
	routed := make(map[string]struct{}, len(config.routes))
	for _, route := range config.routes {
		routed[route] = struct{}{}
	}
	host := make(map[string]struct{}, len(config.host))
	for _, zone := range config.host {
		host[zone] = struct{}{}
	}
	var free, costly []adminName
	for _, name := range names {
		switch firstDNSHolder(name.fqdn(), routed, host, left) {
		case holderRoute:
			free = append(free, name)
		case holderLeft:
			view.overBudget++
		default:
			costly = append(costly, name)
		}
	}
	fqdns := make([]string, 0, len(names))
	for _, name := range free {
		fqdns = append(fqdns, name.fqdn())
	}
	kept := len(costly)
	if !boundedRoutes(config, costly) {
		with := func(count int) []string {
			all := slices.Clone(fqdns)
			for _, name := range costly[:count] {
				all = append(all, name.fqdn())
			}
			return all
		}
		// The client's cost grows with the names but not strictly: search
		// the largest prefix that fits, then make sure of it.
		kept = sortSearchLast(len(costly), func(count int) bool { return config.fits(with(count)) })
		for kept > 0 && !config.fits(with(kept)) {
			kept--
		}
		view.overBudget += len(costly) - kept
		// None fits: the zones go too, with their search domains (a search
		// domain the client cannot route fails its whole plan).
		for len(config.host) > 0 && !config.fits(with(kept)) {
			gone := config.host[len(config.host)-1]
			config.host = config.host[:len(config.host)-1]
			view.zones = slices.DeleteFunc(view.zones, func(zone DNSForwardZone) bool { return zone.Domain == gone })
			view.searchDomains = slices.DeleteFunc(view.searchDomains, func(domain string) bool {
				return domain == gone
			})
			config.search = view.SearchDomains()
			view.overBudget++
		}
	}
	keep := append(free, costly[:kept]...)
	slices.SortFunc(keep, func(first, second adminName) int { return strings.Compare(first.fqdn(), second.fqdn()) })
	for _, name := range keep {
		if name.alias != nil {
			view.aliases = append(view.aliases, *name.alias)
			continue
		}
		view.records = append(view.records, name.record)
	}
}

// boundedRoutes reports, without following the client, whether the routes
// fit even if every zone leaving its other names to the host were routed
// whole and every costly name had a route of its own: the client never
// routes more.
func boundedRoutes(config clientDNSRoutes, costly []adminName) bool {
	domains, bytes := clientDNSRoutes{routes: config.routes, search: config.search}.cost(nil)
	for _, zone := range config.host {
		domains, bytes = domains+1, bytes+len(zone)
	}
	for _, name := range costly {
		domains, bytes = domains+1, bytes+len(name.fqdn())
	}
	return domains <= maximumDNSRouteDomains && bytes <= maximumDNSRouteBytes
}

type dnsHolder uint8

const (
	holderNone dnsHolder = iota
	holderRoute
	holderHost
	holderLeft
)

// firstDNSHolder returns what holds name most closely: a route, a zone
// leaving its other names to the host, or a zone the budget left out.
func firstDNSHolder(name string, routed, host, left map[string]struct{}) dnsHolder {
	for suffix := range dnsAncestors(name) {
		if _, found := host[suffix]; found {
			return holderHost
		}
		if _, found := routed[suffix]; found {
			return holderRoute
		}
		if _, found := left[suffix]; found {
			return holderLeft
		}
	}
	return holderNone
}

// sortSearchLast returns the largest count in [0, n] for which fits holds,
// assuming fits holds up to some count and not after; 0 when none does.
func sortSearchLast(n int, fits func(int) bool) int {
	low, high := 0, n
	for low < high {
		middle := low + (high-low+1)/2
		if fits(middle) {
			low = middle
		} else {
			high = middle - 1
		}
	}
	return low
}
