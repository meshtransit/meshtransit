package networkmap

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Bounds of the subnet routes of one map (mtcp-v1 §14).
const (
	maxRouteSites          = 1_024
	maxRouteSitePrefixes   = 1_024
	maxRoutePrefixes       = 4_096
	maxRouteCandidates     = 32
	maxRouteRouters        = 256
	maxRouteSiteReferences = 64
)

// RouteStatus is what Core says a node may do with a Site (mtcp-v1 §7.6).
type RouteStatus uint8

const (
	// RouteStatusUnknown is invalid in a map.
	RouteStatusUnknown RouteStatus = iota
	// RouteServed means forward through the primary.
	RouteServed
	// RouteUnserved means granted, but no router can serve now.
	RouteUnserved
	// RouteConflict means the Site overlaps another granted Site.
	RouteConflict
	// RouteCapacity means the routers' maps cannot hold this node.
	RouteCapacity
)

// SiteRoute is one Site the node may reach: the prefixes its rules grant
// and the routers (peers by StableID) that forward to them.
type SiteRoute struct {
	Ref string
	// Name is the Site's display name, empty when Core sent none or one
	// the node would not show (SiteName).
	Name       string
	Prefixes   []netip.Prefix
	Candidates []string
	Primary    string // empty: none
	Generation uint64
	Status     RouteStatus
}

// validateRoutes checks routes as mtcp-v1 §7.6 requires of a map: Sites
// sorted by reference and listed once; canonical, sorted prefixes within the
// bounds; distinct candidates other than self, a primary among them, and a
// primary whenever the Site is SERVED. Overlap between Sites is not
// malformed: the node handles those Sites as CONFLICT (EffectiveStatus).
func validateRoutes(routes []SiteRoute, self string) error {
	if len(routes) > maxRouteSites {
		return fmt.Errorf("more than %d Sites", maxRouteSites)
	}
	prefixes, routers := 0, make(map[string]struct{})
	for index, route := range routes {
		if route.Ref == "" || len(route.Ref) > maxRouteSiteReferences || !utf8.ValidString(route.Ref) ||
			(index > 0 && routes[index-1].Ref >= route.Ref) {
			return errors.New("site references must be valid, sorted and listed once")
		}
		if len(route.Prefixes) == 0 || len(route.Prefixes) > maxRouteSitePrefixes {
			return fmt.Errorf("site %q has no or too many prefixes", route.Ref)
		}
		prefixes += len(route.Prefixes)
		for position, prefix := range route.Prefixes {
			if !canonicalRoutePrefix(prefix) ||
				(position > 0 && compareRoutePrefixes(route.Prefixes[position-1], prefix) >= 0) {
				return fmt.Errorf("site %q prefixes must be canonical, sorted and listed once", route.Ref)
			}
		}
		if len(route.Candidates) > maxRouteCandidates {
			return fmt.Errorf("site %q has more than %d candidates", route.Ref, maxRouteCandidates)
		}
		for position, candidate := range route.Candidates {
			if candidate == "" || candidate == self || slices.Contains(route.Candidates[:position], candidate) {
				return fmt.Errorf("site %q candidates must be distinct peers", route.Ref)
			}
			routers[candidate] = struct{}{}
		}
		if (route.Primary != "" && !slices.Contains(route.Candidates, route.Primary)) ||
			(route.Status == RouteServed && route.Primary == "") ||
			route.Status < RouteServed || route.Status > RouteCapacity {
			return fmt.Errorf("site %q has an invalid primary or status", route.Ref)
		}
	}
	if prefixes > maxRoutePrefixes || len(routers) > maxRouteRouters {
		return errors.New("routes exceed the map bounds")
	}
	return nil
}

// canonicalRoutePrefix accepts a prefix with no host bits, not IPv4-mapped
// and not a default route.
func canonicalRoutePrefix(prefix netip.Prefix) bool {
	return prefix.IsValid() && prefix == prefix.Masked() && !prefix.Addr().Is4In6() && prefix.Addr().Zone() == "" &&
		prefix.Bits() > 0
}

// compareRoutePrefixes orders IPv4 before IPv6, then by address bytes, then
// by length (mtcp-v1 §7.6).
func compareRoutePrefixes(first, second netip.Prefix) int {
	if order := first.Addr().Compare(second.Addr()); order != 0 {
		return order
	}
	return first.Bits() - second.Bits()
}

// EffectiveStatus returns each Site's status as the node must handle it:
// Core's, except CONFLICT for every Site whose prefixes overlap another's.
// Two prefixes overlap when one contains the other, so one sorted sweep
// with the chain of containing prefixes finds every pair: O(n log n) over the
// map's at most 4,096 prefixes.
func EffectiveStatus(routes []SiteRoute) []RouteStatus {
	statuses := make([]RouteStatus, len(routes))
	type entry struct {
		prefix netip.Prefix
		site   int
	}
	var entries []entry
	for index, route := range routes {
		statuses[index] = route.Status
		for _, prefix := range route.Prefixes {
			entries = append(entries, entry{prefix: prefix, site: index})
		}
	}
	slices.SortFunc(entries, func(first, second entry) int { return compareRoutePrefixes(first.prefix, second.prefix) })
	var chain []entry
	for _, current := range entries {
		for len(chain) > 0 && !chain[len(chain)-1].prefix.Contains(current.prefix.Addr()) {
			chain = chain[:len(chain)-1]
		}
		for _, outer := range chain {
			if outer.site != current.site {
				statuses[outer.site], statuses[current.site] = RouteConflict, RouteConflict
			}
		}
		chain = append(chain, current)
	}
	return statuses
}

func cloneRoutes(routes []SiteRoute) []SiteRoute {
	if routes == nil {
		return nil
	}
	cloned := make([]SiteRoute, len(routes))
	for index, route := range routes {
		route.Prefixes, route.Candidates = slices.Clone(route.Prefixes), slices.Clone(route.Candidates)
		cloned[index] = route
	}
	return cloned
}

// maxSiteNameCharacters bounds a Site's display name (mtcp-v1 §7.6).
const maxSiteNameCharacters = 64

// SiteName returns name when a node may show it: UTF-8, at most 64
// characters, no control characters. Otherwise it returns "": a name is for
// status only, so a bad one costs the name, never the map.
func SiteName(name string) string {
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > maxSiteNameCharacters ||
		strings.ContainsFunc(name, unicode.IsControl) {
		return ""
	}
	return name
}
