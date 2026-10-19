//go:build linux || darwin

package netadmin

import (
	"bufio"
	"bytes"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"

	"meshtransit.net/client/internal/routesettings"
)

// localRoute is one route of the host's own (main) table on another
// interface than the mesh's.
type localRoute struct {
	Prefix netip.Prefix
	// Connected marks a network the host is directly attached to.
	Connected bool
}

// hostRouting reads what the local route checks need from the host.
type hostRouting interface {
	// LocalRoutes returns the main table's routes other than default routes
	// and those on the mesh interface.
	LocalRoutes(meshInterface string) ([]localRoute, error)
	// Resolvers returns the system DNS servers learned from the physical
	// network.
	Resolvers() []netip.Addr
}

// withoutLocalConflicts drops each route that overlaps a network the host
// is attached to, or that an equal or more specific route of the host
// already covers in part: the mesh must never take over the host's own LAN or a
// network another path reaches (mtcp-v1 §7.6). A wider local route, such as
// another VPN's, is no conflict: the routed table is consulted first.
//
// The check is indexed: each route costs one binary search over the sorted
// local routes and one map lookup per attached prefix length.
func withoutLocalConflicts(routes []netip.Prefix, local []localRoute) ([]netip.Prefix, []routesettings.Refusal) {
	sorted := make([]netip.Prefix, 0, len(local))
	connected := map[netip.Prefix]struct{}{}
	connectedLengths := map[bool][]int{}
	for _, other := range local {
		sorted = append(sorted, other.Prefix)
		if !other.Connected {
			continue
		}
		connected[other.Prefix] = struct{}{}
		family := other.Prefix.Addr().Is4()
		if !slices.Contains(connectedLengths[family], other.Prefix.Bits()) {
			connectedLengths[family] = append(connectedLengths[family], other.Prefix.Bits())
		}
	}
	slices.SortFunc(sorted, compareRoutedPrefixes)
	kept := make([]netip.Prefix, 0, len(routes))
	var refused []routesettings.Refusal
	for _, route := range routes {
		if coversLocalRoute(sorted, route) || insideConnected(connected, connectedLengths[route.Addr().Is4()], route) {
			refused = append(refused, routesettings.Refusal{Prefix: route, Reason: routesettings.ReasonLocalConflict})
			continue
		}
		kept = append(kept, route)
	}
	return kept, refused
}

// coversLocalRoute reports whether route contains or equals a local route:
// sorted by address, those start at route's first address.
func coversLocalRoute(sorted []netip.Prefix, route netip.Prefix) bool {
	start, _ := slices.BinarySearchFunc(sorted, route.Masked().Addr(), func(prefix netip.Prefix, address netip.Addr) int {
		return prefix.Addr().Compare(address)
	})
	for _, other := range sorted[start:] {
		if !route.Contains(other.Addr()) {
			return false
		}
		if other.Bits() >= route.Bits() {
			return true
		}
	}
	return false
}

// insideConnected reports whether an attached network contains route.
func insideConnected(connected map[netip.Prefix]struct{}, lengths []int, route netip.Prefix) bool {
	for _, bits := range lengths {
		if bits >= route.Bits() {
			continue // equal or narrower: coversLocalRoute finds it
		}
		if _, found := connected[netip.PrefixFrom(route.Addr(), bits).Masked()]; found {
			return true
		}
	}
	return false
}

// pinnedResolvers returns the host routes that keep system resolvers inside
// installed routes on the physical network, sorted and listed once.
func pinnedResolvers(routes []netip.Prefix, resolvers []netip.Addr) []netip.Prefix {
	var pinned []netip.Prefix
	for _, resolver := range resolvers {
		resolver = resolver.Unmap().WithZone("")
		if !resolver.IsValid() || !slices.ContainsFunc(routes, func(route netip.Prefix) bool { return route.Contains(resolver) }) {
			continue
		}
		pinned = append(pinned, netip.PrefixFrom(resolver, resolver.BitLen()))
	}
	slices.SortFunc(pinned, compareRoutedPrefixes)
	return slices.Compact(pinned)
}

// maxResolverFileBytes bounds one resolver configuration file.
const maxResolverFileBytes = 64 << 10

// readResolvers reads the nameserver lines of the resolver files, skipping
// loopback stubs and files that are missing or unreadable.
func readResolvers(paths []string) []netip.Addr {
	var resolvers []netip.Addr
	for _, path := range paths {
		file, err := os.Open(path) //nolint:gosec // G304: fixed system paths
		if err != nil {
			continue
		}
		content, err := io.ReadAll(io.LimitReader(file, maxResolverFileBytes))
		_ = file.Close()
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 2 || fields[0] != "nameserver" {
				continue
			}
			address, err := netip.ParseAddr(fields[1])
			if err != nil || address.IsLoopback() {
				continue
			}
			resolvers = append(resolvers, address.WithZone(""))
		}
	}
	return resolvers
}
