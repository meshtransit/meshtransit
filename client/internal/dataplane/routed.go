package dataplane

import (
	"net/netip"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/internet"
)

// routedSite is one Site of the map as the packet path handles it
// (mtcp-v1 §7.6).
type routedSite struct {
	ref string
	// served means packets to the Site go through primary; otherwise they
	// are answered unreachable.
	served  bool
	primary packetAuthority
}

// routedExit is the exit node the node chose (networkmap.ExitRoute) as the
// packet path handles it (mtcp-v1 §7.7).
type routedExit struct {
	pool string
	// served means Internet packets go through node; otherwise they are
	// dropped, never sent outside the mesh.
	served bool
	// nodeRef is the exit node's device ID, node its packet authority.
	nodeRef string
	node    packetAuthority
	ipv6    bool
}

// routedTable finds the Site of an address among the map's at most 4,096
// routed prefixes, and the exit node of the others on the Internet.
type routedTable struct {
	sites    []routedSite
	prefixes *prefixIndex[int]
	exit     *routedExit
}

// newRoutedTable indexes the map's Sites. A Site whose prefixes overlap
// another's is not served (networkmap.EffectiveStatus), and neither is one
// whose primary is not a peer of the map. A prefix containing a mesh address
// of this node or a peer is left out entirely: a router must never take over
// a node's own address, in WireGuard or in the routing table.
func newRoutedTable(snapshot networkmap.Snapshot) *routedTable {
	if len(snapshot.Routes) == 0 && snapshot.ExitRoute == nil {
		return nil
	}
	peers := make(map[string]networkmap.Node, len(snapshot.Peers))
	for _, peer := range snapshot.Peers {
		peers[peer.StableID] = peer
	}
	table := &routedTable{prefixes: newPrefixIndex[int](0)}
	if route := snapshot.ExitRoute; route != nil {
		table.exit = &routedExit{pool: route.Pool, ipv6: route.IPv6}
		if peer, found := peers[route.Node]; found && route.Node != "" {
			table.exit.served, table.exit.nodeRef, table.exit.node = true, route.Node, authorityFor(peer)
		}
	}
	if len(snapshot.Routes) == 0 {
		return table
	}
	statuses := networkmap.EffectiveStatus(snapshot.Routes)
	table.sites = make([]routedSite, 0, len(snapshot.Routes))
	for index, route := range snapshot.Routes {
		site := routedSite{ref: route.Ref}
		if primary, found := peers[route.Primary]; found && statuses[index] == networkmap.RouteServed {
			site.served, site.primary = true, authorityFor(primary)
		}
		table.sites = append(table.sites, site)
		for _, prefix := range route.Prefixes {
			// Equal prefixes of two Sites put both in conflict, unserved:
			// either answers the same.
			table.prefixes.add(prefix, len(table.sites)-1)
		}
	}
	table.removeMeshAddresses(snapshot.Self)
	for _, peer := range snapshot.Peers {
		table.removeMeshAddresses(peer)
	}
	return table
}

// removeMeshAddresses drops the prefixes containing a node's mesh addresses,
// Device alias addresses included.
func (t *routedTable) removeMeshAddresses(node networkmap.Node) {
	for _, address := range node.Addresses {
		t.prefixes.removeContaining(address.Addr())
	}
	if node.Alias != nil {
		t.prefixes.removeContaining(node.Alias.SelfIPv4)
		t.prefixes.removeContaining(node.Alias.SelfIPv6)
	}
}

// lookup returns the most specific routed prefix containing address and its
// Site.
func (t *routedTable) lookup(address netip.Addr) (netip.Prefix, *routedSite, bool) {
	if t == nil {
		return netip.Prefix{}, nil, false
	}
	prefix, index, found := t.prefixes.lookup(address)
	if !found {
		return netip.Prefix{}, nil, false
	}
	return prefix, &t.sites[index], true
}

// servedPrefixes returns, per primary's node id, the prefixes of the Sites
// it serves, sorted, then the default routes of the exit node: the
// WireGuard allowed IPs routed traffic needs. Only the chosen exit node
// holds a default route, so an Internet source is accepted from it alone;
// a mesh address or a Site prefix stays with its own peer, the most
// specific match, whatever source the exit node puts on its packets.
func (t *routedTable) servedPrefixes() map[uint64][]netip.Prefix {
	if t == nil {
		return nil
	}
	served := map[uint64][]netip.Prefix{}
	for _, prefix := range t.prefixes.sorted() {
		if site := t.sites[t.prefixes.values[prefix]]; site.served {
			served[site.primary.nodeID] = append(served[site.primary.nodeID], prefix)
		}
	}
	if exit := t.exit; exit != nil && exit.served {
		served[exit.node.nodeID] = append(served[exit.node.nodeID], exit.prefixes()...)
	}
	return served
}

// prefixes are the default routes the exit node takes.
func (exit *routedExit) prefixes() []netip.Prefix {
	routes := []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)}
	if exit.ipv6 {
		routes = append(routes, netip.PrefixFrom(netip.IPv6Unspecified(), 0))
	}
	return routes
}

// exitFor returns the exit node that carries traffic with an Internet
// address, of a family it carries.
func (t *routedTable) exitFor(address netip.Addr) (packetAuthority, bool) {
	if t == nil || t.exit == nil || !t.exit.served || !internet.Contains(address) ||
		(address.Is6() && !t.exit.ipv6) {
		return packetAuthority{}, false
	}
	return t.exit.node, true
}

// routedPrefixesOf returns every prefix of the map's Sites, sorted: the
// routes meshd asks the helper to install, whatever each Site's status, so
// traffic to an unserved Site is answered here instead of leaving by the
// default route (mtcp-v1 §7.6).
func routedPrefixesOf(snapshot networkmap.Snapshot) []netip.Prefix {
	return newRoutedTable(snapshot).allPrefixes()
}

func (t *routedTable) allPrefixes() []netip.Prefix {
	if t == nil {
		return nil
	}
	return t.prefixes.sorted()
}

// equalRoutedTables reports whether both tables route every address the same
// way.
func equalRoutedTables(first, second *routedTable) bool {
	if first == nil || second == nil {
		return first == second
	}
	if !equalRoutedExits(first.exit, second.exit) || first.prefixes.len() != second.prefixes.len() {
		return false
	}
	for prefix, index := range first.prefixes.values {
		other, found := second.prefixes.values[prefix]
		if !found || !equalRoutedSite(first.sites[index], second.sites[other]) {
			return false
		}
	}
	return true
}

func equalRoutedSite(first, second routedSite) bool {
	return first.ref == second.ref && first.served == second.served && first.primary.equal(second.primary)
}

func equalRoutedExits(first, second *routedExit) bool {
	if first == nil || second == nil {
		return first == second
	}
	return first.pool == second.pool && first.served == second.served && first.nodeRef == second.nodeRef &&
		first.node.equal(second.node) && first.ipv6 == second.ipv6
}
