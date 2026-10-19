package dataplane

import (
	"net/netip"

	"meshtransit.net/client/internal/networkmap"
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

// routedTable finds the Site of an address among the map's at most 4,096
// routed prefixes.
type routedTable struct {
	sites    []routedSite
	prefixes *prefixIndex[int]
}

// newRoutedTable indexes the map's Sites. A Site whose prefixes overlap
// another's is not served (networkmap.EffectiveStatus), and neither is one
// whose primary is not a peer of the map. A prefix containing a mesh address
// of this node or a peer is left out entirely: a router must never take over
// a node's own address, in WireGuard or in the routing table.
func newRoutedTable(snapshot networkmap.Snapshot) *routedTable {
	if len(snapshot.Routes) == 0 {
		return nil
	}
	peers := make(map[string]networkmap.Node, len(snapshot.Peers))
	for _, peer := range snapshot.Peers {
		peers[peer.StableID] = peer
	}
	statuses := networkmap.EffectiveStatus(snapshot.Routes)
	table := &routedTable{sites: make([]routedSite, 0, len(snapshot.Routes)), prefixes: newPrefixIndex[int](0)}
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
// it serves, sorted: the WireGuard allowed IPs routed traffic needs.
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
	return served
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
	if first.prefixes.len() != second.prefixes.len() {
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
