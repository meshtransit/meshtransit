package underlay

import (
	"net/netip"
	"slices"
	"sync/atomic"
)

// routedSet holds installed subnet routes for a lookup of a few map probes:
// one per prefix length in use, of the address's family.
type routedSet struct {
	prefixes map[netip.Prefix]struct{}
	lengths4 []int
	lengths6 []int
}

var routed atomic.Pointer[routedSet]

// SetRouted records the subnet routes installed on the mesh TUN, where the
// client's own sockets would follow them (FollowsRoutes): a socket to an
// address inside one is bound to the physical path, and the packet path
// sends no datagram there. An empty list clears them.
func SetRouted(prefixes []netip.Prefix) {
	if len(prefixes) == 0 {
		routed.Store(nil)
		return
	}
	set := &routedSet{prefixes: make(map[netip.Prefix]struct{}, len(prefixes))}
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		if !prefix.IsValid() {
			continue
		}
		set.prefixes[prefix] = struct{}{}
		lengths := &set.lengths6
		if prefix.Addr().Is4() {
			lengths = &set.lengths4
		}
		if !slices.Contains(*lengths, prefix.Bits()) {
			*lengths = append(*lengths, prefix.Bits())
		}
	}
	routed.Store(set)
}

// Routed reports whether an installed subnet route covers address.
func Routed(address netip.Addr) bool {
	set := routed.Load()
	if set == nil || !address.IsValid() {
		return false
	}
	address = address.Unmap()
	lengths := set.lengths6
	if address.Is4() {
		lengths = set.lengths4
	}
	for _, bits := range lengths {
		prefix, err := address.Prefix(bits)
		if err != nil {
			continue
		}
		if _, found := set.prefixes[prefix]; found {
			return true
		}
	}
	return false
}
