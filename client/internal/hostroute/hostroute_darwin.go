package hostroute

import (
	"fmt"
	"math/bits"
	"net/netip"
	"slices"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// Mark tells the routes meshnetd installs for subnet routes apart in the
// host's single routing table: from the overlay routes on the same utun and
// from everyone else's. macOS sets neither protocol flag itself.
const Mark = unix.RTF_PROTO1 | unix.RTF_PROTO2

// Route is one route of the host's routing table.
type Route struct {
	Prefix  netip.Prefix
	Flags   int
	Index   int
	Gateway route.Addr
}

// Marked reports a route carrying meshnetd's mark.
func (r Route) Marked() bool { return r.Flags&Mark == Mark }

// Owned reports a route meshnetd installed: marked, static and not one the
// kernel derived, which never carries the mark of the route it came from.
func (r Route) Owned() bool { return r.Marked() && r.Flags&unix.RTF_STATIC != 0 && !r.Cloned() }

// MeshLinks returns the interfaces meshnetd's subnet routes use: the mesh
// utun.
func MeshLinks(table []Route) []int {
	var links []int
	for _, entry := range table {
		if entry.Owned() && entry.Flags&unix.RTF_GATEWAY == 0 && !slices.Contains(links, entry.Index) {
			links = append(links, entry.Index)
		}
	}
	return links
}

// SameGateway reports whether two routes' gateways are the same address, or
// the same link.
func SameGateway(first, second route.Addr) bool {
	switch a := first.(type) {
	case *route.Inet4Addr:
		b, ok := second.(*route.Inet4Addr)
		return ok && a.IP == b.IP
	case *route.Inet6Addr:
		b, ok := second.(*route.Inet6Addr)
		return ok && a.IP == b.IP && a.ZoneID == b.ZoneID
	case *route.LinkAddr:
		b, ok := second.(*route.LinkAddr)
		return ok && a.Index == b.Index
	default:
		return false
	}
}

// Cloned reports a route the kernel derived from another (a host's ARP or
// neighbour entry, a cached path) or one only scoped lookups use: neither is
// a network the host routes to.
func (r Route) Cloned() bool {
	return r.Flags&(unix.RTF_WASCLONED|unix.RTF_LLINFO|unix.RTF_IFSCOPE|unix.RTF_BROADCAST) != 0
}

// Read returns the host's IPv4 and IPv6 unicast routes.
func Read() ([]Route, error) {
	raw, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, fmt.Errorf("hostroute: reading the routing table: %w", err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, raw)
	if err != nil {
		return nil, fmt.Errorf("hostroute: parsing the routing table: %w", err)
	}
	return Parse(messages), nil
}

// Parse keeps the IPv4 and IPv6 unicast routes of a routing table dump.
func Parse(messages []route.Message) []Route {
	routes := make([]Route, 0, len(messages))
	for _, message := range messages {
		entry, ok := message.(*route.RouteMessage)
		if !ok || len(entry.Addrs) <= unix.RTAX_GATEWAY {
			continue
		}
		prefix, ok := prefixOf(entry)
		if !ok {
			continue
		}
		routes = append(routes, Route{
			Prefix: prefix, Flags: entry.Flags, Index: entry.Index, Gateway: entry.Addrs[unix.RTAX_GATEWAY],
		})
	}
	return routes
}

// Physical returns the most specific route the host itself uses for
// address, skipping the mesh links, marked and cloned routes: the path a
// socket must take to stay off the mesh.
func Physical(table []Route, skip []int, address netip.Addr) (Route, bool) {
	best, found := Route{}, false
	for _, entry := range table {
		if slices.Contains(skip, entry.Index) || entry.Marked() || entry.Cloned() || entry.Gateway == nil ||
			!entry.Prefix.Contains(address) {
			continue
		}
		if !found || entry.Prefix.Bits() > best.Prefix.Bits() {
			best, found = entry, true
		}
	}
	return best, found
}

// prefixOf reads a route's destination and netmask; a host route has none.
func prefixOf(entry *route.RouteMessage) (netip.Prefix, bool) {
	address, ok := inetAddr(entry.Addrs[unix.RTAX_DST])
	if !ok {
		return netip.Prefix{}, false
	}
	if entry.Flags&unix.RTF_HOST != 0 {
		return netip.PrefixFrom(address, address.BitLen()), true
	}
	length := 0
	if len(entry.Addrs) > unix.RTAX_NETMASK && entry.Addrs[unix.RTAX_NETMASK] != nil {
		var mask []byte
		switch value := entry.Addrs[unix.RTAX_NETMASK].(type) {
		case *route.Inet4Addr:
			mask = value.IP[:]
		case *route.Inet6Addr:
			mask = value.IP[:]
		default:
			return netip.Prefix{}, false
		}
		var contiguous bool
		if length, contiguous = maskLength(mask, address.BitLen()); !contiguous {
			return netip.Prefix{}, false
		}
	}
	return netip.PrefixFrom(address, length).Masked(), true
}

// maskLength counts a netmask's leading ones, up to the address length, and
// reports whether no one follows a zero.
func maskLength(mask []byte, addressBits int) (int, bool) {
	length, ended := 0, false
	for index, value := range mask {
		if index*8 >= addressBits {
			break
		}
		ones := bits.LeadingZeros8(^value)
		if ended && value != 0 || ones < 8 && value<<ones != 0 {
			return 0, false
		}
		length += ones
		ended = ended || ones < 8
	}
	return length, true
}

func inetAddr(value route.Addr) (netip.Addr, bool) {
	switch address := value.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(address.IP), true
	case *route.Inet6Addr:
		return netip.AddrFrom16(address.IP), true
	default:
		return netip.Addr{}, false
	}
}
