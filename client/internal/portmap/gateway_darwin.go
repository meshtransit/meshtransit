package portmap

import (
	"fmt"
	"net/netip"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// rtfIfscope marks a per-interface copy of a route (RTF_IFSCOPE).
const rtfIfscope = 0x1000000

// DefaultGateway returns the IPv4 default gateway and the source address the
// kernel uses towards it.
func DefaultGateway() (Gateway, error) {
	rib, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return Gateway{}, fmt.Errorf("portmap: reading the routing table: %w", err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return Gateway{}, fmt.Errorf("portmap: parsing the routing table: %w", err)
	}
	gateway, ok := defaultIPv4Gateway(messages)
	if !ok {
		return Gateway{}, ErrNoGateway
	}
	local, err := sourceAddressTowards(gateway)
	if err != nil {
		return Gateway{}, err
	}
	result := Gateway{Addr: gateway, Local: local}
	if !result.Valid() {
		return Gateway{}, ErrNoGateway
	}
	return result, nil
}

// defaultIPv4Gateway finds the unscoped IPv4 default route's gateway.
func defaultIPv4Gateway(messages []route.Message) (netip.Addr, bool) {
	for _, message := range messages {
		routeMessage, ok := message.(*route.RouteMessage)
		if !ok || routeMessage.Flags&rtfIfscope != 0 ||
			routeMessage.Flags&(unix.RTF_UP|unix.RTF_GATEWAY) != unix.RTF_UP|unix.RTF_GATEWAY ||
			len(routeMessage.Addrs) <= unix.RTAX_GATEWAY {
			continue
		}
		destination, ok := routeMessage.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
		if !ok || destination.IP != [4]byte{} {
			continue
		}
		if len(routeMessage.Addrs) > unix.RTAX_NETMASK {
			if mask, ok := routeMessage.Addrs[unix.RTAX_NETMASK].(*route.Inet4Addr); ok && mask.IP != [4]byte{} {
				continue
			}
		}
		if gateway, ok := routeMessage.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr); ok {
			return netip.AddrFrom4(gateway.IP), true
		}
	}
	return netip.Addr{}, false
}
