//go:build linux

package portmap

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

// routeProbe is a documentation address (RFC 5737); asking the kernel for its
// route returns the IPv4 default route without sending anything.
var routeProbe = net.IPv4(192, 0, 2, 1)

// DefaultGateway returns the IPv4 default gateway and the source address the
// kernel uses towards it.
func DefaultGateway() (Gateway, error) {
	routes, err := netlink.RouteGet(routeProbe)
	if err != nil {
		return Gateway{}, fmt.Errorf("portmap: reading the default route: %w", err)
	}
	for _, route := range routes {
		gw, okGW := netip.AddrFromSlice(route.Gw)
		local, okLocal := netip.AddrFromSlice(route.Src)
		if !okGW || !okLocal {
			continue
		}
		gateway := Gateway{Addr: gw.Unmap(), Local: local.Unmap()}
		if gateway.Valid() {
			return gateway, nil
		}
	}

	return Gateway{}, ErrNoGateway
}
