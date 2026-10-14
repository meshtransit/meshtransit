//go:build darwin || windows

package portmap

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"meshtransit.net/client/internal/underlay"
)

// sourceAddressTowards asks the kernel which local address it would use: a
// connected UDP socket picks one without sending anything.
func sourceAddressTowards(gateway netip.Addr) (netip.Addr, error) {
	connection, err := underlay.Dialer(0).DialContext(context.Background(), "udp4",
		netip.AddrPortFrom(gateway, gatewayPort).String())
	if err != nil {
		return netip.Addr{}, fmt.Errorf("portmap: finding the local address: %w", err)
	}
	defer func() { _ = connection.Close() }()
	local, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, ErrNoGateway
	}
	address, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		return netip.Addr{}, ErrNoGateway
	}
	return address.Unmap(), nil
}
