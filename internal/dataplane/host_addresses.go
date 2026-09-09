package dataplane

import (
	"fmt"
	"net"
	"net/netip"
)

func localHostAddresses() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("dataplane: listing host interfaces: %w", err)
	}
	addresses := make([]netip.Addr, 0, len(interfaces)*2)
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 ||
			networkInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		interfaceAddresses, err := networkInterface.Addrs()
		if err != nil {
			continue
		}
		for _, rawAddress := range interfaceAddresses {
			address, valid := hostAddress(rawAddress)
			if valid {
				addresses = append(addresses, address)
			}
		}
	}

	return addresses, nil
}

func hostAddress(raw net.Addr) (netip.Addr, bool) {
	var value net.IP
	switch address := raw.(type) {
	case *net.IPNet:
		value = address.IP
	case *net.IPAddr:
		if address.Zone != "" {
			return netip.Addr{}, false
		}
		value = address.IP
	default:
		return netip.Addr{}, false
	}
	parsed, valid := netip.AddrFromSlice(value)
	if !valid {
		return netip.Addr{}, false
	}

	return parsed.Unmap(), true
}
