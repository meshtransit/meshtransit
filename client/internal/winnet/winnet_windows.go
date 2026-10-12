//go:build windows

package winnet

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Configure gives the adapter exactly addresses (host prefixes), on-link
// routes to routes, and mtu for every address family it uses.
func Configure(luid uint64, mtu int, addresses, routes []netip.Prefix) error {
	if mtu < 1280 || mtu > 9000 {
		return fmt.Errorf("winnet: mtu %d is outside 1280-9000", mtu)
	}
	adapter := winipcfg.LUID(luid)
	if err := adapter.SetIPAddresses(addresses); err != nil {
		return fmt.Errorf("winnet: setting adapter addresses: %w", err)
	}
	for _, family := range families(addresses) {
		if err := setMTU(adapter, family, mtu); err != nil {
			return err
		}
	}

	return ReplaceRoutes(luid, routes)
}

// ReplaceRoutes makes routes the adapter's only on-link routes.
func ReplaceRoutes(luid uint64, routes []netip.Prefix) error {
	data := make([]*winipcfg.RouteData, 0, len(routes))
	for _, route := range routes {
		if !route.IsValid() || route != route.Masked() {
			return fmt.Errorf("winnet: route %s is not a canonical prefix", route)
		}
		nextHop := netip.IPv4Unspecified()
		if route.Addr().Is6() {
			nextHop = netip.IPv6Unspecified()
		}
		data = append(data, &winipcfg.RouteData{Destination: route, NextHop: nextHop})
	}
	if err := winipcfg.LUID(luid).SetRoutes(data); err != nil {
		return fmt.Errorf("winnet: setting adapter routes: %w", err)
	}

	return nil
}

// Index returns the adapter's interface index, which other Windows APIs and
// net.Interface use.
func Index(luid uint64) (uint32, error) {
	row, err := winipcfg.LUID(luid).Interface()
	if err != nil {
		return 0, fmt.Errorf("winnet: reading the adapter: %w", err)
	}

	return row.InterfaceIndex, nil
}

func setMTU(adapter winipcfg.LUID, family winipcfg.AddressFamily, mtu int) error {
	row, err := adapter.IPInterface(family)
	if errors.Is(err, windows.ERROR_NOT_FOUND) {
		return nil // the family is not bound to the adapter
	}
	if err != nil {
		return fmt.Errorf("winnet: reading the adapter interface: %w", err)
	}
	row.NLMTU = uint32(mtu) //nolint:gosec // Bounded to 1280-9000 above.
	if err := row.Set(); err != nil {
		return fmt.Errorf("winnet: setting the adapter mtu: %w", err)
	}

	return nil
}

func families(addresses []netip.Prefix) []winipcfg.AddressFamily {
	var hasV4, hasV6 bool
	for _, address := range addresses {
		hasV4 = hasV4 || address.Addr().Is4()
		hasV6 = hasV6 || address.Addr().Is6()
	}
	var result []winipcfg.AddressFamily
	if hasV4 {
		result = append(result, windows.AF_INET)
	}
	if hasV6 {
		result = append(result, windows.AF_INET6)
	}

	return result
}
