package dataplane

import "net/netip"

// SetHostAddressSource makes the engine take this host's underlay addresses
// from source instead of listing the system's interfaces. Mobile platforms
// forbid apps the interface list (Android denies the netlink socket) but
// tell them each network's addresses; source returns those, for every
// network except the app's own VPN. Call it before the engine runs.
func (e *WireGuardEngine) SetHostAddressSource(source func() []netip.Addr) {
	if e == nil || source == nil {
		return
	}
	e.hostAddresses = func() ([]netip.Addr, error) { return platformHostAddresses(source()), nil }
}

// platformHostAddresses keeps the addresses a peer could reach, as
// usableHostAddresses does for interfaces, and applies the IPv6 limits.
// The platform reports no address lifetimes, so every IPv6 address counts
// as stable.
func platformHostAddresses(addresses []netip.Addr) []netip.Addr {
	usable := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() ||
			address.IsLinkLocalUnicast() || address.Zone() != "" || meshOverlayAddress(address) {
			continue
		}
		usable = append(usable, address)
	}

	return selectIPv6HostAddresses(usable, nil)
}
