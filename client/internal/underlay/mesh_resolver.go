package underlay

import (
	"net/netip"

	"meshtransit.net/client/internal/overlayframe"
)

// meshResolver reports an address MeshTransit's resolver listens on, or one
// of the mesh: never the host's network's.
func meshResolver(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsLoopback() || address.IsUnspecified() || testNet.Contains(address) ||
		overlayframe.Contains(netip.PrefixFrom(address, address.BitLen()))
}
