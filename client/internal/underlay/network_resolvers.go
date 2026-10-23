package underlay

import (
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"
)

// NetworkResolver is a DNS server of one of the host's networks, as a
// mobile platform reports it: Network names the network (Android's network
// handle) whose sockets reach it, 0 for none.
type NetworkResolver struct {
	Address netip.AddrPort
	Network int64
}

// NetworkBinder binds the socket fd to the platform network named network,
// after it was protected (Android Network.bindSocket).
type NetworkBinder func(fd uintptr, network int64) error

var (
	reportedResolvers  atomic.Pointer[[]NetworkResolver]
	resolverGeneration atomic.Uint64
	networkBinder      atomic.Pointer[NetworkBinder]
	meshRoutes         atomic.Pointer[[]netip.Prefix]
	privateReach       atomic.Pointer[func(netip.Addr) bool]
)

// SetReportedResolvers records the DNS servers of the host's networks a
// mobile platform reported, best first; NetworkResolvers returns them where
// the host has no resolver list of its own to read. nil clears them.
func SetReportedResolvers(resolvers []NetworkResolver) {
	cloned := slices.Clone(resolvers)
	reportedResolvers.Store(&cloned)
	resolverGeneration.Add(1)
}

// ReportedResolvers returns what SetReportedResolvers recorded.
func ReportedResolvers() []NetworkResolver {
	if resolvers := reportedResolvers.Load(); resolvers != nil {
		return slices.Clone(*resolvers)
	}
	return nil
}

// ReportedGeneration changes whenever SetReportedResolvers is called.
func ReportedGeneration() uint64 { return resolverGeneration.Load() }

// SetNetworkBinder installs bind for the sockets to a reported resolver of
// a known network, or removes it when bind is nil.
func SetNetworkBinder(bind NetworkBinder) {
	if bind == nil {
		networkBinder.Store(nil)
		return
	}
	networkBinder.Store(&bind)
}

// bindNetwork binds the socket to destination to the network of the
// reported resolver at destination, if there is one and a binder.
func bindNetwork(raw interface{ Control(func(uintptr)) error }, destination netip.AddrPort) error {
	bind := networkBinder.Load()
	if bind == nil {
		return nil
	}
	var network int64
	for _, resolver := range ReportedResolvers() {
		if resolver.Address == destination && resolver.Network != 0 {
			network = resolver.Network
			break
		}
	}
	if network == 0 {
		return nil
	}
	var bindErr error
	if err := raw.Control(func(fd uintptr) { bindErr = (*bind)(fd, network) }); err != nil {
		return fmt.Errorf("underlay: reaching the socket: %w", err)
	}
	if bindErr != nil {
		return fmt.Errorf("underlay: binding a socket to %s to its network: %w", destination, bindErr)
	}
	return nil
}

// SetMeshRoutes records the subnet routes a mobile VPN interface carries:
// a socket the client opens to an address inside one goes through the VPN
// to the Site, under its rules, like the device's other traffic (DNS design
// D4 §3.3). An empty list clears them.
func SetMeshRoutes(prefixes []netip.Prefix) {
	cloned := slices.Clone(prefixes)
	meshRoutes.Store(&cloned)
}

// ThroughMesh reports whether address is inside a route SetMeshRoutes
// recorded. A reported resolver never is: a network's own DNS server is
// asked over that network, whatever route covers it.
func ThroughMesh(address netip.Addr) bool {
	routes := meshRoutes.Load()
	if routes == nil {
		return false
	}
	address = address.Unmap()
	if reportedAddress(address) {
		return false
	}
	return slices.ContainsFunc(*routes, func(prefix netip.Prefix) bool { return prefix.Contains(address) })
}

func reportedAddress(address netip.Addr) bool {
	return slices.ContainsFunc(ReportedResolvers(), func(resolver NetworkResolver) bool {
		return resolver.Address.Addr() == address
	})
}

// SetPrivateReach installs reach, which tells whether the client may ask a
// resolver at a private address outside the mesh: on a phone, only one in
// a Site it routes to, on a network it is attached to, or a network's own
// DNS server, never one sent out to whatever Wi-Fi the phone is on (DNS
// design D4 §4). nil removes it: every one may be asked.
func SetPrivateReach(reach func(netip.Addr) bool) {
	if reach == nil {
		privateReach.Store(nil)
		return
	}
	privateReach.Store(&reach)
}

// PrivateReachable reports whether a resolver at the private address may
// be asked (SetPrivateReach).
func PrivateReachable(address netip.Addr) bool {
	reach := privateReach.Load()
	if reach == nil {
		return true
	}
	address = address.Unmap()
	return reportedAddress(address) || ThroughMesh(address) || (*reach)(address)
}
