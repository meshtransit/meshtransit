//go:build !ios

package underlay

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"

	"meshtransit.net/client/internal/hostroute"
)

// FollowsRoutes reports that the client's own sockets follow the host's
// routing table, subnet routes included: macOS has no per-user routing.
const FollowsRoutes = true

// bindPhysical binds the socket to the interface of the most specific route
// to destination off the mesh utun and other than meshnetd's subnet routes
// (IP_BOUND_IF), so its packets take the path the host would use without
// them, and to that interface's address: macOS picks a connecting socket's
// source address from the unscoped route, the utun's, whatever interface
// the socket is bound to, and its packets would then carry the mesh address
// out of the physical interface, or fail to connect.
func bindPhysical(raw syscall.RawConn, destination netip.Addr) error {
	index, err := physicalInterfaces.lookup(destination, physicalIndex)
	if err != nil {
		return err
	}
	source, err := interfaceAddress(index, destination.Is6())
	if err != nil {
		return err
	}
	level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
	if destination.Is6() {
		level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	}
	var bindErr error
	if err := raw.Control(func(fd uintptr) {
		if bindErr = unix.SetsockoptInt(int(fd), level, option, index); bindErr != nil {
			return
		}
		bindErr = bindSource(int(fd), source)
	}); err != nil {
		return fmt.Errorf("reaching the socket: %w", err)
	}
	if bindErr != nil {
		return fmt.Errorf("binding to interface %d (%s): %w", index, source, bindErr)
	}
	reportBound(destination.String(), index, source.String())
	return nil
}

// bindSource gives an unbound socket the source address; one already bound
// keeps its own.
func bindSource(fd int, source netip.Addr) error {
	if bound, err := unix.Getsockname(fd); err == nil {
		switch local := bound.(type) {
		case *unix.SockaddrInet4:
			if local.Port != 0 || local.Addr != [4]byte{} {
				return nil
			}
		case *unix.SockaddrInet6:
			if local.Port != 0 || local.Addr != [16]byte{} {
				return nil
			}
		}
	}
	if source.Is4() {
		return unix.Bind(fd, &unix.SockaddrInet4{Addr: source.As4()})
	}
	return unix.Bind(fd, &unix.SockaddrInet6{Addr: source.As16()})
}

// interfaceAddress returns the interface's first usable address of the
// family: not link-local, nor a mesh address.
func interfaceAddress(index int, ipv6 bool) (netip.Addr, error) {
	link, err := net.InterfaceByIndex(index)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("reading interface %d: %w", index, err)
	}
	addresses, err := link.Addrs()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("reading the addresses of %s: %w", link.Name, err)
	}
	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok {
			continue
		}
		ip, valid := netip.AddrFromSlice(network.IP)
		if !valid {
			continue
		}
		ip = ip.Unmap()
		if ip.Is6() != ipv6 || !ip.IsGlobalUnicast() && !ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			continue
		}
		return ip, nil
	}
	return netip.Addr{}, fmt.Errorf("%s has no address of the family", link.Name)
}

// physicalIndex reads the routing table for the interface of destination.
func physicalIndex(destination netip.Addr) (int, error) {
	table, err := hostroute.Read()
	if err != nil {
		return 0, err
	}
	path, found := hostroute.Physical(table, hostroute.MeshLinks(table), destination)
	if !found || path.Index <= 0 {
		return 0, errors.New("no physical route")
	}
	return path.Index, nil
}

// PhysicalIndex returns the interface of the host's route to destination
// off the mesh, 0 for none.
func PhysicalIndex(destination netip.Addr) uint32 {
	index, err := physicalInterfaces.lookup(destination, physicalIndex)
	if err != nil || index <= 0 || index > math.MaxUint32 {
		return 0
	}
	return uint32(index)
}

// ReconnectOnExitChange is true: a connected socket keeps the source
// address it took when it connected, so connections made before the exit
// routes came (or went) must be made again (OnExitBoundChange).
const ReconnectOnExitChange = true

// DirectBlocked reports that the packet path must send no datagram on its
// own UDP socket: while the host routes the Internet into the mesh, macOS
// gives that unconnected socket the utun's source address whatever
// interface it is bound to, so its peers are reached through the relays.
func DirectBlocked() bool { return ExitBound() }

// reportBound notes, at most every 10 s, a socket kept on the physical
// path: which destination, interface and source address.
func reportBound(destination string, index int, source string) {
	l := logger.Load()
	if l == nil || !due("bound") {
		return
	}
	l.Info("socket kept on the physical path", "destination", destination, "interface", index, "source", source)
}
