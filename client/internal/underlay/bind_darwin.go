//go:build !ios

package underlay

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

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
	source, err := interfaceAddress(index, destination)
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

// interfaceAddress returns the interface's address to reach destination
// from (pickSource).
func interfaceAddress(index int, destination netip.Addr) (netip.Addr, error) {
	link, err := net.InterfaceByIndex(index)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("reading interface %d: %w", index, err)
	}
	addresses, err := link.Addrs()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("reading the addresses of %s: %w", link.Name, err)
	}
	candidates := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok {
			if ip, valid := netip.AddrFromSlice(network.IP); valid {
				candidates = append(candidates, ip.Unmap())
			}
		}
	}
	flags := func(address netip.Addr) (uint32, error) { return ipv6AddressFlags(link.Name, address) }
	if source, ok := pickSource(candidates, destination, flags); ok {
		return source, nil
	}
	return netip.Addr{}, fmt.Errorf("%s has no usable address of the family", link.Name)
}

// IPv6 address flags of macOS (netinet6/in6_var.h).
const (
	// in6IffUnusable: anycast, tentative, duplicated, or the CLAT46 address
	// macOS keeps for translated IPv4 traffic.
	in6IffUnusable = 0x01 | 0x02 | 0x04 | 0x1000
	// in6IffAging: detached or deprecated, still valid for a while.
	in6IffAging     = 0x08 | 0x10
	in6IffTemporary = 0x80
	in6IffSecured   = 0x400
)

// pickSource chooses the source address for destination among an
// interface's: of its family, not link-local, and for IPv6 never anycast,
// tentative, duplicated or CLAT46 (a bind to one fails or its replies go
// elsewhere); a stable one before a temporary one, either before a
// deprecated or detached one, which only serves when nothing else does
// (renumbering); a unique local one only to a unique local destination,
// which alone has a way back to it. flags reads an IPv6 address's flags;
// one it cannot read counts as a temporary one.
func pickSource(candidates []netip.Addr, destination netip.Addr, flags func(netip.Addr) (uint32, error)) (netip.Addr, bool) {
	ipv6, local := destination.Is6(), destination.Is6() && destination.IsPrivate()
	var best netip.Addr
	bestRank := -1
	for _, address := range candidates {
		if address.Is6() != ipv6 || !address.IsGlobalUnicast() || address.IsLinkLocalUnicast() {
			continue
		}
		if !ipv6 {
			return address, true
		}
		if address.IsPrivate() && !local {
			continue
		}
		rank := 1
		if value, err := flags(address); err == nil {
			switch {
			case value&in6IffUnusable != 0:
				continue
			case value&in6IffAging != 0:
				rank = 0
			case value&in6IffTemporary == 0:
				rank = 2
			}
		}
		if address.IsPrivate() == local {
			rank += 3
		}
		if rank > bestRank {
			best, bestRank = address, rank
		}
	}
	return best, best.IsValid()
}

// siocgifaflagIn6 is SIOCGIFAFLAG_IN6, _IOWR('i', 73, struct in6_ifreq),
// and in6IfreqSize that struct's size.
const (
	siocgifaflagIn6 = 0xc1206949
	in6IfreqSize    = 288
)

// ipv6AddressFlags reads the flags of the interface's IPv6 address.
func ipv6AddressFlags(name string, address netip.Addr) (uint32, error) {
	if len(name) >= unix.IFNAMSIZ || !address.Is6() {
		return 0, errors.New("invalid interface or address")
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(fd) }()
	// struct in6_ifreq: the name, then a sockaddr_in6 the kernel answers
	// with the flags in place of.
	var request [in6IfreqSize]byte
	copy(request[:], name)
	request[16], request[17] = unix.SizeofSockaddrInet6, unix.AF_INET6
	bytes := address.As16()
	copy(request[24:40], bytes[:])
	// x/sys exports no pointer ioctl for this request on darwin.
	if _, _, errno := unix.Syscall(
		unix.SYS_IOCTL, //nolint:staticcheck // x/sys has no libSystem wrapper for this request
		uintptr(fd),
		siocgifaflagIn6,
		uintptr(unsafe.Pointer(&request)), //nolint:gosec // the in6_ifreq the kernel reads and writes
	); errno != 0 {
		return 0, errno
	}
	return binary.NativeEndian.Uint32(request[16:20]), nil
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
