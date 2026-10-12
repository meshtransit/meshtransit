package netadmin

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// macOS kernel interfaces used to create a utun link. The values come from
// <sys/sys_domain.h>, <net/if_utun.h> and <netinet6/in6_var.h>.
const (
	sysprotoControl = 2 // SYSPROTO_CONTROL
	utunOptIfname   = 2 // UTUN_OPT_IFNAME
	utunControlName = "com.apple.net.utun_control"
	siocAIFAddrIn6  = 0x8080691a // SIOCAIFADDR_IN6: _IOW('i', 26, struct in6_aliasreq)
	nd6InfiniteLife = 0xffffffff // ND6_INFINITE_LIFETIME
)

// kernelTUNCreator opens utun interfaces through the utun kernel control. The
// kernel picks the unit (utunN); the link and its routes disappear when the
// last descriptor closes, as on Linux.
type kernelTUNCreator struct {
	logger *slog.Logger
}

// maxShutUTUNs bounds how many utuns that arrive with their receive side
// shut Open sets aside before giving up.
const maxShutUTUNs = 4

// Open creates a utun and configures it. A new utun sometimes comes up with
// its receive side already shut (seen right after the previous one closed):
// it reads 0 bytes at once and never delivers a packet. Open keeps such a
// utun open, which holds its unit so the kernel picks another for the next
// try, and closes the rejects once it has a working one.
func (creator kernelTUNCreator) Open(
	_ string,
	mtu int,
	_ uint32,
	addresses []netip.Prefix,
	routes []netip.Prefix,
) (*os.File, string, error) {
	var rejected []*os.File
	defer func() {
		for _, file := range rejected {
			_ = file.Close()
		}
	}()
	for {
		file, name, err := openUTUN()
		if err != nil {
			return nil, "", err
		}
		if !utunReceiveShut(file) {
			if err := configureUTUN(name, mtu, addresses); err != nil {
				_ = file.Close()
				return nil, "", err
			}
			if err := applyRouteDiff(nil, routes, func(prefix netip.Prefix, add bool) error {
				return changeHostRoute(name, prefix, add)
			}); err != nil {
				_ = file.Close()
				return nil, "", err
			}
			return file, name, nil
		}
		if creator.logger != nil {
			creator.logger.Warn("new utun came up with its receive side shut; trying another", "interface", name)
		}
		rejected = append(rejected, file)
		if len(rejected) >= maxShutUTUNs {
			return nil, "", fmt.Errorf("creating utun interface: %d new utuns came up with their receive side shut", len(rejected))
		}
	}
}

// openUTUN connects a utun kernel control socket; unit 0 lets the kernel
// choose the next free utunN.
func openUTUN() (*os.File, string, error) {
	descriptor, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, "", fmt.Errorf("opening utun control socket: %w", err)
	}
	unix.CloseOnExec(descriptor)
	file := os.NewFile(uintptr(descriptor), "meshnetd-utun")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, "", errors.New("creating utun file: invalid descriptor")
	}
	info := &unix.CtlInfo{}
	copy(info.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(descriptor, info); err != nil {
		_ = file.Close()
		return nil, "", fmt.Errorf("finding utun control: %w", err)
	}
	if err := unix.Connect(descriptor, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		_ = file.Close()
		return nil, "", fmt.Errorf("creating utun interface: %w", err)
	}
	name, err := unix.GetsockoptString(descriptor, sysprotoControl, utunOptIfname)
	if err != nil {
		_ = file.Close()
		return nil, "", fmt.Errorf("reading utun interface name: %w", err)
	}
	if !validInterfaceName(name) {
		_ = file.Close()
		return nil, "", fmt.Errorf("utun interface name %q is unexpected", name)
	}
	return file, name, nil
}

// utunReceiveShut peeks without consuming or blocking: an idle utun has
// nothing to read (EAGAIN); one whose receive side is shut reads 0 bytes.
// Recvmsg may fail to parse a source address after a successful read; that
// error still means the read happened.
func utunReceiveShut(file *os.File) bool {
	raw, err := file.SyscallConn()
	if err != nil {
		return false
	}
	shut := false
	_ = raw.Control(func(descriptor uintptr) {
		var buffer [1]byte
		read, _, _, _, err := unix.Recvmsg(int(descriptor), buffer[:], nil, unix.MSG_PEEK|unix.MSG_DONTWAIT)
		shut = read == 0 && (err == nil || errors.Is(err, unix.EAFNOSUPPORT))
	})
	return shut
}

func (kernelTUNCreator) ReplaceRoutes(name string, current, desired []netip.Prefix) error {
	if !validInterfaceName(name) || name[:4] != "utun" {
		return errors.New("tun route update target is invalid")
	}
	return applyRouteDiff(current, desired, func(prefix netip.Prefix, add bool) error {
		return changeHostRoute(name, prefix, add)
	})
}

// configureUTUN sets the MTU, brings the link up and assigns each host
// address (/32 or /128).
func configureUTUN(name string, mtu int, addresses []netip.Prefix) error {
	inet, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("opening interface control socket: %w", err)
	}
	defer func() { _ = unix.Close(inet) }()

	mtuRequest := &unix.IfreqMTU{MTU: int32(mtu)} //nolint:gosec // validated 1280..9000
	copy(mtuRequest.Name[:], name)
	if err := unix.IoctlSetIfreqMTU(inet, mtuRequest); err != nil {
		return fmt.Errorf("setting utun mtu: %w", err)
	}
	flags := ifreqFlags{}
	copy(flags.Name[:], name)
	if err := ioctl(inet, unix.SIOCGIFFLAGS, &flags); err != nil {
		return fmt.Errorf("reading utun flags: %w", err)
	}
	flags.Flags |= unix.IFF_UP
	if err := ioctl(inet, unix.SIOCSIFFLAGS, &flags); err != nil {
		return fmt.Errorf("bringing utun interface up: %w", err)
	}

	for _, prefix := range addresses {
		if prefix.Addr().Is4() {
			err = addIPv4Address(inet, name, prefix.Addr())
		} else {
			err = addIPv6Address(name, prefix.Addr())
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ifreqFlags is struct ifreq with the ifr_flags member of its union.
type ifreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags int16
	_     [14]byte
}

// ifAliasReq is struct ifaliasreq for SIOCAIFADDR.
type ifAliasReq struct {
	Name        [unix.IFNAMSIZ]byte
	Address     unix.RawSockaddrInet4
	Destination unix.RawSockaddrInet4
	Mask        unix.RawSockaddrInet4
}

// in6AliasReq is struct in6_aliasreq for SIOCAIFADDR_IN6.
type in6AliasReq struct {
	Name        [unix.IFNAMSIZ]byte
	Address     unix.RawSockaddrInet6
	Destination unix.RawSockaddrInet6
	PrefixMask  unix.RawSockaddrInet6
	Flags       int32
	Lifetime    in6AddrLifetime
}

type in6AddrLifetime struct {
	Expire    int64
	Preferred int64
	Valid     uint32
	PreferLen uint32
}

// addIPv4Address assigns a point-to-point /32 whose peer is itself, which is
// how a utun link carries one host address.
func addIPv4Address(socket int, name string, address netip.Addr) error {
	request := ifAliasReq{
		Address:     inet4(address),
		Destination: inet4(address),
		Mask:        inet4(netip.AddrFrom4([4]byte{255, 255, 255, 255})),
	}
	copy(request.Name[:], name)
	if err := ioctl(socket, unix.SIOCAIFADDR, &request); err != nil {
		return fmt.Errorf("adding utun address %s: %w", address, err)
	}
	return nil
}

func addIPv6Address(name string, address netip.Addr) error {
	socket, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("opening IPv6 interface control socket: %w", err)
	}
	defer func() { _ = unix.Close(socket) }()
	mask := [16]byte{}
	for index := range mask {
		mask[index] = 0xff
	}
	request := in6AliasReq{
		Address:    inet6(address),
		PrefixMask: inet6(netip.AddrFrom16(mask)),
		Lifetime:   in6AddrLifetime{Valid: nd6InfiniteLife, PreferLen: nd6InfiniteLife},
	}
	copy(request.Name[:], name)
	if err := ioctl(socket, siocAIFAddrIn6, &request); err != nil {
		return fmt.Errorf("adding utun address %s: %w", address, err)
	}
	return nil
}

func inet4(address netip.Addr) unix.RawSockaddrInet4 {
	return unix.RawSockaddrInet4{Len: unix.SizeofSockaddrInet4, Family: unix.AF_INET, Addr: address.As4()}
}

func inet6(address netip.Addr) unix.RawSockaddrInet6 {
	return unix.RawSockaddrInet6{Len: unix.SizeofSockaddrInet6, Family: unix.AF_INET6, Addr: address.As16()}
}

// ioctl passes a pointer to one of the request structs above. x/sys exports
// no pointer ioctl for these requests on darwin, hence the raw call.
func ioctl[T ifreqFlags | ifAliasReq | in6AliasReq | ifreqAddr4](descriptor int, request uint, argument *T) error {
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL, //nolint:staticcheck // x/sys has no libSystem wrapper for these requests
		uintptr(descriptor),
		uintptr(request),
		uintptr(unsafe.Pointer(argument)), //nolint:gosec // argument is one of the fixed kernel structs
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// changeHostRoute adds or deletes a host route to prefix through the utun
// link, over a routing socket (the equivalent of route add -host -interface).
func changeHostRoute(name string, prefix netip.Prefix, add bool) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("finding utun link: %w", err)
	}
	message, err := hostRouteMessage(link.Index, prefix, add, os.Getpid())
	if err != nil {
		return err
	}
	socket, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("opening routing socket: %w", err)
	}
	defer func() { _ = unix.Close(socket) }()
	if _, err := unix.Write(socket, message); err != nil {
		if add && errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("route to %s already exists: %w", prefix, err)
		}
		return fmt.Errorf("changing route to %s: %w", prefix, err)
	}
	return nil
}

// hostRouteMessage builds the RTM_ADD or RTM_DELETE message for one host
// prefix bound to the interface index.
func hostRouteMessage(index int, prefix netip.Prefix, add bool, pid int) ([]byte, error) {
	if !prefix.IsSingleIP() {
		return nil, fmt.Errorf("%w: route %s is not a host prefix", ErrTUNConfig, prefix)
	}
	var destination route.Addr
	if prefix.Addr().Is4() {
		destination = &route.Inet4Addr{IP: prefix.Addr().As4()}
	} else {
		destination = &route.Inet6Addr{IP: prefix.Addr().As16()}
	}
	messageType := unix.RTM_DELETE
	if add {
		messageType = unix.RTM_ADD
	}
	message := &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    messageType,
		Flags:   unix.RTF_UP | unix.RTF_HOST | unix.RTF_STATIC,
		ID:      uintptr(pid),
		Seq:     1,
		Addrs: []route.Addr{
			unix.RTAX_DST:     destination,
			unix.RTAX_GATEWAY: &route.LinkAddr{Index: index},
		},
	}
	encoded, err := message.Marshal()
	if err != nil {
		return nil, fmt.Errorf("encoding route to %s: %w", prefix, err)
	}
	return encoded, nil
}

// loopbackInterface holds the MeshTransit resolver address on macOS.
const loopbackInterface = "lo0"

// ifreqAddr4 is struct ifreq with an IPv4 ifr_addr, for SIOCDIFADDR.
type ifreqAddr4 struct {
	Name    [unix.IFNAMSIZ]byte
	Address unix.RawSockaddrInet4
}

// kernelLoopback adds and removes /32 aliases on lo0, where local delivery
// is guaranteed.
type kernelLoopback struct{}

func (kernelLoopback) Add(address netip.Addr) error {
	if !address.Is4() {
		return fmt.Errorf("%w: loopback resolver address %s is not IPv4", ErrTUNConfig, address)
	}
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("opening interface control socket: %w", err)
	}
	defer func() { _ = unix.Close(socket) }()
	request := ifAliasReq{
		Address: inet4(address),
		Mask:    inet4(netip.AddrFrom4([4]byte{255, 255, 255, 255})),
	}
	copy(request.Name[:], loopbackInterface)
	if err := ioctl(socket, unix.SIOCAIFADDR, &request); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("adding %s to %s: %w", address, loopbackInterface, err)
	}
	return nil
}

func (kernelLoopback) Remove(address netip.Addr) error {
	if !address.Is4() {
		return nil
	}
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("opening interface control socket: %w", err)
	}
	defer func() { _ = unix.Close(socket) }()
	request := ifreqAddr4{Address: inet4(address)}
	copy(request.Name[:], loopbackInterface)
	if err := ioctl(socket, unix.SIOCDIFADDR, &request); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) {
		return fmt.Errorf("removing %s from %s: %w", address, loopbackInterface, err)
	}
	return nil
}
