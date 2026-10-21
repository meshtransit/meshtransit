//go:build darwin && !ios

package dataplane

import (
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

// maximumScannedDescriptors bounds the descriptors searched for the bind's
// sockets.
const maximumScannedDescriptors = 8192

// interfaceBinder returns what binds the bind's sockets to an interface.
// wireguard-go's macOS bind exposes neither its sockets nor such a method,
// so its sockets are found among the process's descriptors as the UDP
// sockets bound to its port, and bound with IP_BOUND_IF.
func interfaceBinder(inner conn.Bind, port uint16) (conn.BindSocketToInterface, bool) {
	if binder, ok := inner.(conn.BindSocketToInterface); ok {
		return binder, true
	}
	if port == 0 {
		return nil, false
	}
	if _, isStd := inner.(*conn.StdNetBind); !isStd {
		return nil, false
	}
	return portBinder{port: port}, true
}

// portBinder binds the UDP sockets of this process bound to port.
type portBinder struct{ port uint16 }

func (binder portBinder) BindSocketToInterface4(index uint32, _ bool) error {
	return binder.bind(false, index)
}

func (binder portBinder) BindSocketToInterface6(index uint32, _ bool) error {
	return binder.bind(true, index)
}

// bind sets the bound interface of every UDP socket of the family on the
// port: 0 unbinds.
func (binder portBinder) bind(ipv6 bool, index uint32) error {
	limit := maximumScannedDescriptors
	var rlimit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &rlimit) == nil && rlimit.Cur < uint64(limit) {
		limit = int(rlimit.Cur) //nolint:gosec // G115: below maximumScannedDescriptors
	}
	found := false
	for fd := 3; fd < limit; fd++ {
		if !binder.owns(fd, ipv6) {
			continue
		}
		level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
		if ipv6 {
			level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
		}
		if err := unix.SetsockoptInt(fd, level, option, int(index)); err != nil {
			return err
		}
		found = true
	}
	if !found {
		return errNoBindSocket
	}
	return nil
}

// owns reports whether fd is a UDP socket of the family bound to the port.
func (binder portBinder) owns(fd int, ipv6 bool) bool {
	kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || kind != unix.SOCK_DGRAM {
		return false
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return false
	}
	switch bound := address.(type) {
	case *unix.SockaddrInet4:
		return !ipv6 && bound.Port == int(binder.port)
	case *unix.SockaddrInet6:
		return ipv6 && bound.Port == int(binder.port)
	default:
		return false
	}
}
