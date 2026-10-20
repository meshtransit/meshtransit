// Package underlay keeps the client's own sockets on the physical network.
//
// The client's sockets carry the mesh: the encrypted packet path, Control,
// relays, NAT discovery and DNS upstreams. Their packets must never enter the
// mesh TUN, or they would loop through the tunnel they carry. Overlay routes
// never cover these destinations; subnet routes may (mtcp-v1 §7.6). On
// Linux meshnetd keeps them in their own table, which a policy rule never
// lets meshd's user reach, so nothing is needed here. macOS and Windows have
// no such rule (FollowsRoutes): a socket whose destination an installed
// subnet route covers is bound to the interface the host would use without
// it, and the packet path sends no datagram into one. A mobile VPN routes the
// whole app through its TUN unless each socket is excluded (Android
// VpnService.protect): the embedding app installs a Protector, and every
// socket the client opens to the network calls it before the socket connects
// or sends.
package underlay

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

// ErrNotProtected reports a socket the platform did not exclude from its
// VPN. The socket is closed unused.
var ErrNotProtected = errors.New("underlay: socket not excluded from the VPN")

// Protector excludes the socket fd from the platform VPN. It returns an
// error when it cannot.
type Protector func(fd uintptr) error

var protector atomic.Pointer[Protector]

// SetProtector installs protect for every socket opened after it returns,
// or removes the protector when protect is nil. It is process-wide, as the
// platform VPN is.
func SetProtector(protect Protector) {
	if protect == nil {
		protector.Store(nil)
		return
	}
	protector.Store(&protect)
}

// Active reports whether a protector is installed.
func Active() bool { return protector.Load() != nil }

// Protect excludes fd with the installed protector; without one it does
// nothing.
func Protect(fd uintptr) error {
	protect := protector.Load()
	if protect == nil {
		return nil
	}
	if err := (*protect)(fd); err != nil {
		return fmt.Errorf("%w: %w", ErrNotProtected, err)
	}
	return nil
}

// Control is a net.Dialer and net.ListenConfig Control function: it
// protects each new socket before it connects or binds, and binds one to an
// address inside a subnet route to the physical path.
func Control(_, address string, raw syscall.RawConn) error {
	if destination, err := netip.ParseAddrPort(address); err == nil && Routed(destination.Addr()) {
		if err := bindPhysical(raw, destination.Addr().Unmap()); err != nil {
			return fmt.Errorf("underlay: keeping a socket to %s off a subnet route: %w", destination.Addr(), err)
		}
	}
	if !Active() {
		return nil
	}
	var protectErr error
	if err := raw.Control(func(fd uintptr) { protectErr = Protect(fd) }); err != nil {
		return fmt.Errorf("underlay: reaching the socket: %w", err)
	}
	return protectErr
}

// Dialer returns a dialer with the given timeout (0 for none) whose sockets
// are protected.
func Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: Control}
}

// ListenConfig returns a listen configuration whose sockets are protected.
func ListenConfig() *net.ListenConfig {
	return &net.ListenConfig{Control: Control}
}
