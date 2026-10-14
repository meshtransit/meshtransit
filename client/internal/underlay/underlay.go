// Package underlay keeps the client's own sockets on the physical network.
//
// The client's sockets carry the mesh: the encrypted packet path, Control,
// relays, NAT discovery and DNS upstreams. Their packets must never enter the
// mesh TUN, or they would loop through the tunnel they carry. On desktop
// systems the mesh routes never cover these destinations and there is
// nothing to do. A mobile VPN routes the whole app through its TUN unless
// each socket is excluded (Android VpnService.protect): the embedding app
// installs a Protector, and every socket the client opens to the network
// calls it before the socket connects or sends.
package underlay

import (
	"errors"
	"fmt"
	"net"
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
// protects each new socket before it connects or binds.
func Control(_, _ string, raw syscall.RawConn) error {
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
