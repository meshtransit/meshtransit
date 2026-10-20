//go:build !ios

package underlay

import (
	"errors"
	"fmt"
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
// them.
func bindPhysical(raw syscall.RawConn, destination netip.Addr) error {
	table, err := hostroute.Read()
	if err != nil {
		return err
	}
	path, found := hostroute.Physical(table, hostroute.MeshLinks(table), destination)
	if !found || path.Index <= 0 {
		return errors.New("no physical route")
	}
	level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
	if destination.Is6() {
		level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	}
	var bindErr error
	if err := raw.Control(func(fd uintptr) { bindErr = unix.SetsockoptInt(int(fd), level, option, path.Index) }); err != nil {
		return fmt.Errorf("reaching the socket: %w", err)
	}
	if bindErr != nil {
		return fmt.Errorf("binding to interface %d: %w", path.Index, bindErr)
	}
	return nil
}
