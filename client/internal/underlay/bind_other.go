//go:build (!darwin && !windows) || ios

package underlay

import (
	"errors"
	"net/netip"
	"syscall"
)

// FollowsRoutes is false here: meshnetd keeps meshd's sockets off subnet
// routes (Linux), or the platform VPN excludes them (mobile).
const FollowsRoutes = false

// bindPhysical is never reached: no subnet route is recorded here.
func bindPhysical(syscall.RawConn, netip.Addr) error {
	return errors.New("binding to the physical path is not supported here")
}

// PhysicalIndex is 0: the client's sockets do not follow the mesh routes
// here.
func PhysicalIndex(netip.Addr) uint32 { return 0 }

// forgetPhysicalInterfaces has no cache to drop here.
func forgetPhysicalInterfaces() {}

// DirectBlocked is false: nothing here routes the client's own sockets into
// the mesh.
func DirectBlocked() bool { return false }

// ReconnectOnExitChange is false: nothing here routes the client's own
// sockets into the mesh.
const ReconnectOnExitChange = false
