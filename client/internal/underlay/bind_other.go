//go:build !darwin || ios

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
