// Package peercred reads the kernel-verified user ID of the process at the
// other end of a connected Unix socket.
package peercred

import (
	"errors"
	"fmt"
	"net"
)

// ErrUnavailable reports a platform without peer credentials.
var ErrUnavailable = errors.New("peercred: peer credentials unavailable")

// UID returns the effective user ID of the connection's peer.
func UID(connection *net.UnixConn) (uint32, error) {
	if connection == nil {
		return 0, errors.New("peercred: nil connection")
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("peercred: accessing unix socket: %w", err)
	}
	var uid uint32
	var readErr error
	if err := raw.Control(func(fd uintptr) { uid, readErr = uidOf(int(fd)) }); err != nil {
		return 0, fmt.Errorf("peercred: reading unix socket descriptor: %w", err)
	}
	if readErr != nil {
		return 0, readErr
	}
	return uid, nil
}
