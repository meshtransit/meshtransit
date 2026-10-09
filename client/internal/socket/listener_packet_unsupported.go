//go:build !linux && !windows

package socket

import (
	"errors"
	"net"
)

// ListenPacket reports that privileged local IPC is Linux-only.
func ListenPacket(_ string) (net.Listener, error) {
	return nil, errors.New("privileged local transport is implemented only on linux")
}
