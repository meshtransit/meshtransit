//go:build windows

// Package socket creates and owns the daemon's local control listener.
package socket

import (
	"errors"
	"net"
)

// Listen reports that the Windows named-pipe transport is not implemented yet.
func Listen(_ string) (net.Listener, error) {
	return nil, errors.New("windows named-pipe transport is not implemented")
}

// ListenPacket reports that privileged local IPC is Linux-only.
func ListenPacket(_ string) (net.Listener, error) {
	return nil, errors.New("windows privileged local transport is not implemented")
}
