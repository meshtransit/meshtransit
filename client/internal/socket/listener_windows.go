//go:build windows

// Package socket creates and owns the daemon's local control listener.
package socket

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"

	"meshtransit.net/client/internal/peercred"
)

// pipePrefix is where meshd's pipes live: only Administrators and SYSTEM can
// create a pipe under ProtectedPrefix\Administrators, so no unprivileged
// process can take the name before the service does.
const pipePrefix = `\\.\pipe\ProtectedPrefix\Administrators\`

// Listen opens the local API named pipe. Its security descriptor lets
// SYSTEM and Administrators connect, and members of the MeshTransit Users
// group when that group exists; the namedpipe package rejects remote
// clients. The local API still checks each caller's token.
func Listen(path string) (net.Listener, error) {
	if !strings.HasPrefix(path, pipePrefix) || len(path) == len(pipePrefix) {
		return nil, fmt.Errorf("socket: pipe %q must be under %s", path, pipePrefix)
	}
	operators, err := peercred.OperatorsSID()
	if err != nil {
		return nil, err
	}
	descriptor, err := windows.SecurityDescriptorFromString(pipeSDDL(operators))
	if err != nil {
		return nil, fmt.Errorf("socket: building pipe security descriptor: %w", err)
	}
	listener, err := (&namedpipe.ListenConfig{SecurityDescriptor: descriptor}).Listen(path)
	if err != nil {
		return nil, fmt.Errorf("socket: listening on %s: %w", path, err)
	}

	return listener, nil
}

// pipeSDDL is owned by SYSTEM with a protected DACL: full access for SYSTEM
// and Administrators, read and write for the operators group.
func pipeSDDL(operatorsSID string) string {
	sddl := "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)"
	if operatorsSID != "" {
		sddl += "(A;;GRGW;;;" + operatorsSID + ")"
	}

	return sddl
}

// ListenPacket is unused on Windows: one service owns the adapter, so there
// is no privileged helper to reach.
func ListenPacket(_ string) (net.Listener, error) {
	return nil, errors.New("socket: Windows has no privileged helper transport")
}
