//go:build windows

package localapi

import (
	"errors"
	"net"

	"golang.org/x/sys/windows"

	"meshtransit.net/client/internal/peercred"
)

// peerFromConn reads the access token of the named-pipe client and decides
// whether it is an operator (LocalSystem, an elevated Administrator, or a
// member of the operators group).
func peerFromConn(connection net.Conn, operatorsSID string) (peerIdentity, error) {
	pipe, ok := connection.(interface{ Handle() windows.Handle })
	if !ok {
		return peerIdentity{}, errors.New("localapi: connection is not a named pipe")
	}
	caller, err := peercred.PipeCaller(pipe.Handle())
	if err != nil {
		return peerIdentity{isPresent: true}, err
	}

	return peerIdentity{isPresent: true, isVerified: true, operator: caller.IsOperator(operatorsSID)}, nil
}
