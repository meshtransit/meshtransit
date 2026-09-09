//go:build linux

package localapi

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func peerFromConn(connection net.Conn) (peerIdentity, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return peerIdentity{}, errors.New("localapi: connection is not a unix socket")
	}
	rawConnection, err := unixConnection.SyscallConn()
	if err != nil {
		return peerIdentity{}, fmt.Errorf("localapi: accessing unix socket: %w", err)
	}

	var credentials *unix.Ucred
	var credentialErr error
	if err := rawConnection.Control(func(fd uintptr) {
		credentials, credentialErr = unix.GetsockoptUcred(
			int(fd),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED,
		)
	}); err != nil {
		return peerIdentity{}, fmt.Errorf("localapi: reading unix socket descriptor: %w", err)
	}
	if credentialErr != nil {
		return peerIdentity{}, fmt.Errorf("localapi: reading peer credentials: %w", credentialErr)
	}
	if credentials == nil {
		return peerIdentity{}, errors.New("localapi: kernel returned no peer credentials")
	}

	return peerIdentity{
		uid:        credentials.Uid,
		isPresent:  true,
		isVerified: true,
	}, nil
}
