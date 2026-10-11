package localapi

import (
	"errors"
	"net"

	"meshtransit.net/client/internal/peercred"
)

// peerFromConn reads the kernel-verified user of the connecting process
// (SO_PEERCRED on Linux, LOCAL_PEERCRED on macOS).
func peerFromConn(connection net.Conn) (peerIdentity, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return peerIdentity{}, errors.New("localapi: connection is not a unix socket")
	}
	uid, err := peercred.UID(unixConnection)
	if err != nil {
		return peerIdentity{isPresent: true}, err
	}
	return peerIdentity{uid: uid, isPresent: true, isVerified: true}, nil
}
