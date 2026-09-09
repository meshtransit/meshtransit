//go:build !linux

package localapi

import (
	"errors"
	"net"
)

var errPeerCredentialsUnavailable = errors.New("localapi: peer credentials unavailable")

func peerFromConn(_ net.Conn) (peerIdentity, error) {
	return peerIdentity{isPresent: true}, errPeerCredentialsUnavailable
}
