package pathdiscovery

import (
	"errors"
	"net/netip"
)

// ErrTransportClosed means the shared UDP socket is not available.
var ErrTransportClosed = errors.New("pathdiscovery: datagram transport is closed")

// Socket identifies one open generation of the shared UDP transport.
type Socket struct {
	Port       uint16
	Generation uint64
}

// IsOpen reports whether the value identifies an open socket generation.
func (s Socket) IsOpen() bool { return s.Port != 0 && s.Generation != 0 }

// DatagramTransport sends control datagrams through the encrypted packet
// socket. The returned Socket is the exact generation used for the send.
type DatagramTransport interface {
	Socket() Socket
	SendDatagram([]byte, netip.AddrPort) (Socket, error)
}

// DatagramHandler synchronously consumes non-WireGuard packets from the shared
// socket. Implementations must not retain the packet slice.
type DatagramHandler interface {
	MatchesDatagram([]byte) bool
	HandleDatagram([]byte, netip.AddrPort, Socket)
}
