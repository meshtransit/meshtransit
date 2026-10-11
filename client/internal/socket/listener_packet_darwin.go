package socket

import "net"

// ListenPacket creates the privileged IPC socket. macOS has no
// SOCK_SEQPACKET for Unix sockets, so it is a stream socket and netadmin
// frames each message.
func ListenPacket(path string) (net.Listener, error) {
	return listen(path, "unix")
}
