//go:build linux

package socket

import "net"

// ListenPacket creates a Linux Unix sequenced-packet socket for privileged IPC.
func ListenPacket(path string) (net.Listener, error) {
	return listen(path, "unixpacket")
}
