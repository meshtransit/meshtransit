//go:build !unix

package servicemanager

import "net"

// writeDatagram sends payload; no service manager listens here.
func writeDatagram(connection net.Conn, payload []byte) (int, error) {
	return connection.Write(payload)
}
