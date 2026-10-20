//go:build unix

package servicemanager

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// writeDatagram sends payload without ever blocking in the kernel
// (MSG_DONTWAIT): a full or wedged receiver makes the connection's poller
// wait, so the write deadline holds. A plain write was seen blocking in the
// kernel past any deadline on some hosts.
func writeDatagram(connection net.Conn, payload []byte) (int, error) {
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, errors.New("service-manager connection is not a Unix socket")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("reaching the service-manager socket: %w", err)
	}
	written, sendErr := 0, error(nil)
	if err := raw.Write(func(fd uintptr) bool {
		written, sendErr = unix.SendmsgN(int(fd), payload, nil, nil, unix.MSG_DONTWAIT)
		return !errors.Is(sendErr, unix.EAGAIN)
	}); err != nil {
		return 0, err
	}
	return written, sendErr
}
