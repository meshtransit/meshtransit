package netadmin

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// helperNetwork is the meshnetd socket type: SOCK_SEQPACKET keeps one
// request or response per message.
const helperNetwork = "unixpacket"

// sendBufferBytes leaves room for the largest message: a SEQPACKET message
// must fit the sender's buffer, which hosts may tune below the default.
const sendBufferBytes = maxMessageBytes + 64<<10

// fitLargestMessage sizes the socket's send buffer for the largest message.
// The kernel caps it at net.core.wmem_max, which the helper may exceed: it
// holds CAP_NET_ADMIN.
func fitLargestMessage(connection *net.UnixConn) {
	if raw, err := connection.SyscallConn(); err == nil {
		forced := false
		_ = raw.Control(func(descriptor uintptr) {
			forced = unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, sendBufferBytes) == nil
		})
		if forced {
			return
		}
	}
	_ = connection.SetWriteBuffer(sendBufferBytes)
}

func writeRequestFrame(connection *net.UnixConn, payload []byte) error {
	fitLargestMessage(connection)
	if _, err := connection.Write(payload); err != nil {
		return fmt.Errorf("netadmin: writing helper request: %w", err)
	}
	return nil
}

// readRequestFrame returns the request, and any descriptors the peer sent so
// the caller closes them; a request never carries descriptors.
func readRequestFrame(connection *net.UnixConn) ([]byte, []int, error) {
	message := make([]byte, maxMessageBytes+1)
	control := make([]byte, unix.CmsgSpace(4))
	messageSize, controlSize, flags, _, err := connection.ReadMsgUnix(message, control)
	if err != nil {
		return nil, nil, fmt.Errorf("netadmin: reading request: %w", err)
	}
	descriptors := parseDescriptors(control[:controlSize])
	if controlSize != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || messageSize > maxMessageBytes {
		return nil, descriptors, errRequestFraming
	}
	return message[:messageSize], descriptors, nil
}

func writeResponseFrame(connection *net.UnixConn, payload []byte, file *os.File) error {
	var control []byte
	if file != nil {
		control = unix.UnixRights(int(file.Fd()))
	}
	fitLargestMessage(connection)
	written, controlWritten, err := connection.WriteMsgUnix(payload, control, nil)
	if err != nil {
		return fmt.Errorf("netadmin: writing response: %w", err)
	}
	if written != len(payload) || controlWritten != len(control) {
		return fmt.Errorf("%w: incomplete response write", ErrProtocol)
	}
	return nil
}

func readResponseFrame(connection *net.UnixConn) ([]byte, []int, error) {
	message := make([]byte, maxMessageBytes+1)
	control := make([]byte, unix.CmsgSpace(maxReceivedDescriptors*4))
	messageSize, controlSize, flags, _, err := connection.ReadMsgUnix(message, control)
	if err != nil {
		return nil, nil, fmt.Errorf("netadmin: reading helper response: %w", err)
	}
	descriptors := parseDescriptors(control[:controlSize])
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || messageSize > maxMessageBytes {
		closeDescriptors(descriptors)
		return nil, nil, fmt.Errorf("%w: truncated helper response", ErrProtocol)
	}
	return message[:messageSize], descriptors, nil
}
