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

func writeRequestFrame(connection *net.UnixConn, payload []byte) error {
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
