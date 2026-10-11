package netadmin

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// helperNetwork is the meshnetd socket type. macOS has no SOCK_SEQPACKET for
// Unix sockets, so each message is a 4-byte big-endian length and the JSON
// payload on a stream socket, one request per connection. A response's
// descriptor travels with its first byte.
const helperNetwork = "unix"

const frameHeaderBytes = 4

func writeRequestFrame(connection *net.UnixConn, payload []byte) error {
	if _, err := connection.Write(frame(payload)); err != nil {
		return fmt.Errorf("netadmin: writing helper request: %w", err)
	}
	return nil
}

func readRequestFrame(connection *net.UnixConn) ([]byte, []int, error) {
	payload, descriptors, err := readFrame(connection, 1)
	if err != nil {
		return nil, descriptors, err
	}
	if len(descriptors) != 0 {
		return nil, descriptors, errRequestFraming
	}
	return payload, nil, nil
}

func writeResponseFrame(connection *net.UnixConn, payload []byte, file *os.File) error {
	message := frame(payload)
	var control []byte
	if file != nil {
		control = unix.UnixRights(int(file.Fd()))
	}
	written, controlWritten, err := connection.WriteMsgUnix(message, control, nil)
	if err != nil {
		return fmt.Errorf("netadmin: writing response: %w", err)
	}
	if written != len(message) || controlWritten != len(control) {
		return fmt.Errorf("%w: incomplete response write", ErrProtocol)
	}
	return nil
}

func readResponseFrame(connection *net.UnixConn) ([]byte, []int, error) {
	payload, descriptors, err := readFrame(connection, maxReceivedDescriptors)
	if err != nil {
		closeDescriptors(descriptors)
		return nil, nil, fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	return payload, descriptors, nil
}

func frame(payload []byte) []byte {
	message := make([]byte, frameHeaderBytes+len(payload))
	binary.BigEndian.PutUint32(message, uint32(len(payload))) //nolint:gosec // bounded by maxMessageBytes
	copy(message[frameHeaderBytes:], payload)
	return message
}

// readFrame reads one length-prefixed message. Descriptors may arrive only
// with the first chunk; a truncated control message, descriptors on a later
// chunk, a bad length or bytes past the frame fail it. The descriptors read
// are returned even on failure so the caller closes them.
func readFrame(connection *net.UnixConn, maxDescriptors int) ([]byte, []int, error) {
	buffer := make([]byte, frameHeaderBytes+maxMessageBytes+1)
	control := make([]byte, unix.CmsgSpace(maxDescriptors*4))
	read, controlSize, flags, _, err := connection.ReadMsgUnix(buffer, control)
	descriptors := parseDescriptors(control[:controlSize])
	if err != nil {
		return nil, descriptors, fmt.Errorf("netadmin: reading helper message: %w", err)
	}
	if flags&unix.MSG_CTRUNC != 0 {
		return nil, descriptors, errRequestFraming
	}
	for read < frameHeaderBytes {
		more, extra, err := readChunk(connection, buffer[read:])
		if err != nil || extra {
			return nil, descriptors, errRequestFraming
		}
		read += more
	}
	size := int(binary.BigEndian.Uint32(buffer))
	if size == 0 || size > maxMessageBytes {
		return nil, descriptors, errRequestFraming
	}
	total := frameHeaderBytes + size
	for read < total {
		more, extra, err := readChunk(connection, buffer[read:total])
		if err != nil || extra {
			return nil, descriptors, errRequestFraming
		}
		read += more
	}
	if read != total {
		return nil, descriptors, errRequestFraming
	}
	return buffer[frameHeaderBytes:total], descriptors, nil
}

// readChunk reads more stream bytes and reports control data, which only the
// first chunk may carry; any descriptors found are closed at once.
func readChunk(connection *net.UnixConn, buffer []byte) (int, bool, error) {
	control := make([]byte, unix.CmsgSpace(4))
	read, controlSize, _, _, err := connection.ReadMsgUnix(buffer, control)
	if controlSize != 0 {
		closeDescriptors(parseDescriptors(control[:controlSize]))
		return read, true, err
	}
	if err == nil && read == 0 {
		return 0, false, fmt.Errorf("netadmin: helper message ended early")
	}
	return read, false, err
}
