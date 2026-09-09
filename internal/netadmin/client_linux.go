//go:build linux

package netadmin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

const maxReceivedDescriptors = 4

// Client opens TUN descriptors through one-request Unix packet connections.
type Client struct {
	socketPath string
	timeout    time.Duration
}

// NewClient validates the fixed meshnetd socket endpoint.
func NewClient(socketPath string, timeout time.Duration) (*Client, error) {
	if !filepath.IsAbs(socketPath) {
		return nil, errors.New("netadmin: socket path must be absolute")
	}
	if timeout <= 0 || timeout > 30*time.Second {
		return nil, errors.New("netadmin: timeout is outside the allowed range")
	}

	return &Client{socketPath: socketPath, timeout: timeout}, nil
}

// OpenTUN asks meshnetd for an interface restricted to the requested host prefixes.
func (c *Client) OpenTUN(ctx context.Context, config TUNConfig) (TUN, error) {
	if c == nil {
		return TUN{}, errors.New("netadmin: client is not initialized")
	}
	requestValue, normalized, err := newOpenTUNRequest(config)
	if err != nil {
		return TUN{}, err
	}
	payload, err := encodeMessage(requestValue)
	if err != nil {
		return TUN{}, err
	}
	dialer := net.Dialer{Timeout: c.timeout}
	rawConnection, err := dialer.DialContext(ctx, "unixpacket", c.socketPath)
	if err != nil {
		return TUN{}, fmt.Errorf("netadmin: connecting to helper: %w", err)
	}
	defer func() { _ = rawConnection.Close() }()
	connection, ok := rawConnection.(*net.UnixConn)
	if !ok {
		return TUN{}, fmt.Errorf("%w: helper connection is not unix", ErrProtocol)
	}
	if err := connection.SetDeadline(operationDeadline(ctx, c.timeout)); err != nil {
		return TUN{}, fmt.Errorf("netadmin: setting helper deadline: %w", err)
	}
	if _, err := connection.Write(payload); err != nil {
		return TUN{}, fmt.Errorf("netadmin: writing helper request: %w", err)
	}

	message := make([]byte, maxMessageBytes+1)
	control := make([]byte, unix.CmsgSpace(maxReceivedDescriptors*4))
	messageSize, controlSize, flags, _, err := connection.ReadMsgUnix(message, control)
	if err != nil {
		return TUN{}, fmt.Errorf("netadmin: reading helper response: %w", err)
	}
	descriptors := parseDescriptors(control[:controlSize])
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || messageSize > maxMessageBytes {
		closeDescriptors(descriptors)

		return TUN{}, fmt.Errorf("%w: truncated helper response", ErrProtocol)
	}

	value := response{}
	if err := decodeMessage(message[:messageSize], &value); err != nil {
		closeDescriptors(descriptors)

		return TUN{}, err
	}
	if err := validateResponse(value); err != nil {
		closeDescriptors(descriptors)

		return TUN{}, err
	}
	if !value.OK {
		closeDescriptors(descriptors)
		if len(descriptors) != 0 {
			return TUN{}, fmt.Errorf("%w: error response included a descriptor", ErrProtocol)
		}

		return TUN{}, &remoteError{code: value.Code, message: value.Message}
	}
	if len(descriptors) != 1 {
		closeDescriptors(descriptors)

		return TUN{}, fmt.Errorf("%w: success response included %d descriptors", ErrProtocol, len(descriptors))
	}
	descriptor := descriptors[0]
	unix.CloseOnExec(descriptor)
	if err := unix.SetNonblock(descriptor, true); err != nil {
		_ = unix.Close(descriptor)

		return TUN{}, fmt.Errorf("netadmin: setting tun descriptor nonblocking: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), "meshnetd-tun")
	if file == nil {
		_ = unix.Close(descriptor)

		return TUN{}, fmt.Errorf("%w: invalid tun descriptor", ErrProtocol)
	}

	responseConfig, err := parseTUNConfig(value.Addresses, value.Routes)
	if err != nil {
		_ = file.Close()

		return TUN{}, fmt.Errorf("%w: helper returned invalid tun configuration", ErrProtocol)
	}
	if !slices.Equal(value.Addresses, prefixStrings(responseConfig.Addresses)) ||
		!slices.Equal(value.Routes, prefixStrings(responseConfig.Routes)) {
		_ = file.Close()

		return TUN{}, fmt.Errorf("%w: helper returned non-canonical prefixes", ErrProtocol)
	}
	if !slices.Equal(responseConfig.Addresses, normalized.Addresses) ||
		!slices.Equal(responseConfig.Routes, normalized.Routes) {
		_ = file.Close()

		return TUN{}, fmt.Errorf("%w: helper configuration differs from request", ErrProtocol)
	}

	return TUN{
		File:      file,
		Name:      value.InterfaceName,
		MTU:       value.MTU,
		Addresses: append([]netip.Prefix{}, responseConfig.Addresses...),
		Routes:    append([]netip.Prefix{}, responseConfig.Routes...),
	}, nil
}

func operationDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}

	return deadline
}

func parseDescriptors(control []byte) []int {
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return nil
	}
	var descriptors []int
	for _, message := range messages {
		rights, err := unix.ParseUnixRights(&message)
		if err != nil {
			closeDescriptors(descriptors)

			return nil
		}
		descriptors = append(descriptors, rights...)
	}

	return descriptors
}

func closeDescriptors(descriptors []int) {
	for _, descriptor := range descriptors {
		_ = unix.Close(descriptor)
	}
}
