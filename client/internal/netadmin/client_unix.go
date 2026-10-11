//go:build linux || darwin

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

// Client opens TUN descriptors through one-request Unix socket connections.
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
	value, descriptors, err := c.exchange(ctx, requestValue)
	if err != nil {
		return TUN{}, err
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

// ConfigureTUNRoutes replaces routes on the helper-owned data interface.
// Addresses must exactly match the interface opened earlier by this helper.
func (c *Client) ConfigureTUNRoutes(ctx context.Context, config TUNConfig) error {
	if c == nil {
		return errors.New("netadmin: client is not initialized")
	}
	requestValue, _, err := newSetTUNRequest(config)
	if err != nil {
		return err
	}
	_, descriptors, err := c.exchange(ctx, requestValue)
	closeDescriptors(descriptors)
	if err != nil {
		return err
	}
	if len(descriptors) != 0 {
		return fmt.Errorf("%w: set tun response included descriptors", ErrProtocol)
	}

	return nil
}

// OpenDNS opens the fixed non-persistent DNS link configured by meshnetd.
func (c *Client) OpenDNS(ctx context.Context) (DNSLink, error) {
	if c == nil {
		return DNSLink{}, errors.New("netadmin: client is not initialized")
	}
	value, descriptors, err := c.exchange(ctx, request{
		Version:   protocolVersion,
		Operation: operationOpenDNS,
	})
	if err != nil {
		return DNSLink{}, err
	}
	if len(descriptors) != 1 {
		closeDescriptors(descriptors)

		return DNSLink{}, fmt.Errorf(
			"%w: open dns response included %d descriptors",
			ErrProtocol,
			len(descriptors),
		)
	}
	endpoint, err := parseDNSEndpoint(value.InterfaceName, value.Resolver)
	if err != nil {
		closeDescriptors(descriptors)

		return DNSLink{}, err
	}
	descriptor := descriptors[0]
	unix.CloseOnExec(descriptor)
	file := os.NewFile(uintptr(descriptor), "meshnetd-dns-link")
	if file == nil {
		_ = unix.Close(descriptor)

		return DNSLink{}, fmt.Errorf("%w: invalid dns link descriptor", ErrProtocol)
	}

	return DNSLink{File: file, Endpoint: endpoint}, nil
}

// ConfigureDNS atomically applies one per-link systemd-resolved config.
func (c *Client) ConfigureDNS(ctx context.Context, config DNSConfig) error {
	if c == nil {
		return errors.New("netadmin: client is not initialized")
	}
	if err := validateDNSConfig(config); err != nil {
		return err
	}
	_, descriptors, err := c.exchange(ctx, request{
		Version:         protocolVersion,
		Operation:       operationSetDNS,
		InterfaceName:   config.Endpoint.InterfaceName,
		Resolver:        config.Endpoint.Resolver.String(),
		SearchDomains:   append([]string{}, config.SearchDomains...),
		RouteDomains:    append([]string{}, config.RouteDomains...),
		DNSDefaultRoute: config.DefaultRoute,
	})
	closeDescriptors(descriptors)
	if err != nil {
		return err
	}
	if len(descriptors) != 0 {
		return fmt.Errorf("%w: set dns response included descriptors", ErrProtocol)
	}

	return nil
}

// ResetDNS reverts all runtime DNS state on the dedicated link.
func (c *Client) ResetDNS(ctx context.Context) error {
	if c == nil {
		return errors.New("netadmin: client is not initialized")
	}
	_, descriptors, err := c.exchange(ctx, request{
		Version:   protocolVersion,
		Operation: operationResetDNS,
	})
	closeDescriptors(descriptors)
	if err != nil {
		return err
	}
	if len(descriptors) != 0 {
		return fmt.Errorf("%w: reset dns response included descriptors", ErrProtocol)
	}

	return nil
}

func (c *Client) exchange(ctx context.Context, requestValue request) (response, []int, error) {
	payload, err := encodeMessage(requestValue)
	if err != nil {
		return response{}, nil, err
	}
	dialer := net.Dialer{Timeout: c.timeout}
	rawConnection, err := dialer.DialContext(ctx, helperNetwork, c.socketPath)
	if err != nil {
		return response{}, nil, fmt.Errorf("netadmin: connecting to helper: %w", err)
	}
	defer func() { _ = rawConnection.Close() }()
	connection, ok := rawConnection.(*net.UnixConn)
	if !ok {
		return response{}, nil, fmt.Errorf("%w: helper connection is not unix", ErrProtocol)
	}
	if err := connection.SetDeadline(operationDeadline(ctx, c.timeout)); err != nil {
		return response{}, nil, fmt.Errorf("netadmin: setting helper deadline: %w", err)
	}
	if err := writeRequestFrame(connection, payload); err != nil {
		return response{}, nil, err
	}
	message, descriptors, err := readResponseFrame(connection)
	if err != nil {
		return response{}, nil, err
	}

	value := response{}
	if err := decodeMessage(message, &value); err != nil {
		closeDescriptors(descriptors)

		return response{}, nil, err
	}
	if err := validateResponse(value, requestValue.Operation); err != nil {
		closeDescriptors(descriptors)

		return response{}, nil, err
	}
	if !value.OK {
		closeDescriptors(descriptors)
		if len(descriptors) != 0 {
			return response{}, nil, fmt.Errorf("%w: error response included a descriptor", ErrProtocol)
		}

		return response{}, nil, &remoteError{code: value.Code, message: value.Message}
	}

	return value, descriptors, nil
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
