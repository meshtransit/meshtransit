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

	"meshtransit.net/client/internal/routesettings"
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

// SetRoutedRoutes replaces the subnet routes of the helper-owned data
// interface (mtcp-v1 §7.6). The helper installs only what its root-owned
// settings admit and reports the rest as refused.
func (c *Client) SetRoutedRoutes(ctx context.Context, routes []netip.Prefix) (RoutedResult, error) {
	if c == nil {
		return RoutedResult{}, errors.New("netadmin: client is not initialized")
	}
	sorted := slices.Clone(routes)
	slices.SortFunc(sorted, compareRoutedPrefixes)
	sorted = slices.Compact(sorted)
	if len(sorted) > routesettings.MaximumRoutes {
		return RoutedResult{}, fmt.Errorf("%w: more than %d routed routes", ErrTUNConfig, routesettings.MaximumRoutes)
	}
	requestValue := request{Version: protocolVersion, Operation: operationSetRouted, Routes: prefixStrings(sorted)}
	if encoded, err := encodeMessage(requestValue); err != nil || len(encoded) > maxMessageBytes {
		return RoutedResult{}, fmt.Errorf("%w: routed routes exceed the helper request bound", ErrTUNConfig)
	}
	value, descriptors, err := c.exchange(ctx, requestValue)
	closeDescriptors(descriptors)
	if err != nil {
		return RoutedResult{}, err
	}
	if len(descriptors) != 0 {
		return RoutedResult{}, fmt.Errorf("%w: routed route response included descriptors", ErrProtocol)
	}
	result := RoutedResult{Installed: make([]netip.Prefix, 0, len(value.Routes)), RefusedTotal: value.RefusedTotal}
	for _, text := range value.Routes {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || !slices.Contains(sorted, prefix) {
			return RoutedResult{}, fmt.Errorf("%w: helper installed an unrequested route", ErrProtocol)
		}
		result.Installed = append(result.Installed, prefix)
	}
	for _, refusal := range value.Refused {
		prefix, err := netip.ParsePrefix(refusal.Prefix)
		if err != nil || refusal.Reason == "" {
			return RoutedResult{}, fmt.Errorf("%w: malformed route refusal", ErrProtocol)
		}
		result.Refused = append(result.Refused, routesettings.Refusal{Prefix: prefix, Reason: refusal.Reason})
	}
	return result, nil
}

// SetServedRoutes replaces the subnets the host forwards into as a router
// (mtcp-v1 §7.6). The helper serves only what its root-owned settings offer
// and reports the rest as refused; unmasqueraded lists the requested
// prefixes whose sources keep their mesh addresses.
func (c *Client) SetServedRoutes(ctx context.Context, served, unmasqueraded []netip.Prefix) (ServedResult, error) {
	if c == nil {
		return ServedResult{}, errors.New("netadmin: client is not initialized")
	}
	sorted := slices.Clone(served)
	slices.SortFunc(sorted, compareRoutedPrefixes)
	sorted = slices.Compact(sorted)
	plain := slices.Clone(unmasqueraded)
	slices.SortFunc(plain, compareRoutedPrefixes)
	plain = slices.Compact(plain)
	if len(sorted) > routesettings.MaximumRoutes {
		return ServedResult{}, fmt.Errorf("%w: more than %d served routes", ErrTUNConfig, routesettings.MaximumRoutes)
	}
	flags := make([]byte, len(sorted))
	for index, prefix := range sorted {
		flags[index] = '1'
		if slices.Contains(plain, prefix) {
			flags[index] = '0'
		}
	}
	requestValue := request{
		Version: protocolVersion, Operation: operationSetServed, Routes: prefixStrings(sorted),
		Masquerade: string(flags),
	}
	if encoded, err := encodeMessage(requestValue); err != nil || len(encoded) > maxMessageBytes {
		return ServedResult{}, fmt.Errorf("%w: served routes exceed the helper request bound", ErrTUNConfig)
	}
	value, descriptors, err := c.exchange(ctx, requestValue)
	closeDescriptors(descriptors)
	if err != nil {
		return ServedResult{}, err
	}
	if len(descriptors) != 0 {
		return ServedResult{}, fmt.Errorf("%w: served route response included descriptors", ErrProtocol)
	}
	result := ServedResult{Installed: make([]netip.Prefix, 0, len(value.Routes)), RefusedTotal: value.RefusedTotal}
	for _, text := range value.Routes {
		prefix, err := netip.ParsePrefix(text)
		// Each one served is a requested prefix or part of one.
		inside := err == nil && slices.ContainsFunc(sorted, func(requested netip.Prefix) bool {
			return requested.Bits() <= prefix.Bits() && requested.Contains(prefix.Addr())
		})
		if !inside || prefix != prefix.Masked() {
			return ServedResult{}, fmt.Errorf("%w: helper served an unrequested route", ErrProtocol)
		}
		result.Installed = append(result.Installed, prefix)
	}
	for _, refusal := range value.Refused {
		prefix, err := netip.ParsePrefix(refusal.Prefix)
		if err != nil || refusal.Reason == "" {
			return ServedResult{}, fmt.Errorf("%w: malformed route refusal", ErrProtocol)
		}
		result.Refused = append(result.Refused, routesettings.Refusal{Prefix: prefix, Reason: refusal.Reason})
	}
	return result, nil
}

// CheckServedRoutes reports the router's health as the helper sees it
// (design §6.5): what it forwards into, the problems it could not repair,
// connection tracking use and the self-test counter.
func (c *Client) CheckServedRoutes(ctx context.Context) (ServedHealth, error) {
	if c == nil {
		return ServedHealth{}, errors.New("netadmin: client is not initialized")
	}
	value, descriptors, err := c.exchange(ctx, request{Version: protocolVersion, Operation: operationCheckServed})
	closeDescriptors(descriptors)
	if err != nil {
		return ServedHealth{}, err
	}
	if len(descriptors) != 0 {
		return ServedHealth{}, fmt.Errorf("%w: served route check included descriptors", ErrProtocol)
	}
	health := ServedHealth{
		ServedResult: ServedResult{Installed: make([]netip.Prefix, 0, len(value.Routes)), RefusedTotal: value.RefusedTotal},
		Problems:     slices.Clone(value.Problems), ConntrackCount: value.ConntrackCount, ConntrackMax: value.ConntrackMax,
	}
	for _, text := range value.Routes {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || prefix != prefix.Masked() {
			return ServedHealth{}, fmt.Errorf("%w: malformed served route", ErrProtocol)
		}
		health.Installed = append(health.Installed, prefix)
	}
	for _, refusal := range value.Refused {
		prefix, err := netip.ParsePrefix(refusal.Prefix)
		if err != nil || refusal.Reason == "" {
			return ServedHealth{}, fmt.Errorf("%w: malformed route refusal", ErrProtocol)
		}
		health.Refused = append(health.Refused, routesettings.Refusal{Prefix: prefix, Reason: refusal.Reason})
	}
	if value.SelfTestPackets != nil {
		health.SelfTestPackets, health.SelfTestKnown = *value.SelfTestPackets, true
	}
	health.Exit = exitServingOf(value)
	return health, nil
}

// SetServedExit makes the host an exit node of the pool it serves, within
// Core's limits narrowed by the host's settings, or stops it (mtcp-v1
// §7.7). The helper forwards only while the host's exit mode is on and
// reports why it does not otherwise.
func (c *Client) SetServedExit(ctx context.Context, exit ExitRequest) (ExitServing, error) {
	if c == nil {
		return ExitServing{}, errors.New("netadmin: client is not initialized")
	}
	excluded := slices.Clone(exit.Excluded)
	slices.SortFunc(excluded, compareRoutedPrefixes)
	excluded = slices.Compact(excluded)
	if len(excluded) > maxExitExcluded {
		excluded = excluded[:maxExitExcluded]
	}
	requestValue := request{Version: protocolVersion, Operation: operationSetServedExit, Routes: []string{}}
	if exit.Serve {
		requestValue.Exit, requestValue.ExitConntrack, requestValue.ExitSMTP = true, exit.ConntrackPerConsumer, exit.SMTP
		requestValue.Routes = prefixStrings(excluded)
	}
	value, descriptors, err := c.exchange(ctx, requestValue)
	closeDescriptors(descriptors)
	if err != nil {
		return ExitServing{}, err
	}
	if len(descriptors) != 0 {
		return ExitServing{}, fmt.Errorf("%w: exit response included descriptors", ErrProtocol)
	}
	serving := exitServingOf(value)
	if serving.Serving && (!exit.Serve || serving.ConntrackPerConsumer > exit.ConntrackPerConsumer ||
		(serving.SMTP && !exit.SMTP)) {
		return ExitServing{}, fmt.Errorf("%w: helper widened the exit limits", ErrProtocol)
	}
	return serving, nil
}

// SetExitRoute sends the host's Internet traffic into the mesh, behind the
// helper's kill switch, or stops (exit node design §6). The helper does so
// only while the host's settings say it uses an exit node, and reports why
// it does not otherwise; while root names a pool it keeps routing into the
// mesh even when asked to stop.
func (c *Client) SetExitRoute(ctx context.Context, route ExitRouteRequest) (ExitRouting, error) {
	if c == nil {
		return ExitRouting{}, errors.New("netadmin: client is not initialized")
	}
	value, descriptors, err := c.exchange(ctx, request{
		Version: protocolVersion, Operation: operationSetExitRoute,
		ExitRoute: route.Use, ExitRouteIPv6: route.Use && route.IPv6,
	})
	closeDescriptors(descriptors)
	if err != nil {
		return ExitRouting{}, err
	}
	if len(descriptors) != 0 {
		return ExitRouting{}, fmt.Errorf("%w: exit route response included descriptors", ErrProtocol)
	}
	return ExitRouting{Routing: value.ExitRouting, Refused: value.ExitRouteRefused, Tampered: value.ExitRouteTampered}, nil
}

func exitServingOf(value response) ExitServing {
	return ExitServing{
		Serving: value.ExitServing, ConntrackPerConsumer: value.ExitConntrack, SMTP: value.ExitSMTP,
		MaxConsumers: value.ExitMaxConsumers, Refused: value.ExitRefused,
	}
}
