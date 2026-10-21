//go:build linux || darwin

package netadmin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"meshtransit.net/client/internal/captive"

	"meshtransit.net/client/internal/peercred"
	"meshtransit.net/client/internal/routesettings"
)

const (
	helperOperationTimeout   = 5 * time.Second
	unauthorizedDrainTimeout = 250 * time.Millisecond
)

// tunCreator opens a non-persistent tunnel interface and reports the name it
// has: Linux uses the requested name, macOS lets the kernel pick utunN.
type tunCreator interface {
	Open(string, int, uint32, []netip.Prefix, []netip.Prefix) (*os.File, string, error)
	ReplaceRoutes(string, []netip.Prefix, []netip.Prefix) error
}

type dnsConfigurator interface {
	Apply(context.Context, DNSConfig) error
	Reset(context.Context, DNSEndpoint) error
}

// DNSOptions fixes the dedicated resolver link at privileged-helper startup.
// No value in this struct is client controlled.
type DNSOptions struct {
	InterfaceName  string
	Resolver       netip.AddrPort
	ResolvectlPath string // Linux
	ScutilPath     string // macOS
}

// ServerOptions fixes privileged device values and overlay pools at helper startup.
type ServerOptions struct {
	AllowedUID      uint32
	InterfaceName   string
	MTU             int
	AllowedPrefixes []netip.Prefix
	DNS             *DNSOptions
	// Routed, when set, lets meshd install subnet routes (Linux).
	Routed *RoutedOptions
	Logger *slog.Logger
}

// Server validates one bounded operation from one configured meshd UID.
type Server struct {
	allowedUID      uint32
	interfaceName   string
	mtu             int
	allowedPrefixes []netip.Prefix
	logger          *slog.Logger
	creator         tunCreator
	dns             dnsConfigurator
	dnsEndpoint     DNSEndpoint
	activeTUN       TUNConfig
	activeName      string
	hasActiveTUN    bool
	// routed and routedConfigurer install subnet routes; activeRouted are
	// those installed on the current interface.
	routed           *RoutedOptions
	routedConfigurer routedConfigurer
	hostRouting      hostRouting
	activeRouted     routedState
	requestedRouted  []netip.Prefix // nil until meshd asks
	// servedConfigurer forwards into served prefixes; activeServed are those
	// it forwards into, requestedServed what meshd last asked (nil before).
	servedConfigurer servedConfigurer
	activeServed     []routesettings.ServedEntry
	requestedServed  *servedRequest
	// servedRefused are the requested prefixes the last apply did not serve;
	// servedFailed means it could not install forwarding at all.
	servedRefused []routesettings.Refusal
	servedFailed  bool
	// servedRepaired is when a health check last installed forwarding again.
	servedRepaired time.Time
	// requestedExit is what meshd last asked of the exit node (nil before);
	// activeExit how the helper forwards as one.
	requestedExit *ExitRequest
	activeExit    ExitServing
	// exitRouteConfigurer sends the host's Internet traffic through an exit
	// node; requestedExitRoute is what meshd last asked (nil before) and
	// activeExitRoute what the helper did.
	exitRouteConfigurer exitRouteConfigurer
	requestedExitRoute  *ExitRouteRequest
	activeExitRoute     ExitRouting
	// exitRouteKey identifies the exit route installed (interface,
	// families, LAN and the host's networks); empty when none is.
	exitRouteKey string
	// exitTamperedAt is when the helper last found the exit routes it
	// installed changed by another program.
	exitTamperedAt time.Time
	// captiveWindow is the captive portal window open, nil while none is;
	// captiveNow the clock it is counted on (time.Now, monotonic).
	captiveWindow *openCaptiveWindow
	captiveNow    func() time.Time
	// readWindow reads the window file (captive.ReadWindow).
	readWindow func(string) (captive.Window, error)
	// loadSettings reads the route settings (routesettings.Load).
	loadSettings func(string) (routesettings.Settings, error)
	// mu serializes requests with background work (watchDNSLink on macOS).
	mu sync.Mutex
	// background runs alongside Serve, until it returns.
	background func(context.Context)
	// dnsLoopback, when set, holds the resolver address on the loopback
	// interface instead of the DNS link (macOS delivers a point-to-point
	// link's own address into the link, not to local sockets).
	dnsLoopback loopbackAddresses
}

// loopbackAddresses adds and removes host addresses on the loopback interface.
type loopbackAddresses interface {
	Add(netip.Addr) error
	Remove(netip.Addr) error
}

func newServer(options ServerOptions, creator tunCreator) (*Server, error) {
	return newServerWithDNS(options, creator, nil)
}

func newServerWithDNS(
	options ServerOptions,
	creator tunCreator,
	dns dnsConfigurator,
) (*Server, error) {
	if options.Logger == nil {
		return nil, errors.New("netadmin: logger is required")
	}
	if creator == nil {
		return nil, errors.New("netadmin: tun creator is required")
	}
	if !validConfiguredInterfaceName(options.InterfaceName) {
		return nil, errors.New("netadmin: interface name is invalid")
	}
	if options.MTU < 1280 || options.MTU > 9000 {
		return nil, errors.New("netadmin: mtu is outside the allowed range")
	}
	allowedPrefixes, err := normalizeAllowedPrefixes(options.AllowedPrefixes)
	if err != nil {
		return nil, err
	}
	dnsEndpoint := DNSEndpoint{}
	if options.DNS != nil {
		if dns == nil {
			return nil, errors.New("netadmin: dns configurator is required")
		}
		endpoint, err := configuredDNSEndpoint(options.DNS.InterfaceName, options.DNS.Resolver)
		if err != nil {
			return nil, err
		}
		if endpoint.InterfaceName != "" && endpoint.InterfaceName == options.InterfaceName {
			return nil, errors.New("netadmin: dns and data interfaces must be different")
		}
		for _, pool := range allowedPrefixes {
			if pool.Contains(endpoint.Resolver.Addr()) {
				return nil, errors.New("netadmin: dns endpoint overlaps an overlay pool")
			}
		}
		dnsEndpoint = endpoint
	} else if dns != nil {
		return nil, errors.New("netadmin: dns options are required")
	}

	if options.Routed != nil && !validRoutedOptions(*options.Routed) {
		return nil, errors.New("netadmin: routed route options are invalid")
	}
	var routed *RoutedOptions
	if options.Routed != nil {
		copied := *options.Routed
		routed = &copied
	}
	return &Server{
		loadSettings:    routesettings.Load,
		captiveNow:      time.Now,
		readWindow:      captive.ReadWindow,
		routed:          routed,
		allowedUID:      options.AllowedUID,
		interfaceName:   options.InterfaceName,
		mtu:             options.MTU,
		allowedPrefixes: allowedPrefixes,
		logger:          options.Logger,
		creator:         creator,
		dns:             dns,
		dnsEndpoint:     dnsEndpoint,
	}, nil
}

// Serve handles bounded one-request connections until cancellation.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s == nil {
		return errors.New("netadmin: server is not initialized")
	}
	if listener == nil || listener.Addr().Network() != helperNetwork {
		return errors.New("netadmin: " + helperNetwork + " listener is required")
	}
	stopClose := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopClose()
	if s.background != nil {
		backgroundCtx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.background(backgroundCtx)
		}()
		defer func() {
			cancel()
			<-done
		}()
	}

	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			return fmt.Errorf("netadmin: accepting helper connection: %w", err)
		}
		s.mu.Lock()
		err = s.handle(ctx, connection)
		s.mu.Unlock()
		if err != nil {
			s.logger.Warn("meshnetd request rejected", "error", err)
		}
		if err := connection.Close(); err != nil {
			s.logger.Debug("closing meshnetd connection failed", "error", err)
		}
	}
}

func (s *Server) handle(ctx context.Context, rawConnection net.Conn) error {
	connection, ok := rawConnection.(*net.UnixConn)
	if !ok {
		return errors.New("netadmin: accepted connection is not unix")
	}
	if err := connection.SetDeadline(time.Now().Add(helperOperationTimeout)); err != nil {
		return fmt.Errorf("netadmin: setting connection deadline: %w", err)
	}
	uid, err := peercred.UID(connection)
	if err != nil {
		return fmt.Errorf("netadmin: %w", err)
	}
	if uid != s.allowedUID {
		if err := connection.SetDeadline(time.Now().Add(unauthorizedDrainTimeout)); err != nil {
			return fmt.Errorf("netadmin: setting unauthorized peer deadline: %w", err)
		}
	}

	message, descriptors, err := readRequestFrame(connection)
	closeDescriptors(descriptors)
	if err != nil && !errors.Is(err, errRequestFraming) {
		return err
	}
	if uid != s.allowedUID {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "forbidden",
			Message: "peer uid is not authorized",
		}, nil)

		return fmt.Errorf("netadmin: peer uid %d is not authorized", uid)
	}
	if err != nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "invalid_request",
			Message: "request framing is invalid",
		}, nil)

		return errors.New("netadmin: invalid request framing")
	}
	value := request{}
	if err := decodeMessage(message, &value); err != nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "invalid_request",
			Message: "request is invalid",
		}, nil)

		return err
	}
	validated, err := validateRequest(value)
	if err != nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "unsupported_request",
			Message: "request is not supported",
		}, nil)

		return err
	}
	switch validated.operation {
	case operationOpenTUN:
		return s.openTUN(connection, validated.tun)
	case operationSetTUN:
		return s.setTUN(connection, validated.tun)
	case operationOpenDNS:
		return s.openDNS(connection)
	case operationSetDNS:
		return s.setDNS(ctx, connection, validated.dns)
	case operationResetDNS:
		return s.resetDNS(ctx, connection)
	case operationSetRouted:
		return s.setRouted(connection, validated.routed)
	case operationSetServed:
		return s.setServed(connection, validated.served)
	case operationSetServedExit:
		return s.setServedExit(connection, validated.exit)
	case operationCheckServed:
		return s.checkServed(connection)
	case operationSetExitRoute:
		return s.setExitRoute(connection, validated.exitRoute)
	default:
		return errors.New("netadmin: validated request has an unknown operation")
	}
}

func (s *Server) openTUN(connection *net.UnixConn, config TUNConfig) error {
	if err := validateAllowedTUNConfig(config, s.allowedPrefixes); err != nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "invalid_tun_config",
			Message: "requested prefixes are outside the helper allowlist",
		}, nil)

		return err
	}

	file, name, err := s.creator.Open(
		s.interfaceName,
		s.mtu,
		s.allowedUID,
		config.Addresses,
		config.Routes,
	)
	if err == nil && !validInterfaceName(name) {
		_ = file.Close()
		err = fmt.Errorf("%w: kernel interface name %q", ErrProtocol, name)
	}
	if err != nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "tun_unavailable",
			Message: "tun interface could not be opened",
		}, nil)

		return fmt.Errorf("netadmin: opening tun: %w", err)
	}
	defer func() { _ = file.Close() }()
	s.activeTUN = cloneTUNConfig(config)
	s.activeName = name
	s.hasActiveTUN = true
	// A new interface carries no routed routes: the old one's left with it.
	s.activeRouted, s.requestedRouted = routedState{}, nil
	// Nor forwarding: meshd asks again for the new interface.
	s.clearServed()
	// The exit route went with the old interface, but not its kill switch:
	// the new interface carries it at once while the settings want it.
	s.activeExitRoute, s.exitRouteKey = ExitRouting{}, ""
	s.applyExitRoute()

	return writeResponse(connection, response{
		Version:       protocolVersion,
		OK:            true,
		InterfaceName: name,
		MTU:           s.mtu,
		Addresses:     prefixStrings(config.Addresses),
		Routes:        prefixStrings(config.Routes),
	}, file)
}

func (s *Server) setTUN(connection *net.UnixConn, config TUNConfig) error {
	if !s.hasActiveTUN || !slices.Equal(config.Addresses, s.activeTUN.Addresses) {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "invalid_tun_state",
			Message: "tun interface is not owned by this helper generation",
		}, nil)

		return errors.New("netadmin: tun interface is not owned by this helper generation")
	}
	if err := validateAllowedTUNConfig(config, s.allowedPrefixes); err != nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "invalid_tun_config",
			Message: "requested prefixes are outside the helper allowlist",
		}, nil)

		return err
	}
	if err := s.creator.ReplaceRoutes(
		s.activeName,
		s.activeTUN.Routes,
		config.Routes,
	); err != nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "tun_config_failed",
			Message: "tun routes could not be replaced",
		}, nil)

		return fmt.Errorf("netadmin: replacing tun routes: %w", err)
	}
	s.activeTUN = cloneTUNConfig(config)
	// The router's own addresses may have changed: its rules follow.
	if s.forwarding() {
		if _, _, err := s.applyForwarding(s.forwardingRequest()); err != nil {
			s.logger.Warn("reapplying subnet forwarding after a tun change failed", "error", err)
		}
	}

	return writeResponse(connection, response{Version: protocolVersion, OK: true}, nil)
}

func cloneTUNConfig(config TUNConfig) TUNConfig {
	return TUNConfig{
		Addresses: append([]netip.Prefix(nil), config.Addresses...),
		Routes:    append([]netip.Prefix(nil), config.Routes...),
	}
}

func (s *Server) openDNS(connection *net.UnixConn) error {
	if s.dns == nil || !s.dnsEndpoint.Resolver.IsValid() {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "dns_unavailable",
			Message: "dns support is not enabled",
		}, nil)

		return errors.New("netadmin: dns support is not enabled")
	}
	linkAddresses := []netip.Prefix{netip.PrefixFrom(
		s.dnsEndpoint.Resolver.Addr(),
		s.dnsEndpoint.Resolver.Addr().BitLen(),
	)}
	if s.dnsLoopback != nil {
		linkAddresses = []netip.Prefix{}
	}
	file, name, err := s.creator.Open(
		s.dnsEndpoint.InterfaceName,
		1280,
		s.allowedUID,
		linkAddresses,
		[]netip.Prefix{},
	)
	if err == nil && !validInterfaceName(name) {
		_ = file.Close()
		err = fmt.Errorf("%w: kernel interface name %q", ErrProtocol, name)
	}
	if err == nil && s.dnsLoopback != nil {
		if aliasErr := s.dnsLoopback.Add(s.dnsEndpoint.Resolver.Addr()); aliasErr != nil {
			_ = file.Close()
			err = fmt.Errorf("adding the resolver address to loopback: %w", aliasErr)
		}
	}
	if err != nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "dns_link_unavailable",
			Message: "dns link could not be opened",
		}, nil)

		return fmt.Errorf("netadmin: opening dns link: %w", err)
	}
	defer func() { _ = file.Close() }()
	// setDNS compares the endpoint meshd echoes back, so it must carry the
	// name the kernel gave the link.
	s.dnsEndpoint.InterfaceName = name

	return writeResponse(connection, response{
		Version:       protocolVersion,
		OK:            true,
		InterfaceName: name,
		Resolver:      s.dnsEndpoint.Resolver.String(),
	}, file)
}

func (s *Server) setDNS(
	ctx context.Context,
	connection *net.UnixConn,
	config DNSConfig,
) error {
	if s.dns == nil || config.Endpoint != s.dnsEndpoint {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "invalid_dns_config",
			Message: "dns endpoint does not match helper configuration",
		}, nil)

		return errors.New("netadmin: dns endpoint does not match helper configuration")
	}
	operationCtx, cancel := context.WithTimeout(ctx, helperOperationTimeout)
	defer cancel()
	if err := s.dns.Apply(operationCtx, config); err != nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "dns_config_failed",
			Message: "host dns configuration failed",
		}, nil)

		return fmt.Errorf("netadmin: configuring host dns: %w", err)
	}

	return writeResponse(connection, response{Version: protocolVersion, OK: true}, nil)
}

func (s *Server) resetDNS(ctx context.Context, connection *net.UnixConn) error {
	if s.dns == nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "dns_unavailable",
			Message: "dns support is not enabled",
		}, nil)

		return errors.New("netadmin: dns support is not enabled")
	}
	operationCtx, cancel := context.WithTimeout(ctx, helperOperationTimeout)
	defer cancel()
	if err := s.dns.Reset(operationCtx, s.dnsEndpoint); err != nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "dns_reset_failed",
			Message: "host dns reset failed",
		}, nil)

		return fmt.Errorf("netadmin: resetting host dns: %w", err)
	}

	return writeResponse(connection, response{Version: protocolVersion, OK: true}, nil)
}

func normalizeAllowedPrefixes(values []netip.Prefix) ([]netip.Prefix, error) {
	if len(values) == 0 || len(values) > maxAllowedPools {
		return nil, errors.New("netadmin: allowed prefix count is outside the allowed range")
	}
	validated := append([]netip.Prefix(nil), values...)
	for index, prefix := range validated {
		if !prefix.IsValid() {
			return nil, errors.New("netadmin: allowed prefix is invalid")
		}
		address := prefix.Addr().Unmap()
		if prefix != prefix.Masked() || prefix.Addr() != address {
			return nil, errors.New("netadmin: allowed prefix is unsafe")
		}
		if !withinSafeOverlayFrame(prefix) {
			return nil, errors.New("netadmin: allowed prefix is outside the overlay frame")
		}
		validated[index] = netip.PrefixFrom(address, prefix.Bits())
	}
	slices.SortFunc(validated, comparePrefixes)
	for index := 1; index < len(validated); index++ {
		previous := validated[index-1]
		current := validated[index]
		if previous.Contains(current.Addr()) {
			return nil, errors.New("netadmin: allowed prefixes overlap")
		}
	}

	return validated, nil
}

func validateAllowedTUNConfig(config TUNConfig, allowedPrefixes []netip.Prefix) error {
	for _, prefix := range append(
		append([]netip.Prefix{}, config.Addresses...),
		config.Routes...,
	) {
		// The whole prefix must lie in one pool: an aggregated route that only
		// starts inside the overlay must not claim addresses beyond it.
		allowed := slices.ContainsFunc(allowedPrefixes, func(pool netip.Prefix) bool {
			return pool.Bits() <= prefix.Bits() && pool.Contains(prefix.Addr())
		})
		if !allowed {
			return fmt.Errorf("%w: requested prefix is outside the helper allowlist", ErrTUNConfig)
		}
	}

	return nil
}

func writeResponse(connection *net.UnixConn, value response, file *os.File) error {
	payload, err := encodeMessage(value)
	if err != nil {
		return err
	}
	if err := writeResponseFrame(connection, payload, file); err != nil {
		return err
	}
	if file != nil {
		awaitDescriptorReceipt(connection)
	}
	return nil
}

// awaitDescriptorReceipt waits, within the connection deadline, for meshd to
// close its end, which it does once it has received the response. Until then
// the caller keeps its own descriptor open. Closing it and the connection
// while the descriptor is still in flight leaves only in-flight references,
// and on macOS the kernel's in-flight descriptor collection can then flush
// the socket as meshd receives it: the utun arrives with its receive side
// shut and never delivers a packet.
func awaitDescriptorReceipt(connection *net.UnixConn) {
	var buffer [1]byte
	for {
		if _, err := connection.Read(buffer[:]); err != nil {
			return
		}
	}
}

// configuredDNSEndpoint validates the DNS link fixed at startup. Where the
// kernel names interfaces the name stays empty until openDNS learns it.
func configuredDNSEndpoint(interfaceName string, resolver netip.AddrPort) (DNSEndpoint, error) {
	if !validConfiguredInterfaceName(interfaceName) {
		return DNSEndpoint{}, errors.New("netadmin: dns endpoint is invalid")
	}
	// parseDNSEndpoint checks the resolver; any valid name stands in for a
	// kernel-assigned one.
	nameToCheck := interfaceName
	if nameToCheck == "" {
		nameToCheck = "utun0"
	}
	endpoint, err := parseDNSEndpoint(nameToCheck, resolver.String())
	if err != nil || endpoint.Resolver != resolver {
		return DNSEndpoint{}, errors.New("netadmin: dns endpoint is invalid")
	}
	endpoint.InterfaceName = interfaceName
	return endpoint, nil
}

// withBackground runs next alongside the background work already set.
func withBackground(current, next func(context.Context)) func(context.Context) {
	if current == nil {
		return next
	}
	return func(ctx context.Context) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			current(ctx)
		}()
		next(ctx)
		<-done
	}
}
