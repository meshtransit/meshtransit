//go:build linux

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
	"time"

	"golang.org/x/sys/unix"
)

const (
	helperOperationTimeout   = 5 * time.Second
	unauthorizedDrainTimeout = 250 * time.Millisecond
)

type tunCreator interface {
	Open(string, int, uint32, []netip.Prefix, []netip.Prefix) (*os.File, error)
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
	ResolvectlPath string
}

// ServerOptions fixes privileged device values and overlay pools at helper startup.
type ServerOptions struct {
	AllowedUID      uint32
	InterfaceName   string
	MTU             int
	AllowedPrefixes []netip.Prefix
	DNS             *DNSOptions
	Logger          *slog.Logger
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
	hasActiveTUN    bool
}

// NewServer constructs a privileged helper confined to explicit overlay pools.
func NewServer(options ServerOptions) (*Server, error) {
	var configurator dnsConfigurator
	if options.DNS != nil {
		resolved, err := newResolvectlConfigurator(options.DNS.ResolvectlPath)
		if err != nil {
			return nil, err
		}
		configurator = resolved
	}

	return newServerWithDNS(options, kernelTUNCreator{}, configurator)
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
	if !validInterfaceName(options.InterfaceName) {
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
		endpoint, err := parseDNSEndpoint(options.DNS.InterfaceName, options.DNS.Resolver.String())
		if err != nil || endpoint.Resolver != options.DNS.Resolver {
			return nil, errors.New("netadmin: dns endpoint is invalid")
		}
		if endpoint.InterfaceName == options.InterfaceName {
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

	return &Server{
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
	if listener == nil || listener.Addr().Network() != "unixpacket" {
		return errors.New("netadmin: unixpacket listener is required")
	}
	stopClose := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopClose()

	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			return fmt.Errorf("netadmin: accepting helper connection: %w", err)
		}
		if err := s.handle(ctx, connection); err != nil {
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
	uid, err := peerUID(connection)
	if err != nil {
		return err
	}
	if uid != s.allowedUID {
		if err := connection.SetDeadline(time.Now().Add(unauthorizedDrainTimeout)); err != nil {
			return fmt.Errorf("netadmin: setting unauthorized peer deadline: %w", err)
		}
	}

	message := make([]byte, maxMessageBytes+1)
	control := make([]byte, unix.CmsgSpace(4))
	messageSize, controlSize, flags, _, err := connection.ReadMsgUnix(message, control)
	if err != nil {
		return fmt.Errorf("netadmin: reading request: %w", err)
	}
	if uid != s.allowedUID {
		closeDescriptors(parseDescriptors(control[:controlSize]))
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "forbidden",
			Message: "peer uid is not authorized",
		}, nil)

		return fmt.Errorf("netadmin: peer uid %d is not authorized", uid)
	}
	if controlSize != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || messageSize > maxMessageBytes {
		closeDescriptors(parseDescriptors(control[:controlSize]))
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "invalid_request",
			Message: "request framing is invalid",
		}, nil)

		return errors.New("netadmin: invalid request framing")
	}
	value := request{}
	if err := decodeMessage(message[:messageSize], &value); err != nil {
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

	file, err := s.creator.Open(
		s.interfaceName,
		s.mtu,
		s.allowedUID,
		config.Addresses,
		config.Routes,
	)
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
	s.hasActiveTUN = true

	return writeResponse(connection, response{
		Version:       protocolVersion,
		OK:            true,
		InterfaceName: s.interfaceName,
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
		s.interfaceName,
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
	prefix := netip.PrefixFrom(
		s.dnsEndpoint.Resolver.Addr(),
		s.dnsEndpoint.Resolver.Addr().BitLen(),
	)
	file, err := s.creator.Open(
		s.dnsEndpoint.InterfaceName,
		1280,
		s.allowedUID,
		[]netip.Prefix{prefix},
		[]netip.Prefix{},
	)
	if err != nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "dns_link_unavailable",
			Message: "dns link could not be opened",
		}, nil)

		return fmt.Errorf("netadmin: opening dns link: %w", err)
	}
	defer func() { _ = file.Close() }()

	return writeResponse(connection, response{
		Version:       protocolVersion,
		OK:            true,
		InterfaceName: s.dnsEndpoint.InterfaceName,
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
		if prefix != prefix.Masked() || prefix.Addr() != address ||
			!address.IsGlobalUnicast() || address.IsLinkLocalUnicast() ||
			(address.Is4() && prefix.Bits() < 8) || (address.Is6() && prefix.Bits() < 32) {
			return nil, errors.New("netadmin: allowed prefix is unsafe")
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
		allowed := slices.ContainsFunc(allowedPrefixes, func(pool netip.Prefix) bool {
			return pool.Contains(prefix.Addr())
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

func peerUID(connection *net.UnixConn) (uint32, error) {
	rawConnection, err := connection.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("netadmin: accessing peer socket: %w", err)
	}
	var credentials *unix.Ucred
	var credentialErr error
	if err := rawConnection.Control(func(descriptor uintptr) {
		credentials, credentialErr = unix.GetsockoptUcred(
			int(descriptor),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED,
		)
	}); err != nil {
		return 0, fmt.Errorf("netadmin: accessing peer credentials: %w", err)
	}
	if credentialErr != nil {
		return 0, fmt.Errorf("netadmin: reading peer credentials: %w", credentialErr)
	}
	if credentials == nil {
		return 0, errors.New("netadmin: kernel returned no peer credentials")
	}

	return credentials.Uid, nil
}
