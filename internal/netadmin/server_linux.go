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
}

// ServerOptions fixes privileged device values and overlay pools at helper startup.
type ServerOptions struct {
	AllowedUID      uint32
	InterfaceName   string
	MTU             int
	AllowedPrefixes []netip.Prefix
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
}

// NewServer constructs a privileged helper confined to explicit overlay pools.
func NewServer(options ServerOptions) (*Server, error) {
	return newServer(options, kernelTUNCreator{})
}

func newServer(options ServerOptions, creator tunCreator) (*Server, error) {
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

	return &Server{
		allowedUID:      options.AllowedUID,
		interfaceName:   options.InterfaceName,
		mtu:             options.MTU,
		allowedPrefixes: allowedPrefixes,
		logger:          options.Logger,
		creator:         creator,
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
		if err := s.handle(connection); err != nil {
			s.logger.Warn("meshnetd request rejected", "error", err)
		}
		if err := connection.Close(); err != nil {
			s.logger.Debug("closing meshnetd connection failed", "error", err)
		}
	}
}

func (s *Server) handle(rawConnection net.Conn) error {
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
	config, err := validateRequest(value)
	if err != nil {
		_ = writeResponse(connection, response{
			Version: protocolVersion,
			Code:    "unsupported_request",
			Message: "request is not supported",
		}, nil)

		return err
	}
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

	return writeResponse(connection, response{
		Version:       protocolVersion,
		OK:            true,
		InterfaceName: s.interfaceName,
		MTU:           s.mtu,
		Addresses:     prefixStrings(config.Addresses),
		Routes:        prefixStrings(config.Routes),
	}, file)
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

func validInterfaceName(name string) bool {
	if len(name) < len("mesh0") || len(name) >= unix.IFNAMSIZ || name[:4] != "mesh" {
		return false
	}
	for _, character := range name[4:] {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}

	return true
}
