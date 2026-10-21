//go:build linux || darwin

package operator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/user"
	"slices"
	"strconv"
	"sync"
	"time"

	"meshtransit.net/client/internal/peercred"
	"meshtransit.net/client/internal/routesettings"
)

const (
	// requestTimeout bounds one connection, from accept to the response.
	requestTimeout = 5 * time.Second
	// maxConnections bounds the connections served at once; more wait.
	maxConnections = 4
	// The pause after a failed accept, doubling up to the maximum.
	minimumAcceptPause = 5 * time.Millisecond
	maximumAcceptPause = time.Second
)

// ServerOptions fix the settings file and the operators' group when the
// helper starts; nothing a caller sends changes them.
type ServerOptions struct {
	// SettingsPath is the root-owned route settings file.
	SettingsPath string
	// GroupID is the meshtransit group's: its members are operators.
	GroupID uint32
	// DeniedUIDs are never operators, whatever their groups: meshd's user,
	// which talks to Core and must never take the kill switch away.
	DeniedUIDs []uint32
	Logger     *slog.Logger
}

// Server answers operators on the socket the helper listens on.
type Server struct {
	settingsPath string
	groupID      uint32
	deniedUIDs   []uint32
	logger       *slog.Logger
	// peerUID reads the kernel-verified user of a connection.
	peerUID func(*net.UnixConn) (uint32, error)
	// inGroup reports whether the user is in the group, as the system's
	// directory says.
	inGroup func(uid, gid uint32) (bool, error)
	load    func(string) (routesettings.Settings, error)
	// update changes the settings under the lock root's command takes too
	// (routesettings.Update).
	update func(string, func(routesettings.Settings, error) (routesettings.Settings, error)) (
		routesettings.Settings, error)
}

// NewServer returns the server for options.
func NewServer(options ServerOptions) (*Server, error) {
	if options.SettingsPath == "" {
		return nil, errors.New("operator: no route settings path")
	}
	if options.GroupID == 0 {
		// gid 0 is wheel: its members are not the operators.
		return nil, errors.New("operator: no operators group")
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Server{
		settingsPath: options.SettingsPath,
		groupID:      options.GroupID,
		deniedUIDs:   slices.Clone(options.DeniedUIDs),
		logger:       logger,
		peerUID:      peercred.UID,
		inGroup:      UserInGroup,
		load:         routesettings.Load,
		update:       routesettings.Update,
	}, nil
}

// Serve answers connections on listener until ctx ends, then closes it.
// A failed accept (out of descriptors, a connection aborted) is retried
// after a pause rather than ending the socket until the helper restarts.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	defer func() { _ = listener.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	slots := make(chan struct{}, maxConnections)
	var running sync.WaitGroup
	defer running.Wait()
	pause := minimumAcceptPause
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		connection, err := listener.Accept()
		if err != nil {
			<-slots
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("operator: accepting: %w", err)
			}
			s.logger.Warn("operator: accepting failed; retrying", "error", err, "pause", pause)
			select {
			case <-time.After(pause):
			case <-ctx.Done():
				return ctx.Err()
			}
			pause = min(2*pause, maximumAcceptPause)
			continue
		}
		pause = minimumAcceptPause
		running.Go(func() {
			defer func() { <-slots }()
			s.serve(connection)
		})
	}
}

// serve answers the one request of connection.
func (s *Server) serve(connection net.Conn) {
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(requestTimeout))
	response := s.answer(connection)
	response.Version = ProtocolVersion
	if err := encode(connection, response); err != nil {
		s.logger.Debug("operator: answering failed", "error", err)
	}
}

func (s *Server) answer(connection net.Conn) Response {
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		return refused(CodeNotPermitted, "not a unix socket")
	}
	uid, err := s.peerUID(unix)
	if err != nil {
		s.logger.Warn("operator: reading the caller failed", "error", err)
		return refused(CodeNotPermitted, "the caller is unknown")
	}
	var request Request
	if err := decode(connection, &request); err != nil {
		return refused(CodeInvalidRequest, "the request is malformed")
	}
	if request.Version != ProtocolVersion {
		return refused(CodeInvalidRequest, "unsupported protocol version")
	}
	if request.Command != CommandShow && !request.Command.changes() {
		return refused(CodeInvalidRequest, "unknown command")
	}
	if slices.Contains(s.deniedUIDs, uid) {
		s.logger.Error("operator: refused meshd's user", "uid", uid)
		return refused(CodeNotPermitted, "this user never changes the route settings")
	}
	// The socket's group already keeps others out; the helper checks again
	// rather than trust a mode someone may have changed.
	if uid != 0 {
		member, err := s.inGroup(uid, s.groupID)
		if err != nil {
			s.logger.Warn("operator: reading the caller's groups failed", "uid", uid, "error", err)
			return refused(CodeNotPermitted, "the caller's groups are unknown")
		}
		if !member {
			s.logger.Warn("operator: refused a caller outside the group", "uid", uid)
			return refused(CodeNotPermitted, "the caller is not in the meshtransit group")
		}
	}
	return s.run(uid, request)
}

// run reads the settings and, for a change, writes them.
func (s *Server) run(uid uint32, request Request) Response {
	if !request.Command.changes() {
		settings, err := s.load(s.settingsPath)
		if err != nil {
			s.logger.Warn("operator: reading the route settings failed", "error", err)
			return refused(CodeUnavailable, "the route settings cannot be read")
		}
		return accepted(settings)
	}
	var refusal *Response
	changed, err := s.update(s.settingsPath, func(settings routesettings.Settings, loadErr error) (
		routesettings.Settings, error,
	) {
		if loadErr != nil {
			// An unsafe or broken file is root's to fix: an operator never
			// starts it over.
			s.logger.Warn("operator: reading the route settings failed", "error", loadErr)
			refusal = refusedPointer(CodeUnavailable, "the route settings cannot be read")
			return settings, errRefused
		}
		if settings.OperatorsOff && uid != 0 {
			refusal = refusedPointer(CodeOperatorsOff, "root keeps these settings")
			return settings, errRefused
		}
		if code, message, blocked := blockedByRoot(settings, request); blocked {
			refusal = refusedPointer(code, message)
			return settings, errRefused
		}
		next, applyErr := apply(settings, request)
		if applyErr != nil {
			refusal = refusedPointer(CodeInvalidValue, "the value is not accepted")
			return settings, errRefused
		}
		return next, nil
	})
	if refusal != nil {
		return *refusal
	}
	if err != nil {
		s.logger.Error("operator: writing the route settings failed", "error", err)
		return refused(CodeUnavailable, "the route settings cannot be written")
	}
	s.logger.Info("operator: route settings changed", "uid", uid, "command", string(request.Command))
	return accepted(changed)
}

// errRefused ends an update whose refusal run already holds.
var errRefused = errors.New("operator: refused")

func refusedPointer(code ErrorCode, message string) *Response {
	response := refused(code, message)
	return &response
}

func accepted(settings routesettings.Settings) Response {
	choices := choicesOf(settings)
	return Response{OK: true, Choices: &choices}
}

func refused(code ErrorCode, message string) Response {
	return Response{Error: code, Message: message}
}

// UserInGroup reports whether the user is a member of the group, as the
// system's directory says (os/user asks libc's getgrouplist on macOS, whose
// cache may still show a user just removed for a while; root's operators off
// takes the choices back at once).
func UserInGroup(uid, gid uint32) (bool, error) {
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return false, fmt.Errorf("operator: looking up uid %d: %w", uid, err)
	}
	groups, err := account.GroupIds()
	if err != nil {
		return false, fmt.Errorf("operator: listing the groups of uid %d: %w", uid, err)
	}
	return slices.Contains(groups, strconv.FormatUint(uint64(gid), 10)), nil
}
