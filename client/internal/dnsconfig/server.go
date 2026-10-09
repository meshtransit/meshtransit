package dnsconfig

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/client/internal/netadmin"
)

const (
	maxConcurrentQueries = 256
	maxTCPConnections    = 64
	tcpIdleTimeout       = 30 * time.Second
)

type dnsLinkOpener interface {
	OpenDNS(context.Context) (netadmin.DNSLink, error)
}

// EndpointSource exposes only non-secret DNS link metadata to the host
// configurator after the resolver listeners are ready.
type EndpointSource interface {
	Endpoint() (netadmin.DNSEndpoint, bool)
}

// Server owns the unprivileged UDP/TCP resolver and the descriptor for its
// dedicated non-persistent Linux link. Plans are immutable after publication.
type Server struct {
	lifecycleMu sync.Mutex
	opener      dnsLinkOpener
	engine      *resolverEngine
	plan        atomic.Pointer[Plan]
	link        netadmin.DNSLink
	udp         *net.UDPConn
	tcp         *net.TCPListener
	cancel      context.CancelFunc
	wait        sync.WaitGroup
	querySlots  chan struct{}
	tcpSlots    chan struct{}
	isClosed    bool
}

// NewServer creates a stopped resolver. The privileged link and listeners are
// opened lazily when the first enabled plan is applied.
func NewServer(opener dnsLinkOpener) (*Server, error) {
	if opener == nil {
		return nil, errors.New("dnsconfig: dns link opener is required")
	}
	server := &Server{
		opener:     opener,
		engine:     newResolverEngine(),
		querySlots: make(chan struct{}, maxConcurrentQueries),
		tcpSlots:   make(chan struct{}, maxTCPConnections),
	}
	disabled := Plan{}
	server.plan.Store(&disabled)

	return server, nil
}

// Apply atomically publishes a resolver plan. Listener startup completes
// before the plan can be exposed to systemd-resolved.
func (s *Server) Apply(ctx context.Context, plan Plan) error {
	if s == nil {
		return errors.New("dnsconfig: resolver server is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.isClosed {
		return ErrClosed
	}
	if !plan.Enabled {
		disabled := clonePlan(plan)
		s.plan.Store(&disabled)

		return s.stopLocked()
	}
	startedNow := false
	if s.link.File == nil {
		if err := s.startLocked(ctx); err != nil {
			return err
		}
		startedNow = true
	}
	if resolverLoop(plan, s.link.Endpoint.Resolver) {
		if startedNow {
			_ = s.stopLocked()
		}

		return errors.New("dnsconfig: resolver plan points back to the local endpoint")
	}
	published := clonePlan(plan)
	s.plan.Store(&published)

	return nil
}

// Endpoint returns the active dedicated resolver link after both UDP and TCP
// listeners are ready.
func (s *Server) Endpoint() (netadmin.DNSEndpoint, bool) {
	if s == nil {
		return netadmin.DNSEndpoint{}, false
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.link.File == nil || s.udp == nil || s.tcp == nil {
		return netadmin.DNSEndpoint{}, false
	}

	return s.link.Endpoint, true
}

// Close stops all listeners, waits for owned goroutines, and closes the link.
func (s *Server) Close(_ context.Context) error {
	if s == nil {
		return nil
	}
	s.lifecycleMu.Lock()
	if s.isClosed {
		s.lifecycleMu.Unlock()

		return nil
	}
	s.isClosed = true
	disabled := Plan{}
	s.plan.Store(&disabled)
	err := s.stopLocked()
	s.lifecycleMu.Unlock()
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) startLocked(ctx context.Context) error {
	link, err := s.opener.OpenDNS(ctx)
	if err != nil {
		return fmt.Errorf("dnsconfig: opening dns link: %w", err)
	}
	if err := validateDNSLink(link); err != nil {
		if link.File != nil {
			_ = link.File.Close()
		}

		return err
	}
	address := link.Endpoint.Resolver
	networkSuffix := "4"
	if address.Addr().Is6() {
		networkSuffix = "6"
	}
	tcpListener, err := net.ListenTCP("tcp"+networkSuffix, net.TCPAddrFromAddrPort(address))
	if err != nil {
		_ = link.File.Close()

		return fmt.Errorf("dnsconfig: listening for tcp dns: %w", err)
	}
	udpListener, err := net.ListenUDP("udp"+networkSuffix, net.UDPAddrFromAddrPort(address))
	if err != nil {
		_ = tcpListener.Close()
		_ = link.File.Close()

		return fmt.Errorf("dnsconfig: listening for udp dns: %w", err)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	s.link = link
	s.tcp = tcpListener
	s.udp = udpListener
	s.cancel = cancel
	s.wait.Add(2)
	go s.serveTCP(runCtx, tcpListener)
	go s.serveUDP(runCtx, udpListener)

	return nil
}

func (s *Server) stopLocked() error {
	if s.link.File == nil {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	var closeErrors []error
	if s.udp != nil {
		if err := s.udp.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErrors = append(closeErrors, fmt.Errorf("closing udp dns listener: %w", err))
		}
	}
	if s.tcp != nil {
		if err := s.tcp.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErrors = append(closeErrors, fmt.Errorf("closing tcp dns listener: %w", err))
		}
	}
	s.wait.Wait()
	if err := s.link.File.Close(); err != nil {
		closeErrors = append(closeErrors, fmt.Errorf("closing dns link: %w", err))
	}
	s.link = netadmin.DNSLink{}
	s.udp = nil
	s.tcp = nil
	s.cancel = nil

	return errors.Join(closeErrors...)
}

func (s *Server) serveUDP(ctx context.Context, listener *net.UDPConn) {
	defer s.wait.Done()
	buffer := make([]byte, maxQueryBytes+1)
	for {
		count, remote, err := listener.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		query := append([]byte(nil), buffer[:count]...)
		select {
		case <-ctx.Done():
			return
		case s.querySlots <- struct{}{}:
			s.wait.Add(1)
			go s.handleUDP(ctx, listener, remote, query)
		default:
			_, _ = listener.WriteToUDPAddrPort(busyResponse(query), remote)
		}
	}
}

func (s *Server) handleUDP(
	ctx context.Context,
	listener *net.UDPConn,
	remote netip.AddrPort,
	query []byte,
) {
	defer s.wait.Done()
	defer func() { <-s.querySlots }()
	response, _ := s.engine.resolve(ctx, s.currentPlan(), query, "udp")
	if len(response) != 0 {
		_, _ = listener.WriteToUDPAddrPort(response, remote)
	}
}

func (s *Server) serveTCP(ctx context.Context, listener *net.TCPListener) {
	defer s.wait.Done()
	for {
		connection, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			_ = connection.Close()
			return
		case s.tcpSlots <- struct{}{}:
			s.wait.Add(1)
			go s.handleTCP(ctx, connection)
		default:
			_ = connection.Close()
		}
	}
}

func (s *Server) handleTCP(ctx context.Context, connection *net.TCPConn) {
	defer s.wait.Done()
	defer func() { <-s.tcpSlots }()
	defer func() { _ = connection.Close() }()
	stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopClose()
	for {
		if err := connection.SetDeadline(time.Now().Add(tcpIdleTimeout)); err != nil {
			return
		}
		var length uint16
		if err := binary.Read(connection, binary.BigEndian, &length); err != nil {
			return
		}
		if length < 12 || length > maxQueryBytes {
			return
		}
		query := make([]byte, int(length))
		if _, err := io.ReadFull(connection, query); err != nil {
			return
		}
		response, _ := s.engine.resolve(ctx, s.currentPlan(), query, "tcp")
		responseLength := len(response)
		if responseLength == 0 {
			return
		}
		if responseLength > maxDNSMessageBytes {
			return
		}
		wireResponseLength := uint16(responseLength)
		if err := binary.Write(connection, binary.BigEndian, wireResponseLength); err != nil {
			return
		}
		if _, err := connection.Write(response); err != nil {
			return
		}
	}
}

func (s *Server) currentPlan() Plan {
	plan := s.plan.Load()
	if plan == nil {
		return Plan{}
	}

	return *plan
}

func validateDNSLink(link netadmin.DNSLink) error {
	endpoint := link.Endpoint
	if link.File == nil || endpoint.InterfaceName == "" ||
		!strings.HasPrefix(endpoint.InterfaceName, "mesh") ||
		!endpoint.Resolver.IsValid() || endpoint.Resolver.Addr().Is4In6() ||
		!endpoint.Resolver.Addr().IsGlobalUnicast() ||
		endpoint.Resolver.Addr().IsLinkLocalUnicast() || endpoint.Resolver.Port() < 1024 {
		return errors.New("dnsconfig: helper returned invalid dns link metadata")
	}

	return nil
}

func resolverLoop(plan Plan, endpoint netip.AddrPort) bool {
	if slices.Contains(plan.DefaultResolvers, endpoint) ||
		slices.Contains(plan.FallbackResolvers, endpoint) {
		return true
	}
	return slices.ContainsFunc(plan.Routes, func(route Route) bool {
		return slices.Contains(route.Resolvers, endpoint)
	})
}

func busyResponse(query []byte) []byte {
	message, question, _, err := parseQuery(query)
	if err != nil {
		return formatError(query)
	}
	response, err := serverFailure(message, question, Plan{})
	if err != nil {
		return nil
	}

	return response
}

var (
	_ Resolver       = (*Server)(nil)
	_ EndpointSource = (*Server)(nil)
)
