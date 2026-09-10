package pathdiscovery

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	compatstun "github.com/meshtransit/meshd/internal/compat/stun"
)

const (
	maxSTUNServers     = 8
	maxPendingRequests = maxSTUNServers
	defaultProbeWindow = time.Second
	defaultRetryDelay  = 200 * time.Millisecond
)

var (
	// ErrInvalidScope means discovery was not tied to a profile generation.
	ErrInvalidScope = errors.New("pathdiscovery: discovery scope is invalid")
	// ErrInvalidSTUNServers means the server set is empty, malformed, or too large.
	ErrInvalidSTUNServers = errors.New("pathdiscovery: stun server set is invalid")
	// ErrNoSTUNServers means the signed topology has no usable literal STUN address.
	ErrNoSTUNServers = errors.New("pathdiscovery: no literal stun server is available")
	// ErrProbeTimeout means a server did not answer within the bounded window.
	ErrProbeTimeout = errors.New("pathdiscovery: stun probe timed out")
	// ErrSocketChanged means a response or send crossed a socket generation.
	ErrSocketChanged = errors.New("pathdiscovery: socket changed during discovery")
	// ErrNoSTUNResponse means no configured server produced a valid response.
	ErrNoSTUNResponse = errors.New("pathdiscovery: no valid stun response")
)

// DiscoveryResult is one complete, generation-bound STUN observation.
type DiscoveryResult struct {
	Scope            uint64
	Socket           Socket
	Candidates       Set
	ServerLatencies  []ServerLatency
	ReachableServers int
	FailedServers    int
}

// ServerLatency is one authenticated STUN round-trip observation. Server is
// the exact control-authorized endpoint that answered the request.
type ServerLatency struct {
	Server  netip.AddrPort
	Latency time.Duration
}

type probeResponse struct {
	address netip.AddrPort
	socket  Socket
	latency time.Duration
}

type pendingProbe struct {
	server   netip.AddrPort
	socket   Socket
	scope    uint64
	started  time.Time
	response chan probeResponse
}

// Discovery performs bounded request/response rounds without owning a
// background goroutine. Calls are serialized to keep one active scope.
type Discovery struct {
	transport   DatagramTransport
	probeWindow time.Duration
	retryDelay  time.Duration
	roundMu     sync.Mutex
	mu          sync.Mutex
	activeScope uint64
	pending     map[compatstun.TransactionID]pendingProbe
}

// NewDiscovery constructs a STUN discovery client over a shared UDP transport.
func NewDiscovery(transport DatagramTransport) (*Discovery, error) {
	return newDiscovery(transport, defaultProbeWindow, defaultRetryDelay)
}

func newDiscovery(
	transport DatagramTransport,
	probeWindow time.Duration,
	retryDelay time.Duration,
) (*Discovery, error) {
	if transport == nil {
		return nil, errors.New("pathdiscovery: datagram transport is required")
	}
	if probeWindow <= 0 || retryDelay <= 0 || retryDelay >= probeWindow {
		return nil, errors.New("pathdiscovery: probe timing is invalid")
	}

	return &Discovery{
		transport:   transport,
		probeWindow: probeWindow,
		retryDelay:  retryDelay,
		pending:     make(map[compatstun.TransactionID]pendingProbe),
	}, nil
}

// MatchesDatagram implements DatagramHandler.
func (d *Discovery) MatchesDatagram(packet []byte) bool {
	return compatstun.LooksLikeMessage(packet)
}

// Socket returns the currently open transport generation, if any.
func (d *Discovery) Socket() Socket {
	if d == nil || d.transport == nil {
		return Socket{}
	}

	return d.transport.Socket()
}

// HandleDatagram implements DatagramHandler. Invalid, unexpected, late, or
// wrong-source responses are consumed and ignored.
func (d *Discovery) HandleDatagram(
	packet []byte,
	source netip.AddrPort,
	socket Socket,
) {
	if d == nil {
		return
	}
	transactionID, address, err := compatstun.ParseBindingResponse(packet)
	if err != nil {
		return
	}
	if err := validateEndpoint(address); err != nil {
		return
	}

	now := time.Now()
	d.mu.Lock()
	pending, exists := d.pending[transactionID]
	if !exists || pending.scope != d.activeScope || pending.server != source ||
		pending.socket != socket ||
		pending.server.Addr().Is4() != address.Addr().Is4() {
		d.mu.Unlock()

		return
	}
	latency := now.Sub(pending.started)
	if latency > d.probeWindow {
		d.mu.Unlock()

		return
	}
	if latency <= 0 {
		latency = time.Nanosecond
	}
	delete(d.pending, transactionID)
	d.mu.Unlock()

	pending.response <- probeResponse{
		address: address,
		socket:  socket,
		latency: latency,
	}
}

// Discover probes all validated servers concurrently and returns only results
// observed on one unchanged socket generation.
func (d *Discovery) Discover(
	ctx context.Context,
	scope uint64,
	servers []netip.AddrPort,
) (DiscoveryResult, error) {
	if d == nil || d.transport == nil {
		return DiscoveryResult{}, errors.New("pathdiscovery: discovery is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return DiscoveryResult{}, err
	}
	if scope == 0 {
		return DiscoveryResult{}, ErrInvalidScope
	}
	if err := validateSTUNServers(servers); err != nil {
		return DiscoveryResult{}, err
	}

	d.roundMu.Lock()
	defer d.roundMu.Unlock()
	if err := ctx.Err(); err != nil {
		return DiscoveryResult{}, err
	}
	d.beginRound(scope)
	defer d.endRound(scope)

	socket := d.transport.Socket()
	if !socket.IsOpen() {
		return DiscoveryResult{}, ErrTransportClosed
	}

	type outcome struct {
		candidate Candidate
		server    netip.AddrPort
		socket    Socket
		latency   time.Duration
		err       error
	}
	outcomes := make(chan outcome, len(servers))
	for _, server := range servers {
		go func(server netip.AddrPort) {
			candidate, usedSocket, latency, err := d.probe(ctx, scope, server, socket)
			outcomes <- outcome{
				candidate: candidate,
				server:    server,
				socket:    usedSocket,
				latency:   latency,
				err:       err,
			}
		}(server)
	}

	candidates := make([]Candidate, 0, len(servers))
	latencies := make([]ServerLatency, 0, len(servers))
	probeErrors := []error{}
	for range servers {
		result := <-outcomes
		if result.err != nil {
			probeErrors = append(probeErrors, result.err)

			continue
		}
		if result.socket != socket {
			probeErrors = append(probeErrors, ErrSocketChanged)

			continue
		}
		candidates = append(candidates, result.candidate)
		latencies = append(latencies, ServerLatency{
			Server:  result.server,
			Latency: result.latency,
		})
	}
	if err := ctx.Err(); err != nil {
		return DiscoveryResult{}, err
	}
	if d.transport.Socket() != socket {
		return DiscoveryResult{}, ErrSocketChanged
	}
	if len(candidates) == 0 {
		return DiscoveryResult{}, errors.Join(
			append([]error{ErrNoSTUNResponse}, probeErrors...)...,
		)
	}
	set, err := NewSet(candidates)
	if err != nil {
		return DiscoveryResult{}, fmt.Errorf("pathdiscovery: normalizing stun results: %w", err)
	}
	slices.SortFunc(latencies, func(left, right ServerLatency) int {
		return left.Server.Compare(right.Server)
	})

	return DiscoveryResult{
		Scope:            scope,
		Socket:           socket,
		Candidates:       set,
		ServerLatencies:  latencies,
		ReachableServers: len(candidates),
		FailedServers:    len(servers) - len(candidates),
	}, nil
}

func (d *Discovery) probe(
	ctx context.Context,
	scope uint64,
	server netip.AddrPort,
	expectedSocket Socket,
) (Candidate, Socket, time.Duration, error) {
	transactionID, response, err := d.registerProbe(scope, server, expectedSocket)
	if err != nil {
		return Candidate{}, Socket{}, 0, err
	}
	defer d.removeProbe(transactionID)

	packet := compatstun.BindingRequest(transactionID)
	usedSocket, err := d.transport.SendDatagram(packet, server)
	if err != nil {
		return Candidate{}, Socket{}, 0, err
	}
	if usedSocket != expectedSocket {
		return Candidate{}, usedSocket, 0, ErrSocketChanged
	}

	retryTimer := time.NewTimer(d.retryDelay)
	defer retryTimer.Stop()
	deadline := time.NewTimer(d.probeWindow)
	defer deadline.Stop()
	for {
		select {
		case result := <-response:
			candidate, err := NewCandidate(result.address, SourceServerReflexive)
			if err != nil {
				return Candidate{}, result.socket, 0, err
			}

			return candidate, result.socket, result.latency, nil
		case <-retryTimer.C:
			usedSocket, sendErr := d.transport.SendDatagram(packet, server)
			if sendErr != nil {
				continue
			}
			if usedSocket != expectedSocket {
				return Candidate{}, usedSocket, 0, ErrSocketChanged
			}
		case <-deadline.C:
			return Candidate{}, expectedSocket, 0, ErrProbeTimeout
		case <-ctx.Done():
			return Candidate{}, expectedSocket, 0, ctx.Err()
		}
	}
}

func (d *Discovery) registerProbe(
	scope uint64,
	server netip.AddrPort,
	socket Socket,
) (compatstun.TransactionID, <-chan probeResponse, error) {
	for range 4 {
		transactionID, err := compatstun.NewTransactionID()
		if err != nil {
			return compatstun.TransactionID{}, nil, fmt.Errorf(
				"pathdiscovery: creating stun transaction: %w",
				err,
			)
		}
		response := make(chan probeResponse, 1)

		d.mu.Lock()
		if len(d.pending) >= maxPendingRequests {
			d.mu.Unlock()

			return compatstun.TransactionID{}, nil, errors.New(
				"pathdiscovery: too many pending stun probes",
			)
		}
		if _, exists := d.pending[transactionID]; exists {
			d.mu.Unlock()

			continue
		}
		d.pending[transactionID] = pendingProbe{
			server:   server,
			socket:   socket,
			scope:    scope,
			started:  time.Now(),
			response: response,
		}
		d.mu.Unlock()

		return transactionID, response, nil
	}

	return compatstun.TransactionID{}, nil, errors.New(
		"pathdiscovery: could not allocate a unique stun transaction",
	)
}

func (d *Discovery) removeProbe(transactionID compatstun.TransactionID) {
	d.mu.Lock()
	delete(d.pending, transactionID)
	d.mu.Unlock()
}

func (d *Discovery) beginRound(scope uint64) {
	d.mu.Lock()
	d.activeScope = scope
	d.mu.Unlock()
}

func (d *Discovery) endRound(scope uint64) {
	d.mu.Lock()
	if d.activeScope == scope {
		d.activeScope = 0
	}
	for transactionID, pending := range d.pending {
		if pending.scope == scope {
			delete(d.pending, transactionID)
		}
	}
	d.mu.Unlock()
}

func validateSTUNServers(servers []netip.AddrPort) error {
	if len(servers) == 0 || len(servers) > maxSTUNServers {
		return ErrInvalidSTUNServers
	}
	seen := make(map[netip.AddrPort]struct{}, len(servers))
	for _, server := range servers {
		if err := validateEndpoint(server); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidSTUNServers, err)
		}
		if _, exists := seen[server]; exists {
			return ErrInvalidSTUNServers
		}
		seen[server] = struct{}{}
	}

	return nil
}
