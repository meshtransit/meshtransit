package pathdiscovery

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"
)

const (
	probeIDSize             = 12
	defaultProbeLifetime    = 5 * time.Second
	maxPendingPeerProbes    = 512
	maxPendingProbesPerPeer = 8
	maxProbeIDAttempts      = 8
)

var (
	// ErrPeerProbeInactive means no validated session, map, and socket
	// generation is active.
	ErrPeerProbeInactive = errors.New("pathdiscovery: peer-probe manager is inactive")
	// ErrInvalidPeerProbe means a transaction or authenticated reply has
	// invalid product-owned metadata.
	ErrInvalidPeerProbe = errors.New("pathdiscovery: peer probe is invalid")
	// ErrPeerProbeCapacity means a global or per-peer pending limit was reached.
	ErrPeerProbeCapacity = errors.New("pathdiscovery: peer-probe capacity reached")
	// ErrPeerProbeNotFound means a transaction is unknown, already consumed, or
	// already removed by a generation change.
	ErrPeerProbeNotFound = errors.New("pathdiscovery: peer-probe transaction not found")
	// ErrPeerProbeExpired means an authenticated reply arrived at or after its
	// transaction deadline.
	ErrPeerProbeExpired = errors.New("pathdiscovery: peer-probe transaction expired")
	// ErrPeerProbeMismatch means an authenticated reply did not match every
	// property bound to its transaction.
	ErrPeerProbeMismatch = errors.New("pathdiscovery: peer-probe transaction mismatch")
	// ErrPeerProbeEntropy means a cryptographically random transaction could
	// not be created.
	ErrPeerProbeEntropy = errors.New("pathdiscovery: peer-probe entropy unavailable")
)

// ProbeID is an opaque cryptographically random peer-probe transaction token.
type ProbeID [probeIDSize]byte

// IsZero reports whether the transaction token is unset.
func (id ProbeID) IsZero() bool {
	for _, value := range id {
		if value != 0 {
			return false
		}
	}

	return true
}

// ProbeGeneration identifies one authorized map on one active session and UDP
// socket. A change to any field invalidates every outstanding transaction.
type ProbeGeneration struct {
	Scope       uint64
	MapRevision uint64
	Socket      Socket
}

// IsValid reports whether the generation identifies an active session, map,
// and UDP socket.
func (g ProbeGeneration) IsValid() bool { return g.validate() == nil }

func (g ProbeGeneration) validate() error {
	if g.Scope == 0 || g.MapRevision == 0 || !g.Socket.IsOpen() {
		return ErrInvalidPeerProbe
	}

	return nil
}

// ProbeTransaction is the immutable request state callers pass to the wire
// adapter and transport.
type ProbeTransaction struct {
	ID         ProbeID
	PeerID     uint64
	Generation ProbeGeneration
	Endpoint   netip.AddrPort
	StartedAt  time.Time
	Deadline   time.Time
}

// AuthenticatedProbeReply is accepted only after a compatibility adapter has
// authenticated and decoded a reply from the control-authorized peer channel.
type AuthenticatedProbeReply struct {
	ID                    ProbeID
	PeerID                uint64
	Generation            ProbeGeneration
	Source                netip.AddrPort
	ObservedLocalEndpoint netip.AddrPort
}

// PathObservation is a generation-bound proof that a peer answered from the
// exact UDP endpoint that was probed.
type PathObservation struct {
	PeerID                uint64
	Generation            ProbeGeneration
	RemoteEndpoint        netip.AddrPort
	ObservedLocalEndpoint netip.AddrPort
	RoundTrip             time.Duration
}

// ProbeManager owns bounded outgoing peer-probe transactions. It does not
// authenticate packets; callers must pass only successfully authenticated
// replies. All methods are safe for concurrent use.
type ProbeManager struct {
	mu             sync.Mutex
	randomMu       sync.Mutex
	random         io.Reader
	lifetime       time.Duration
	maxPending     int
	maxPerPeer     int
	active         ProbeGeneration
	pending        map[ProbeID]ProbeTransaction
	pendingPerPeer map[uint64]int
}

// NewProbeManager creates an inactive manager with fixed resource limits.
func NewProbeManager() *ProbeManager {
	return newProbeManager(
		rand.Reader,
		defaultProbeLifetime,
		maxPendingPeerProbes,
		maxPendingProbesPerPeer,
	)
}

func newProbeManager(
	random io.Reader,
	lifetime time.Duration,
	maxPending int,
	maxPerPeer int,
) *ProbeManager {
	return &ProbeManager{
		random:         random,
		lifetime:       lifetime,
		maxPending:     maxPending,
		maxPerPeer:     maxPerPeer,
		pending:        make(map[ProbeID]ProbeTransaction),
		pendingPerPeer: make(map[uint64]int),
	}
}

// Activate installs the current generation. A changed or invalid generation
// removes every pending transaction before returning.
func (m *ProbeManager) Activate(generation ProbeGeneration) (int, error) {
	if m == nil {
		return 0, ErrPeerProbeInactive
	}
	if err := generation.validate(); err != nil {
		m.mu.Lock()
		removed := m.clearLocked()
		m.mu.Unlock()

		return removed, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if generation == m.active {
		return 0, nil
	}
	removed := m.clearLocked()
	m.active = generation

	return removed, nil
}

// Deactivate clears the active generation and all pending transactions.
func (m *ProbeManager) Deactivate() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.clearLocked()
}

// Start creates one bounded transaction for the current generation.
func (m *ProbeManager) Start(
	now time.Time,
	peerID uint64,
	endpoint netip.AddrPort,
) (ProbeTransaction, error) {
	if m == nil {
		return ProbeTransaction{}, ErrPeerProbeInactive
	}
	if now.IsZero() || peerID == 0 || validateEndpoint(endpoint) != nil {
		return ProbeTransaction{}, ErrInvalidPeerProbe
	}
	hasInvalidLimits := m.lifetime <= 0 || m.maxPending <= 0 ||
		m.maxPerPeer <= 0 || m.maxPerPeer > m.maxPending
	if hasInvalidLimits {
		return ProbeTransaction{}, ErrPeerProbeInactive
	}
	deadline := now.Add(m.lifetime)
	if !deadline.After(now) {
		return ProbeTransaction{}, ErrInvalidPeerProbe
	}
	m.mu.Lock()
	if err := m.canStartLocked(now, peerID); err != nil {
		m.mu.Unlock()

		return ProbeTransaction{}, err
	}
	m.mu.Unlock()

	for range maxProbeIDAttempts {
		id, err := m.newProbeID()
		if err != nil {
			return ProbeTransaction{}, err
		}
		if id.IsZero() {
			continue
		}

		m.mu.Lock()
		if err := m.canStartLocked(now, peerID); err != nil {
			m.mu.Unlock()

			return ProbeTransaction{}, err
		}
		if _, exists := m.pending[id]; exists {
			m.mu.Unlock()

			continue
		}
		transaction := ProbeTransaction{
			ID:         id,
			PeerID:     peerID,
			Generation: m.active,
			Endpoint:   endpoint,
			StartedAt:  now,
			Deadline:   deadline,
		}
		m.pending[id] = transaction
		m.pendingPerPeer[peerID]++
		m.mu.Unlock()

		return transaction, nil
	}

	return ProbeTransaction{}, fmt.Errorf(
		"%w: unique transaction could not be allocated",
		ErrPeerProbeEntropy,
	)
}

// Complete consumes one transaction and returns an observation only when the
// authenticated reply matches every bound property and arrives before expiry.
func (m *ProbeManager) Complete(
	now time.Time,
	reply AuthenticatedProbeReply,
) (PathObservation, error) {
	if m == nil {
		return PathObservation{}, ErrPeerProbeInactive
	}
	if err := validateAuthenticatedReply(now, reply); err != nil {
		return PathObservation{}, err
	}

	m.mu.Lock()
	pending, exists := m.removeLocked(reply.ID)
	if !exists {
		m.mu.Unlock()

		return PathObservation{}, ErrPeerProbeNotFound
	}
	transaction := pending
	active := m.active
	m.mu.Unlock()

	if !transaction.Deadline.After(now) {
		return PathObservation{}, ErrPeerProbeExpired
	}
	matchesTransaction := !now.Before(transaction.StartedAt) &&
		active == transaction.Generation &&
		reply.PeerID == transaction.PeerID &&
		reply.Generation == transaction.Generation &&
		reply.Source == transaction.Endpoint
	if !matchesTransaction {
		return PathObservation{}, ErrPeerProbeMismatch
	}

	return PathObservation{
		PeerID:                transaction.PeerID,
		Generation:            transaction.Generation,
		RemoteEndpoint:        transaction.Endpoint,
		ObservedLocalEndpoint: reply.ObservedLocalEndpoint,
		RoundTrip:             now.Sub(transaction.StartedAt),
	}, nil
}

// Cancel removes a transaction only when every immutable field still matches
// the pending value. It is used when encoding or transport fails after Start.
func (m *ProbeManager) Cancel(transaction ProbeTransaction) bool {
	if m == nil || transaction.ID.IsZero() {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	pending, exists := m.pending[transaction.ID]
	if !exists || pending != transaction {
		return false
	}
	m.removeLocked(transaction.ID)

	return true
}

// Expire removes transactions whose deadline has arrived.
func (m *ProbeManager) Expire(now time.Time) (int, error) {
	if m == nil {
		return 0, ErrPeerProbeInactive
	}
	if now.IsZero() {
		return 0, ErrInvalidPeerProbe
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.expireLocked(now), nil
}

func (m *ProbeManager) newProbeID() (ProbeID, error) {
	m.randomMu.Lock()
	defer m.randomMu.Unlock()
	if m.random == nil {
		return ProbeID{}, ErrPeerProbeEntropy
	}
	var id ProbeID
	if _, err := io.ReadFull(m.random, id[:]); err != nil {
		return ProbeID{}, fmt.Errorf(
			"%w: reading random transaction: %w",
			ErrPeerProbeEntropy,
			err,
		)
	}

	return id, nil
}

func validateAuthenticatedReply(now time.Time, reply AuthenticatedProbeReply) error {
	if now.IsZero() || reply.ID.IsZero() || reply.PeerID == 0 {
		return ErrInvalidPeerProbe
	}
	if reply.Generation.validate() != nil {
		return ErrInvalidPeerProbe
	}
	if validateEndpoint(reply.Source) != nil ||
		validateEndpoint(reply.ObservedLocalEndpoint) != nil {
		return ErrInvalidPeerProbe
	}

	return nil
}

func (m *ProbeManager) canStartLocked(now time.Time, peerID uint64) error {
	if m.active.validate() != nil {
		return ErrPeerProbeInactive
	}
	m.expireLocked(now)
	if len(m.pending) >= m.maxPending || m.pendingPerPeer[peerID] >= m.maxPerPeer {
		return ErrPeerProbeCapacity
	}

	return nil
}

func (m *ProbeManager) expireLocked(now time.Time) int {
	removed := 0
	for id, transaction := range m.pending {
		if transaction.Deadline.After(now) {
			continue
		}
		m.removeLocked(id)
		removed++
	}

	return removed
}

func (m *ProbeManager) removeLocked(id ProbeID) (ProbeTransaction, bool) {
	transaction, exists := m.pending[id]
	if !exists {
		return ProbeTransaction{}, false
	}
	delete(m.pending, id)
	peerID := transaction.PeerID
	remaining := m.pendingPerPeer[peerID] - 1
	if remaining <= 0 {
		delete(m.pendingPerPeer, peerID)
	} else {
		m.pendingPerPeer[peerID] = remaining
	}

	return transaction, true
}

func (m *ProbeManager) clearLocked() int {
	removed := len(m.pending)
	clear(m.pending)
	clear(m.pendingPerPeer)
	m.active = ProbeGeneration{}

	return removed
}
