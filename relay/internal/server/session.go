package server

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/relay/internal/ratelimit"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// StreamConn is a stream transport connection (TLS or WebSocket) a session
// can be bound to. Send must copy or finish with frame before returning.
type StreamConn interface {
	Send(frame []byte) error
	Close() error
}

// streamPeer is implemented by stream connections that know their remote
// address, so stream handshakes share the per-source limit with UDP.
type streamPeer interface {
	RemoteAddr() netip.Addr
}

// streamBinder is implemented by stream connections that want to know when a
// session binds to them (they close connections that never get one).
type streamBinder interface {
	SessionBound()
}

// binding is where a session's client is reachable. It is immutable; roaming
// and verification replace it atomically.
//
// A UDP binding starts unverified: the relay has not yet seen proof that the
// client receives at that address, so traffic towards it is capped
// (mtrp-v1 §5.2). The handshake binding is verified by the first
// authenticated CONTROL frame from it, because the session keys required
// the RESPONSE sent there. A roamed binding is verified only by a
// PATH_RESPONSE echoing the relay's PATH_CHALLENGE.
type binding struct {
	udp       netip.AddrPort // set for UDP sessions
	stream    StreamConn     // set for stream sessions (always verified)
	verified  bool
	handshake bool // the binding the INIT came from
}

func (b *binding) matches(from binding) bool {
	if from.stream != nil {
		return b.stream == from.stream
	}
	return b.stream == nil && b.udp == from.udp
}

// route is one direction of a relayed pair: frames on the owner's route
// number go to peer, which knows the pair as peerRoute. zone is the zone
// both tickets shared when it opened, rechecked first when tickets or
// revocations change.
type route struct {
	peer      *session
	peerRoute uint32
	zone      mtrp.Zone
}

// session is the relay's state for one authenticated client.
type session struct {
	crypto *mtrp.Session
	node   key.NodePublic
	disco  key.DiscoPublic

	binding   atomic.Pointer[binding]
	lastRecv  atomic.Int64  // Unix nanoseconds of the last authenticated or forwarded frame
	challenge atomic.Uint64 // outstanding PATH_CHALLENGE nonce for the current binding, 0 if none

	mu         sync.Mutex // guards the fields below
	ticket     mtrp.Ticket
	notAfter   time.Time
	maxRoutes  int
	routes     map[uint32]route          // by this session's route number
	byPeer     map[key.NodePublic]uint32 // route number by peer node, one route per pair
	nextRoute  uint32                    // route numbers are never reused within a session
	data       ratelimit.Bucket          // bytes per second from this client
	packets    ratelimit.Bucket          // packets per second from this client
	control    ratelimit.Bucket          // authenticated CONTROL frames per second
	unverified ratelimit.Bucket          // bytes per second towards an unverified binding
	routeOpens ratelimit.Bucket
	zoneFrames ratelimit.Bucket // ZONES frames per second
	closed     bool

	// pending collects the zones of an MTT2 ticket not yet in force: the
	// session keeps its current ticket until they all arrive (§5.4).
	pending *mtrp.ZoneAssembly
	// Zones charged to the relay budget for the current and pending ticket.
	chargedCurrent, chargedPending int
	reackAt                        time.Time // earliest repeat of a TICKET_ACK for resent ZONES
}

func (s *session) index() uint32 { return s.crypto.LocalIndex() }

func (s *session) touch(now time.Time) { s.lastRecv.Store(now.UnixNano()) }

// forward returns the route for a route number and the sender's Network,
// charging the sender's rate limits for one DATA frame of n bytes.
func (s *session) forward(routeNumber uint32, n int, now time.Time) (route, [16]byte, dropReason) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return route{}, [16]byte{}, dropNoSession
	}
	r, ok := s.routes[routeNumber]
	if !ok {
		return route{}, [16]byte{}, dropNoRoute
	}
	if !s.packets.Allow(now, 1) || !s.data.Allow(now, float64(n)) {
		return route{}, [16]byte{}, dropRateLimited
	}
	return r, networkZone(s.ticket), dropNone
}

// allowTowards charges traffic sent to this session's client while its
// binding is unverified.
func (s *session) allowTowards(n int, now time.Time) bool {
	if b := s.binding.Load(); b == nil || b.verified {
		return b != nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unverified.Allow(now, float64(n))
}

// allowControl charges one authenticated CONTROL frame.
func (s *session) allowControl(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.control.Allow(now, 1)
}

// newRouteNumber returns the next route number not in use. Called with s.mu
// held.
func (s *session) newRouteNumberLocked() (uint32, bool) {
	for range 16 {
		s.nextRoute++
		if n := s.nextRoute; n != 0 {
			if _, used := s.routes[n]; !used {
				return n, true
			}
		}
	}
	return 0, false
}

// sharedZone returns a zone both sessions' tickets carry that Core has not
// withdrawn (r may be nil).
func sharedZone(a, b *session, r mtrp.Revocations) (mtrp.Zone, bool) {
	ta, tb := a.currentTicket(), b.currentTicket()
	return mtrp.SharedLiveZone(ta, tb, r)
}

// bothHold reports whether both sessions' tickets still carry z live.
func bothHold(a, b *session, z mtrp.Zone, r mtrp.Revocations) bool {
	return mtrp.HasLiveZone(a.currentTicket(), z, r) && mtrp.HasLiveZone(b.currentTicket(), z, r)
}

// routeTo returns the peer of route number n, or nil.
func (s *session) routeTo(n uint32) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.routes[n].peer
}

// holdsTicket reports whether id is the ticket in force or being assembled.
func (s *session) holdsTicket(id [16]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ticket.ID == id || s.pending != nil && s.pending.Ticket().ID == id
}

// currentTicket returns the ticket in force. Its zone slice is replaced,
// never changed in place, so it may be read without the lock.
func (s *session) currentTicket() mtrp.Ticket {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ticket
}

type dropReason uint8

const (
	dropNone dropReason = iota
	dropNoSession
	dropNoRoute
	dropRateLimited
	dropBinding
	dropMalformed
	dropUnverified
	dropNetworkLimited
)

func (d dropReason) String() string {
	switch d {
	case dropNoSession:
		return "no_session"
	case dropNoRoute:
		return "no_route"
	case dropRateLimited:
		return "rate_limited"
	case dropBinding:
		return "wrong_source"
	case dropMalformed:
		return "malformed"
	case dropUnverified:
		return "unverified_peer"
	case dropNetworkLimited:
		return "network_rate_limited"
	default:
		return "forwarded"
	}
}
