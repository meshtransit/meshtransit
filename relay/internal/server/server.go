// Package server implements the Interchange relay: MTRP v1 sessions, routes
// and DATA forwarding (docs/protocol/mtrp-v1.md).
//
// Transports call HandleUDP or HandleStream for every received frame. All
// decisions use in-memory state; the only I/O on the packet path is the send
// of the forwarded frame. The server owns no sockets.
package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"sync"
	"time"

	"meshtransit.net/relay/internal/ratelimit"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// Defaults (mtrp-v1 §4, §5, §7).
const (
	DefaultKeepalive           = 25 * time.Second
	DefaultIdleTimeout         = 90 * time.Second
	DefaultMaxRoutes           = 4096
	DefaultMaxSessions         = 100_000
	DefaultHandshakeRate       = 1000 // per second, before cookie mode
	DefaultSourceHandshakeRate = 10   // per second per source address (IPv6: per /64)
	DefaultPacketRate          = 50_000
	DefaultBytesPerSecond      = 125_000_000 // 1 Gbit/s ceiling per session
	DefaultUnverifiedRate      = 16 << 10    // bytes/s towards an unverified binding
	DefaultControlRate         = 50          // authenticated CONTROL frames per second
	DefaultRouteOpenRate       = 20          // per second per session
	// MaxTimestampSkew bounds a ClientHello timestamp against the relay
	// clock, which bounds how long replay state must be kept.
	MaxTimestampSkew = time.Minute
	janitorInterval  = time.Second
	maxSources       = 1 << 16
)

// UDPSender sends datagrams from the relay's UDP socket.
type UDPSender interface {
	WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error)
}

// Config configures a Server. Zero limits take the defaults.
type Config struct {
	Key         key.RelayPrivate
	Keys        mtrp.KeySet      // trusted Core signing keys
	Revocations mtrp.Revocations // optional
	UDP         UDPSender        // nil when UDP is disabled

	Keepalive           time.Duration
	IdleTimeout         time.Duration
	MaxSessions         int
	MaxRoutes           int     // per session, capped by the ticket
	HandshakeRate       float64 // per second; above it INIT needs a cookie (mac2)
	SourceHandshakeRate float64 // per source address
	PacketRate          float64 // per session
	BytesPerSecond      float64 // per session ceiling; tickets may lower it
	UnverifiedRate      float64 // bytes/s towards a binding without return-routability
	ControlRate         float64 // per session
	RouteOpenRate       float64 // per session

	Now     func() time.Time
	Random  io.Reader
	Logger  *slog.Logger
	Metrics Metrics
}

// Server is a relay instance. It is safe for concurrent use.
type Server struct {
	cfg       Config
	macs      mtrp.RelayMACKeys
	verifier  mtrp.Verifier
	cookies   *mtrp.CookieJar
	hsLimit   *ratelimit.Shared
	sources   *ratelimit.SourceLimiter
	startedMS int64 // INITs older than the start cannot be told from replays

	mu         sync.RWMutex // guards the maps below
	byIndex    map[uint32]*session
	byNode     map[key.NodePublic]*session
	byDisco    map[key.DiscoPublic]*session
	timestamps map[key.DiscoPublic]int64            // last accepted ClientHello timestamp
	streams    map[StreamConn]map[*session]struct{} // sessions bound to each stream connection
	draining   bool

	routeMu sync.Mutex // serialises route creation and removal across sessions

	revGeneration uint64 // last revocation generation swept; owned by sweep
}

// generational is implemented by revocation sources that can say when they
// changed, so sweeps rescan sessions only after an update.
type generational interface {
	Generation() uint64
}

type (
	dataBuffer    = [mtrp.MaxUDPFrame]byte
	controlBuffer = [mtrp.MaxControlPlaintext + 64]byte
)

// Buffer pools keep the packet path free of per-frame allocations.
var (
	dataBuffers    = sync.Pool{New: func() any { return new(dataBuffer) }}
	controlBuffers = sync.Pool{New: func() any { return new(controlBuffer) }}
)

func getDataBuffer() *dataBuffer {
	if b, ok := dataBuffers.Get().(*dataBuffer); ok {
		return b
	}
	return new(dataBuffer)
}

func getControlBuffer() *controlBuffer {
	if b, ok := controlBuffers.Get().(*controlBuffer); ok {
		return b
	}
	return new(controlBuffer)
}

// New creates a server.
func New(cfg Config) (*Server, error) {
	if cfg.Key.IsZero() || cfg.Keys == nil {
		return nil, errors.New("server: relay key and trusted signing keys are required")
	}
	defaults(&cfg)
	if cfg.IdleTimeout <= cfg.Keepalive {
		return nil, errors.New("server: idle timeout must exceed the keepalive interval")
	}
	cookies, err := mtrp.NewCookieJar(cfg.Random, cfg.Now)
	if err != nil {
		return nil, fmt.Errorf("server: cookie jar: %w", err)
	}
	return &Server{
		cfg:        cfg,
		macs:       mtrp.NewRelayMACKeys(cfg.Key.Public()),
		verifier:   mtrp.Verifier{Keys: cfg.Keys, Revocations: cfg.Revocations, Now: cfg.Now},
		cookies:    cookies,
		hsLimit:    ratelimit.NewShared(cfg.HandshakeRate, cfg.HandshakeRate),
		sources:    ratelimit.NewSourceLimiter(cfg.SourceHandshakeRate, 2*cfg.SourceHandshakeRate, maxSources, cfg.Now),
		startedMS:  cfg.Now().UnixMilli(),
		byIndex:    make(map[uint32]*session),
		byNode:     make(map[key.NodePublic]*session),
		byDisco:    make(map[key.DiscoPublic]*session),
		timestamps: make(map[key.DiscoPublic]int64),
		streams:    make(map[StreamConn]map[*session]struct{}),
	}, nil
}

func defaults(cfg *Config) {
	setDefault(&cfg.Keepalive, DefaultKeepalive)
	setDefault(&cfg.IdleTimeout, DefaultIdleTimeout)
	setDefault(&cfg.MaxSessions, DefaultMaxSessions)
	setDefault(&cfg.MaxRoutes, DefaultMaxRoutes)
	setDefault(&cfg.HandshakeRate, DefaultHandshakeRate)
	setDefault(&cfg.SourceHandshakeRate, DefaultSourceHandshakeRate)
	setDefault(&cfg.PacketRate, DefaultPacketRate)
	setDefault(&cfg.BytesPerSecond, DefaultBytesPerSecond)
	setDefault(&cfg.UnverifiedRate, DefaultUnverifiedRate)
	setDefault(&cfg.ControlRate, DefaultControlRate)
	setDefault(&cfg.RouteOpenRate, DefaultRouteOpenRate)
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Metrics == nil {
		cfg.Metrics = nopMetrics{}
	}
}

func setDefault[T int | float64 | time.Duration](v *T, d T) {
	if *v <= 0 {
		*v = d
	}
}

// PublicKey returns the relay's public key, as published in the relay map.
func (s *Server) PublicKey() key.RelayPublic { return s.cfg.Key.Public() }

// HandleUDP processes one datagram received on the relay's UDP socket. The
// frame is not retained.
func (s *Server) HandleUDP(frame []byte, from netip.AddrPort) {
	s.handle(frame, binding{udp: from}, false)
}

// HandleStream processes one frame received on a stream connection.
func (s *Server) HandleStream(frame []byte, conn StreamConn) {
	s.handle(frame, binding{stream: conn, verified: true}, true)
}

// handle dispatches a frame. from is passed by value so the DATA path does
// not allocate; it is copied to the heap only when a session binds to it.
func (s *Server) handle(frame []byte, from binding, stream bool) {
	t, err := mtrp.PeekType(frame)
	if err != nil {
		s.cfg.Metrics.Data(dropMalformed.String(), 0)
		return
	}
	switch t {
	case mtrp.TypeData:
		s.handleData(frame, from)
	case mtrp.TypeControl:
		s.handleControl(frame, from)
	case mtrp.TypeInit:
		s.handleInit(frame, from, stream)
	default:
		// RESPONSE and COOKIE only flow relay → client.
		s.cfg.Metrics.Data(dropMalformed.String(), 0)
	}
}

func (s *Server) lookup(index uint32) *session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byIndex[index]
}

// handleData forwards a DATA frame to the peer of its route.
func (s *Server) handleData(frame []byte, from binding) {
	d, err := mtrp.ParseData(frame)
	if err != nil {
		s.cfg.Metrics.Data(dropMalformed.String(), 0)
		return
	}
	src := s.lookup(d.ReceiverIndex)
	if src == nil {
		s.cfg.Metrics.Data(dropNoSession.String(), 0)
		return
	}
	// DATA is not authenticated by MTRP (it carries WireGuard ciphertext), so
	// it must come from where the session is bound; only authenticated
	// CONTROL frames move a binding.
	if b := src.binding.Load(); b == nil || !b.matches(from) {
		s.cfg.Metrics.Data(dropBinding.String(), 0)
		return
	}
	now := s.cfg.Now()
	r, reason := src.forward(d.Route, len(d.Payload), now)
	if reason != dropNone {
		s.cfg.Metrics.Data(reason.String(), 0)
		return
	}
	src.touch(now)
	if !r.peer.allowTowards(len(d.Payload), now) {
		s.cfg.Metrics.Data(dropUnverified.String(), 0)
		return
	}
	buf := getDataBuffer()
	defer dataBuffers.Put(buf)
	out, err := mtrp.AppendData(buf[:0], r.peer.crypto.RemoteIndex(), r.peerRoute, d.Payload)
	if err != nil {
		s.cfg.Metrics.Data(dropMalformed.String(), 0)
		return
	}
	if err := s.send(r.peer, out); err != nil {
		s.cfg.Metrics.Data("send_failed", 0)
		return
	}
	s.cfg.Metrics.Data(dropNone.String(), len(d.Payload))
}

// send writes a frame to a session's current binding.
func (s *Server) send(to *session, frame []byte) error {
	b := to.binding.Load()
	if b == nil {
		return errors.New("server: session has no binding")
	}
	return s.sendTo(b, frame)
}

func (s *Server) sendTo(b *binding, frame []byte) error {
	if b.stream != nil {
		return b.stream.Send(frame)
	}
	if s.cfg.UDP == nil {
		return errors.New("server: udp disabled")
	}
	_, err := s.cfg.UDP.WriteToUDPAddrPort(frame, b.udp)
	return err
}

// sendControl seals and sends a CONTROL message to a session.
func (s *Server) sendControl(to *session, msg mtrp.ControlMessage) {
	s.sendControlTo(to, to.binding.Load(), msg)
}

// sendControlTo seals a CONTROL message for a session and sends it to a
// specific binding (a PATH_CHALLENGE goes to the address being verified).
func (s *Server) sendControlTo(to *session, b *binding, msg mtrp.ControlMessage) {
	if b == nil {
		return
	}
	plain, err := mtrp.AppendControlMessage(make([]byte, 0, 64), msg)
	if err != nil {
		s.cfg.Logger.Error("encode control message", "type", msg.Type, "error", err)
		return
	}
	frame, err := to.crypto.SealControl(make([]byte, 0, mtrp.ControlHeaderSize+len(plain)+16), plain)
	if err != nil {
		return // counter exhausted: the session is about to be replaced
	}
	if err := s.sendTo(b, frame); err == nil {
		s.cfg.Metrics.Control("sent")
	}
}

// Run runs the janitor until ctx is done: it closes idle sessions and those
// whose ticket expired or was revoked, and forgets old handshake timestamps.
func (s *Server) Run(ctx context.Context) error {
	t := time.NewTicker(janitorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			s.sweep()
		}
	}
}

// sweep is one janitor pass. It holds the map lock only to copy the session
// list and to prune timestamps, so lookups on the packet path never wait for
// the scan.
func (s *Server) sweep() {
	now := s.cfg.Now()
	s.mu.RLock()
	sessions := make([]*session, 0, len(s.byIndex))
	for _, sess := range s.byIndex {
		sessions = append(sessions, sess)
	}
	s.mu.RUnlock()

	checkRevocations := s.cfg.Revocations != nil
	if g, ok := s.cfg.Revocations.(generational); ok {
		gen := g.Generation()
		checkRevocations = gen != s.revGeneration
		s.revGeneration = gen
	}
	idleBefore := now.Add(-s.cfg.IdleTimeout).UnixNano()
	for _, sess := range sessions {
		sess.mu.Lock()
		ticket, notAfter := sess.ticket, sess.notAfter
		sess.mu.Unlock()
		switch {
		case checkRevocations && mtrp.IsRevoked(ticket, s.cfg.Revocations):
			s.closeSession(sess, mtrp.SessionCloseRevoked, 0)
		case !now.Before(notAfter):
			s.closeSession(sess, mtrp.SessionCloseExpired, 0)
		case sess.lastRecv.Load() < idleBefore:
			s.closeSession(sess, mtrp.SessionCloseIdle, 0)
		case checkRevocations:
			s.pruneRoutes(sess) // a withdrawn zone may end some of its routes
		}
	}

	// A timestamp older than the skew window can never be accepted again,
	// so forgetting it cannot let a replay through.
	forgetBefore := now.Add(-2 * MaxTimestampSkew).UnixMilli()
	s.mu.Lock()
	for disco, ts := range s.timestamps {
		if ts < forgetBefore && s.byDisco[disco] == nil {
			delete(s.timestamps, disco)
		}
	}
	s.mu.Unlock()
}

// pruneRoutes closes the routes of sess that no longer share a live zone.
func (s *Server) pruneRoutes(sess *session) {
	s.routeMu.Lock()
	sess.mu.Lock()
	routes := maps.Clone(sess.routes)
	sess.mu.Unlock()
	out := s.pruneRoutesLocked(sess, routes, nil)
	s.routeMu.Unlock()
	s.flush(out)
}

// closeSession removes a session, tells its client and closes its routes.
// No lock is held while sending.
func (s *Server) closeSession(sess *session, reason mtrp.SessionCloseReason, retryAfter time.Duration) {
	s.mu.Lock()
	if s.byIndex[sess.index()] == sess {
		delete(s.byIndex, sess.index())
	}
	if s.byNode[sess.node] == sess {
		delete(s.byNode, sess.node)
	}
	if s.byDisco[sess.disco] == sess {
		delete(s.byDisco, sess.disco)
	}
	if b := sess.binding.Load(); b != nil && b.stream != nil {
		s.unbindStreamLocked(b.stream, sess)
	}
	s.cfg.Metrics.Sessions(len(s.byIndex))
	s.mu.Unlock()

	s.routeMu.Lock()
	sess.mu.Lock()
	already := sess.closed
	sess.closed = true
	routes := sess.routes
	sess.routes, sess.byPeer = nil, nil
	sess.mu.Unlock()
	for _, r := range routes {
		s.dropPeerRouteLocked(r.peer, r.peerRoute, sess.node)
	}
	s.routeMu.Unlock()
	if already {
		return
	}
	if len(routes) > 0 {
		s.cfg.Metrics.Routes(-len(routes))
	}
	for _, r := range routes {
		s.sendControl(r.peer, mtrp.ControlMessage{Type: mtrp.ControlRouteClose, Route: r.peerRoute, RouteClose: mtrp.RouteClosePeerLeft})
	}
	s.sendControl(sess, mtrp.ControlMessage{Type: mtrp.ControlSessionClose, SessionClose: reason, RetryAfterMS: millis32(retryAfter)})
	s.cfg.Logger.Debug("session closed", "reason", reason)
}

// StreamClosed tells the server a stream connection ended: the sessions bound
// to it can no longer be reached and are closed at once instead of waiting
// for the idle timeout.
func (s *Server) StreamClosed(conn StreamConn) {
	s.mu.Lock()
	bound := s.streams[conn]
	delete(s.streams, conn)
	s.mu.Unlock()
	for sess := range bound {
		if b := sess.binding.Load(); b != nil && b.stream == conn {
			s.closeSession(sess, mtrp.SessionClosePolicy, 0)
		}
	}
}

func (s *Server) bindStreamLocked(conn StreamConn, sess *session) {
	set, ok := s.streams[conn]
	if !ok {
		set = make(map[*session]struct{})
		s.streams[conn] = set
	}
	set[sess] = struct{}{}
	if b, ok := conn.(streamBinder); ok {
		b.SessionBound()
	}
}

func (s *Server) unbindStreamLocked(conn StreamConn, sess *session) {
	if set, ok := s.streams[conn]; ok {
		delete(set, sess)
		if len(set) == 0 {
			delete(s.streams, conn)
		}
	}
}

// moveBinding replaces a session's binding and updates the stream index in
// one step, so concurrent roams cannot leave the index behind the binding.
// It reports false if another change won the race.
func (s *Server) moveBinding(sess *session, from, to *binding) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !sess.binding.CompareAndSwap(from, to) {
		return false
	}
	if from != nil && from.stream != nil {
		s.unbindStreamLocked(from.stream, sess)
	}
	if to.stream != nil && s.byIndex[sess.index()] == sess {
		s.bindStreamLocked(to.stream, sess)
	}
	return true
}

// Drain stops accepting new sessions and tells every client to move to
// another relay within retryAfter. Existing sessions keep forwarding until
// the clients leave or the process stops.
func (s *Server) Drain(retryAfter time.Duration) {
	s.mu.Lock()
	s.draining = true
	sessions := make([]*session, 0, len(s.byIndex))
	for _, sess := range s.byIndex {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	for _, sess := range sessions {
		s.sendControl(sess, mtrp.ControlMessage{
			Type: mtrp.ControlSessionClose, SessionClose: mtrp.SessionCloseDraining, RetryAfterMS: millis32(retryAfter),
		})
	}
}

// SessionCount returns the number of active sessions.
func (s *Server) SessionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byIndex)
}

func millis32(d time.Duration) uint32 {
	return uint32(min(max(d.Milliseconds(), 0), int64(^uint32(0))))
}
