package server

import (
	"encoding/binary"
	"io"
	"math"
	"time"

	"meshtransit.net/relay/internal/ratelimit"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// handleInit authenticates a client and creates its session, in the order
// mtrp-v1 §4 requires: cheap MAC checks and admission before any public-key
// work, then the ticket, then state.
func (s *Server) handleInit(frame []byte, from binding, stream bool) {
	in, err := mtrp.ParseInit(frame)
	if err != nil {
		s.cfg.Metrics.Handshake("malformed")
		return
	}
	beforeMAC1, beforeMAC2, err := mtrp.MACInput(frame)
	if err != nil || !s.macs.CheckMAC1(beforeMAC1, in.MAC1) {
		s.cfg.Metrics.Handshake("bad_mac1")
		return
	}
	now := s.cfg.Now()
	if !stream && !s.sources.Allow(from.udp.Addr()) {
		s.cfg.Metrics.Handshake("source_limited")
		return
	}
	// A full relay counts as loaded: new handshakes must prove their address
	// before any public-key work (mtrp-v1 §7).
	if !s.hsLimit.Allow(now) || s.SessionCount() >= s.cfg.MaxSessions {
		if stream {
			// The TCP handshake already proved the address; shed load.
			s.cfg.Metrics.Handshake("overloaded")
			return
		}
		// Under load a UDP INIT must prove its source address with a
		// cookie; answering costs no state and is smaller than the INIT.
		cookie, err := s.cookies.Cookie(from.udp)
		if err != nil {
			return
		}
		if !mtrp.CheckMAC2(cookie, beforeMAC2, in.MAC2) {
			s.sendCookie(in, cookie, from)
			return
		}
	}
	if s.isDraining() {
		s.cfg.Metrics.Handshake("draining")
		return
	}

	hs, err := mtrp.ReadInit(s.cfg.Key, frame)
	if err != nil {
		s.cfg.Metrics.Handshake("bad_noise")
		return
	}
	hello, peer := hs.Hello(), hs.Peer()
	ticket, err := s.verifier.Verify(hello.Ticket)
	if err != nil {
		s.cfg.Metrics.Handshake("bad_ticket")
		return
	}
	if !key.Equal(ticket.Disco, peer) {
		s.cfg.Metrics.Handshake("ticket_mismatch")
		return
	}
	if !s.timestampInWindow(hello.TimestampMS, now) {
		s.cfg.Metrics.Handshake("stale_timestamp")
		return
	}
	if !s.freshTimestamp(peer, hello.TimestampMS) {
		s.cfg.Metrics.Handshake("replay")
		return
	}

	index, err := s.randomIndex()
	if err != nil {
		return
	}
	maxRoutes, bytesPerSecond := s.ticketLimits(ticket)
	resp, crypto, err := hs.Respond(index, mtrp.ServerHello{
		KeepaliveS:   seconds(s.cfg.Keepalive),
		IdleTimeoutS: seconds(s.cfg.IdleTimeout),
		MaxRoutes:    uint16(maxRoutes), //nolint:gosec // capped at MaxUint16 by ticketLimits
		NotAfterMS:   ticket.NotAfterMS,
	}, s.macs)
	if err != nil {
		s.cfg.Metrics.Handshake("respond_failed")
		return
	}
	sess := &session{
		crypto:     crypto,
		node:       ticket.Node,
		disco:      peer,
		ticket:     ticket,
		notAfter:   ticket.NotAfter(),
		maxRoutes:  maxRoutes,
		routes:     make(map[uint32]route),
		byPeer:     make(map[key.NodePublic]uint32),
		nextRoute:  index, // any start works; numbers then never repeat in this session
		data:       ratelimit.NewBucket(bytesPerSecond, bytesPerSecond),
		packets:    ratelimit.NewBucket(s.cfg.PacketRate, s.cfg.PacketRate),
		control:    ratelimit.NewBucket(s.cfg.ControlRate, 2*s.cfg.ControlRate),
		unverified: ratelimit.NewBucket(s.cfg.UnverifiedRate, 2*s.cfg.UnverifiedRate),
		routeOpens: ratelimit.NewBucket(s.cfg.RouteOpenRate, s.cfg.RouteOpenRate),
	}
	bound := from
	bound.handshake = true
	sess.binding.Store(&bound)
	sess.touch(now)

	replaced, result := s.register(sess, hello.TimestampMS)
	if result != "" {
		s.cfg.Metrics.Handshake(result)
		return
	}
	// Answer first: the client completes its new session before it hears
	// that the old one (already unreachable through the maps) is closed.
	if err := s.sendTo(&bound, resp); err != nil {
		s.closeSession(sess, mtrp.SessionClosePolicy, 0)
		s.cfg.Metrics.Handshake("send_failed")
	} else {
		s.cfg.Metrics.Handshake("ok")
	}
	for _, old := range replaced {
		s.closeSession(old, mtrp.SessionClosePolicy, 0)
	}
}

// register inserts a new session, replacing any session of the same disco or
// node key (a client keeps one session per relay node). It returns a metrics
// result when the session is refused.
func (s *Server) register(sess *session, timestampMS int64) ([]*session, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.timestamps[sess.disco]; ok && timestampMS <= last {
		return nil, "replay"
	}
	if s.draining {
		return nil, "draining"
	}
	if s.byIndex[sess.index()] != nil {
		return nil, "index_collision" // the client retries with a new handshake
	}
	var replaced []*session
	if old := s.byDisco[sess.disco]; old != nil {
		replaced = append(replaced, old)
	}
	if old := s.byNode[sess.node]; old != nil && (len(replaced) == 0 || replaced[0] != old) {
		replaced = append(replaced, old)
	}
	if len(s.byIndex)-len(replaced) >= s.cfg.MaxSessions {
		return nil, "full"
	}
	s.timestamps[sess.disco] = timestampMS
	s.byIndex[sess.index()] = sess
	s.byNode[sess.node] = sess
	s.byDisco[sess.disco] = sess
	s.cfg.Metrics.Sessions(len(s.byIndex))
	return replaced, ""
}

// freshTimestamp is the early, read-only replay check that avoids Noise
// work for replayed INITs; register repeats it atomically.
func (s *Server) freshTimestamp(disco key.DiscoPublic, timestampMS int64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	last, ok := s.timestamps[disco]
	return !ok || timestampMS > last
}

// timestampInWindow bounds a ClientHello timestamp to the relay clock and
// rejects INITs from before the relay started: replay state does not survive
// a restart, so older INITs cannot be told from replays.
func (s *Server) timestampInWindow(timestampMS int64, now time.Time) bool {
	skew := MaxTimestampSkew.Milliseconds()
	nowMS := now.UnixMilli()
	return timestampMS >= s.startedMS && timestampMS >= nowMS-skew && timestampMS <= nowMS+skew
}

func (s *Server) isDraining() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.draining
}

// ticketLimits applies the ticket's limits, capped by relay policy.
func (s *Server) ticketLimits(t mtrp.Ticket) (maxRoutes int, bytesPerSecond float64) {
	maxRoutes = s.cfg.MaxRoutes
	if t.MaxRoutes != 0 {
		maxRoutes = min(maxRoutes, int(t.MaxRoutes))
	}
	maxRoutes = min(maxRoutes, math.MaxUint16)
	bytesPerSecond = s.cfg.BytesPerSecond
	if t.MaxBPS != 0 {
		bytesPerSecond = min(bytesPerSecond, float64(t.MaxBPS))
	}
	return maxRoutes, bytesPerSecond
}

func (s *Server) sendCookie(in mtrp.Init, cookie [mtrp.MACSize]byte, from binding) {
	nonce, sealed, err := s.macs.SealCookie(cookie, in.MAC1, s.cfg.Random)
	if err != nil {
		return
	}
	frame, err := mtrp.AppendCookie(make([]byte, 0, 64), mtrp.Cookie{ReceiverIndex: in.SenderIndex, Nonce: nonce, EncryptedCookie: sealed})
	if err != nil {
		return
	}
	if err := s.sendTo(&from, frame); err == nil {
		s.cfg.Metrics.Handshake("cookie_sent")
	}
}

// randomIndex returns a random non-zero session index; register rejects the
// rare collision with an existing session.
func (s *Server) randomIndex() (uint32, error) {
	var b [4]byte
	for {
		if _, err := io.ReadFull(s.cfg.Random, b[:]); err != nil {
			return 0, err
		}
		if i := binary.BigEndian.Uint32(b[:]); i != 0 {
			return i, nil
		}
	}
}

func seconds(d time.Duration) uint16 {
	return uint16(min(max(d/time.Second, 1), math.MaxUint16))
}
