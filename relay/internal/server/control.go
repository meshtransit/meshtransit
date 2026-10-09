package server

import (
	"encoding/binary"
	"errors"
	"io"
	"maps"

	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// outbound is a CONTROL message to send once no lock is held.
type outbound struct {
	to  *session
	msg mtrp.ControlMessage
}

func (s *Server) flush(msgs []outbound) {
	for _, o := range msgs {
		s.sendControl(o.to, o.msg)
	}
}

// handleControl authenticates a CONTROL frame, updates the session binding
// (roaming and return-routability, mtrp-v1 §5.2) and dispatches the message.
func (s *Server) handleControl(frame []byte, from binding) {
	c, err := mtrp.ParseControl(frame)
	if err != nil {
		s.cfg.Metrics.Control("malformed")
		return
	}
	sess := s.lookup(c.ReceiverIndex)
	if sess == nil {
		s.cfg.Metrics.Control("no_session")
		return
	}
	buf := getControlBuffer()
	defer controlBuffers.Put(buf)
	plain, err := sess.crypto.OpenControl(buf[:0], frame)
	switch {
	case errors.Is(err, mtrp.ErrReplay):
		s.cfg.Metrics.Control("replay")
		return
	case err != nil:
		s.cfg.Metrics.Control("bad_auth")
		return
	}
	// Charged after authentication, so forged frames cannot exhaust a
	// victim's allowance.
	now := s.cfg.Now()
	if !sess.allowControl(now) {
		s.cfg.Metrics.Control("rate_limited")
		return
	}
	sess.touch(now)
	msg, err := mtrp.ParseControlMessage(plain)
	if err != nil {
		s.cfg.Metrics.Control("invalid")
		return
	}
	s.updateBinding(sess, from, msg)
	s.cfg.Metrics.Control("received")
	switch msg.Type {
	case mtrp.ControlKeepalive:
		// Answer so the client can tell a live relay from a dead path.
		s.sendControl(sess, mtrp.ControlMessage{Type: mtrp.ControlKeepalive})
	case mtrp.ControlRouteOpen:
		s.openRoute(sess, msg)
	case mtrp.ControlRouteClose:
		s.closeRoute(sess, msg.Route, mtrp.RouteCloseByClient)
	case mtrp.ControlTicketUpdate:
		s.updateTicket(sess, msg.Ticket)
	case mtrp.ControlPathResponse:
		// Handled by updateBinding.
	default:
		s.cfg.Metrics.Control("unexpected")
	}
}

// updateBinding applies the roaming and verification rules:
//
//   - an authenticated frame from the handshake binding verifies it (the
//     session keys required the RESPONSE sent to that address);
//   - an authenticated frame from a new address moves the binding there,
//     unverified, and the relay sends a PATH_CHALLENGE to that address;
//   - a PATH_RESPONSE with the outstanding nonce from the current binding
//     verifies it.
//
// Traffic towards an unverified binding is capped, so moving a binding to a
// victim's address cannot turn the relay into a reflector.
func (s *Server) updateBinding(sess *session, from binding, msg mtrp.ControlMessage) {
	current := sess.binding.Load()
	if current == nil {
		return
	}
	if !current.matches(from) {
		moved := from
		moved.verified = from.stream != nil
		if !s.moveBinding(sess, current, &moved) {
			return
		}
		s.cfg.Metrics.Control("roamed")
		if !moved.verified {
			s.challenge(sess, &moved)
		}
		return
	}
	switch {
	case current.verified:
	case current.handshake:
		s.verify(sess, current)
	case msg.Type == mtrp.ControlPathResponse && msg.Nonce != 0 && sess.challenge.CompareAndSwap(msg.Nonce, 0):
		s.verify(sess, current)
	}
}

func (s *Server) verify(sess *session, b *binding) {
	verified := *b
	verified.verified = true
	sess.binding.CompareAndSwap(b, &verified)
}

// challenge sends a PATH_CHALLENGE with a fresh nonce to an unverified
// binding. A new challenge replaces any outstanding one.
func (s *Server) challenge(sess *session, b *binding) {
	var raw [8]byte
	if _, err := io.ReadFull(s.cfg.Random, raw[:]); err != nil {
		return
	}
	nonce := binary.BigEndian.Uint64(raw[:]) | 1 // never zero
	sess.challenge.Store(nonce)
	s.sendControlTo(sess, b, mtrp.ControlMessage{Type: mtrp.ControlPathChallenge, Nonce: nonce})
}

// openRoute grants a route to a peer that has a session on this relay and
// shares a zone with the requester. An absent peer and an unauthorised one
// get the same answer, so a client cannot probe which nodes are connected.
// Decisions and changes happen under routeMu; messages go out after it is
// released, so a slow client cannot stall route changes relay-wide.
func (s *Server) openRoute(src *session, msg mtrp.ControlMessage) {
	src.mu.Lock()
	allowed := src.routeOpens.Allow(s.cfg.Now(), 1)
	src.mu.Unlock()
	refuse := func(code mtrp.RouteErrorCode) {
		s.sendControl(src, mtrp.ControlMessage{Type: mtrp.ControlRouteError, Request: msg.Request, RouteError: code})
	}
	switch {
	case !allowed:
		refuse(mtrp.RouteErrorLimit)
		return
	case key.Equal(msg.Peer, src.node):
		refuse(mtrp.RouteErrorInvalid)
		return
	}
	s.routeMu.Lock()
	out, code := s.openRouteLocked(src, msg)
	s.routeMu.Unlock()
	if code != 0 {
		refuse(code)
		return
	}
	s.flush(out)
}

// openRouteLocked decides and records a route. Called with routeMu held.
// The peer learns about the route before the requester, so DATA from the
// requester never arrives on a route the peer cannot attribute.
func (s *Server) openRouteLocked(src *session, msg mtrp.ControlMessage) ([]outbound, mtrp.RouteErrorCode) {
	s.mu.RLock()
	peer := s.byNode[msg.Peer]
	s.mu.RUnlock()
	if peer == nil || !sharesZone(src, peer, s.cfg.Revocations) {
		return nil, mtrp.RouteErrorPeerAbsent
	}

	src.mu.Lock()
	if src.closed {
		src.mu.Unlock()
		return nil, 0
	}
	if existing, ok := src.byPeer[peer.node]; ok {
		r := src.routes[existing]
		src.mu.Unlock()
		if r.peer == peer {
			// Idempotent: repeat both notifications, in case one was lost.
			return []outbound{
				{peer, mtrp.ControlMessage{Type: mtrp.ControlRouteIncoming, Route: r.peerRoute, Peer: src.node}},
				{src, mtrp.ControlMessage{Type: mtrp.ControlRouteOK, Request: msg.Request, Route: existing}},
			}, 0
		}
		// The route points at a replaced session that is still closing.
		s.removeRouteLocked(src, existing)
		src.mu.Lock()
	}
	srcFull := len(src.routes) >= src.maxRoutes
	srcRoute, srcOK := src.newRouteNumberLocked()
	src.mu.Unlock()

	peer.mu.Lock()
	peerClosed, peerFull := peer.closed, len(peer.routes) >= peer.maxRoutes
	peerRoute, peerOK := peer.newRouteNumberLocked()
	peer.mu.Unlock()
	switch {
	case peerClosed:
		return nil, mtrp.RouteErrorPeerAbsent
	case srcFull || peerFull || !srcOK || !peerOK:
		return nil, mtrp.RouteErrorLimit
	}
	// routeMu makes the checks above and these inserts one step.
	src.mu.Lock()
	src.routes[srcRoute] = route{peer: peer, peerRoute: peerRoute}
	src.byPeer[peer.node] = srcRoute
	src.mu.Unlock()
	peer.mu.Lock()
	peer.routes[peerRoute] = route{peer: src, peerRoute: srcRoute}
	peer.byPeer[src.node] = peerRoute
	peer.mu.Unlock()
	s.cfg.Metrics.Routes(1)
	return []outbound{
		{peer, mtrp.ControlMessage{Type: mtrp.ControlRouteIncoming, Route: peerRoute, Peer: src.node}},
		{src, mtrp.ControlMessage{Type: mtrp.ControlRouteOK, Request: msg.Request, Route: srcRoute}},
	}, 0
}

// closeRoute removes a route at the request of one side and tells the other.
func (s *Server) closeRoute(owner *session, routeNumber uint32, reason mtrp.RouteCloseReason) {
	s.routeMu.Lock()
	r, ok := s.removeRouteLocked(owner, routeNumber)
	s.routeMu.Unlock()
	if ok {
		s.sendControl(r.peer, mtrp.ControlMessage{Type: mtrp.ControlRouteClose, Route: r.peerRoute, RouteClose: reason})
	}
}

// removeRouteLocked removes both halves of a route. Called with routeMu held.
func (s *Server) removeRouteLocked(owner *session, routeNumber uint32) (route, bool) {
	owner.mu.Lock()
	r, ok := owner.routes[routeNumber]
	if ok {
		delete(owner.routes, routeNumber)
		delete(owner.byPeer, r.peer.node)
	}
	owner.mu.Unlock()
	if ok {
		s.dropPeerRouteLocked(r.peer, r.peerRoute, owner.node)
		s.cfg.Metrics.Routes(-1)
	}
	return r, ok
}

// dropPeerRouteLocked removes the peer's half of a route. Called with
// routeMu held.
func (s *Server) dropPeerRouteLocked(peer *session, peerRoute uint32, node key.NodePublic) {
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if r, ok := peer.routes[peerRoute]; ok && key.Equal(r.peer.node, node) {
		delete(peer.routes, peerRoute)
		delete(peer.byPeer, node)
	}
}

// updateTicket renews a session's ticket (mtrp-v1 §5.3). The new ticket must
// be for the same keys and not older than the current one. Routes whose peer
// no longer shares a zone are closed as revoked; routeMu keeps a concurrent
// route open from slipping past the check.
func (s *Server) updateTicket(sess *session, raw []byte) {
	ticket, err := s.verifier.Verify(raw)
	if err != nil || !key.Equal(ticket.Node, sess.node) || !key.Equal(ticket.Disco, sess.disco) {
		s.cfg.Metrics.Control("bad_ticket_update")
		return // the current ticket stays in force until it expires
	}
	ticket.Zones = append([]mtrp.Zone(nil), ticket.Zones...) // detach from the frame buffer
	maxRoutes, bytesPerSecond := s.ticketLimits(ticket)

	var out []outbound
	s.routeMu.Lock()
	sess.mu.Lock()
	if ticket.IssuedAtMS < sess.ticket.IssuedAtMS || ticket.NotAfterMS < sess.ticket.NotAfterMS {
		sess.mu.Unlock()
		s.routeMu.Unlock()
		s.cfg.Metrics.Control("stale_ticket_update")
		return
	}
	sess.ticket, sess.notAfter, sess.maxRoutes = ticket, ticket.NotAfter(), maxRoutes
	sess.data.SetRate(bytesPerSecond, bytesPerSecond)
	routes := maps.Clone(sess.routes)
	sess.mu.Unlock()
	out = s.pruneRoutesLocked(sess, routes, out)
	s.routeMu.Unlock()
	s.flush(out)
	s.sendControl(sess, mtrp.ControlMessage{Type: mtrp.ControlTicketAck, NotAfterMS: uint64(ticket.NotAfterMS)}) //nolint:gosec // validated positive by Verify
}

// pruneRoutesLocked closes, as revoked, the routes of sess (a snapshot of its
// route table) whose peer no longer shares a live zone with it, and appends
// the notifications to out. Called with routeMu held.
func (s *Server) pruneRoutesLocked(sess *session, routes map[uint32]route, out []outbound) []outbound {
	for n, r := range routes {
		if sharesZone(sess, r.peer, s.cfg.Revocations) {
			continue
		}
		if removed, ok := s.removeRouteLocked(sess, n); ok {
			out = append(out,
				outbound{removed.peer, mtrp.ControlMessage{Type: mtrp.ControlRouteClose, Route: removed.peerRoute, RouteClose: mtrp.RouteCloseRevoked}},
				outbound{sess, mtrp.ControlMessage{Type: mtrp.ControlRouteClose, Route: n, RouteClose: mtrp.RouteCloseRevoked}},
			)
		}
	}
	return out
}
