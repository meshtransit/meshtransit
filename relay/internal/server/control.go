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
	// victim's allowance. ZONES frames have their own allowance: a node
	// sends a whole zone list at once.
	now := s.cfg.Now()
	if len(plain) > 0 && mtrp.ControlType(plain[0]) == mtrp.ControlZones {
		if !sess.allowZoneFrame(now) {
			s.cfg.Metrics.Control("zones_rate_limited")
			return
		}
	} else if !sess.allowControl(now) {
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
	case mtrp.ControlZones:
		s.addZones(sess, msg)
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
	// The zone search may compare thousands of zones; it runs before routeMu,
	// which then only confirms the zone in O(log n).
	s.mu.RLock()
	peer := s.byNode[msg.Peer]
	s.mu.RUnlock()
	if peer == nil {
		refuse(mtrp.RouteErrorPeerAbsent)
		return
	}
	zone, shared := sharedZone(src, peer, s.cfg.Revocations)
	if !shared {
		refuse(mtrp.RouteErrorPeerAbsent)
		return
	}
	s.routeMu.Lock()
	out, code := s.openRouteLocked(src, msg, peer, zone)
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
func (s *Server) openRouteLocked(src *session, msg mtrp.ControlMessage, peer *session, zone mtrp.Zone) ([]outbound, mtrp.RouteErrorCode) {
	s.mu.RLock()
	current := s.byNode[msg.Peer]
	s.mu.RUnlock()
	// Tickets in force now (they change only under routeMu) must still
	// share the zone found before it was taken.
	if current != peer || !bothHold(src, peer, zone, s.cfg.Revocations) {
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
	src.routes[srcRoute] = route{peer: peer, peerRoute: peerRoute, zone: zone}
	src.byPeer[peer.node] = srcRoute
	src.mu.Unlock()
	peer.mu.Lock()
	peer.routes[peerRoute] = route{peer: src, peerRoute: srcRoute, zone: zone}
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
// be for the same keys and not older than the current one. An MTT2 ticket
// whose zones are not all inline waits for them (§5.4) while the current
// ticket stays in force. A repeat of the current or pending ticket is
// ignored before its signature is checked.
func (s *Server) updateTicket(sess *session, raw []byte) {
	if peek, err := mtrp.ParseTicketUnverified(raw); err == nil && sess.holdsTicket(peek.ID) {
		s.cfg.Metrics.Control("repeated_ticket_update")
		return
	}
	ticket, err := s.verifier.Verify(raw)
	if err != nil || !key.Equal(ticket.Node, sess.node) || !key.Equal(ticket.Disco, sess.disco) {
		s.cfg.Metrics.Control("bad_ticket_update")
		return // the current ticket stays in force until it expires
	}
	ticket.Zones = append([]mtrp.Zone(nil), ticket.Zones...) // detach from the frame buffer
	if !ticket.ZonesComplete() && s.stageZones(sess, ticket) {
		return
	}
	s.applyTicket(sess, ticket, 0)
}

// applyTicket puts ticket in force unless the session holds a newer one.
// charge is what was reserved for it beyond the session's current charge
// (see stageZones); the session ends up charged exactly the zones it holds.
// The ticket changes under routeMu, so a route opened concurrently was
// checked against one ticket or the other, and the prune that follows sees
// every route opened against the old one.
func (s *Server) applyTicket(sess *session, ticket mtrp.Ticket, charge int) {
	maxRoutes, bytesPerSecond := s.ticketLimits(ticket)
	held := 0
	if ticket.IsV2() && ticket.ZonesComplete() && ticket.ZoneTotal > mtrp.MaxZones {
		held = ticket.ZoneTotal
	}
	s.routeMu.Lock()
	sess.mu.Lock()
	if sess.closed || ticket.IssuedAtMS < sess.ticket.IssuedAtMS || ticket.NotAfterMS < sess.ticket.NotAfterMS {
		sess.mu.Unlock()
		s.routeMu.Unlock()
		s.releaseZones(charge)
		s.cfg.Metrics.Control("stale_ticket_update")
		if ticket.IsV2() {
			s.ackTicket(sess, ticket) // the node stops sending this ticket's zones
		}
		return
	}
	if deficit := held - sess.chargedCurrent - charge; deficit > 0 && !s.reserveZones(deficit) {
		// The session's charge shrank since the zones were staged and the
		// budget cannot cover the rest: keep the inline zones only.
		held, ticket.Zones = 0, ticket.Zones[:min(len(ticket.Zones), mtrp.MaxZones)]
		s.cfg.Metrics.Control("zones_refused")
	}
	s.releaseZones(sess.chargedCurrent + charge - held)
	if p := sess.pending; p != nil && p.Ticket().IssuedAtMS <= ticket.IssuedAtMS && p.Ticket().ID != ticket.ID {
		// A ticket at least as new supersedes the one being assembled.
		s.releaseZones(sess.chargedPending)
		sess.pending, sess.chargedPending = nil, 0
	}
	sess.ticket, sess.notAfter, sess.maxRoutes, sess.chargedCurrent = ticket, ticket.NotAfter(), maxRoutes, held
	sess.data.SetRate(bytesPerSecond, bytesPerSecond)
	sess.mu.Unlock()
	s.routeMu.Unlock()
	s.pruneRoutes(sess)
	s.ackTicket(sess, ticket)
}

// ackTicket sends TICKET_ACK for ticket.
func (s *Server) ackTicket(sess *session, ticket mtrp.Ticket) {
	s.sendControl(sess, mtrp.ControlMessage{Type: mtrp.ControlTicketAck, NotAfterMS: uint64(ticket.NotAfterMS)}) //nolint:gosec // validated positive by Verify
}

// pruneRoutes closes, as revoked, the routes of sess whose peer no longer
// shares a live zone with it. Each route is first checked against the zone
// that opened it (O(log n)); only routes that lost it search the tickets
// for another zone, outside routeMu, and routeMu then confirms the outcome
// with O(log n) checks so tickets with thousands of zones never stall route
// changes relay-wide.
func (s *Server) pruneRoutes(sess *session) {
	sess.mu.Lock()
	routes := maps.Clone(sess.routes)
	sess.mu.Unlock()
	type change struct {
		number   uint32
		route    route
		zone     mtrp.Zone
		replaced bool
	}
	var changes []change
	for n, r := range routes {
		if bothHold(sess, r.peer, r.zone, s.cfg.Revocations) {
			continue
		}
		zone, ok := sharedZone(sess, r.peer, s.cfg.Revocations)
		changes = append(changes, change{number: n, route: r, zone: zone, replaced: ok})
	}
	if len(changes) == 0 {
		return
	}
	var out []outbound
	s.routeMu.Lock()
	for _, c := range changes {
		switch {
		case bothHold(sess, c.route.peer, c.route.zone, s.cfg.Revocations):
		case c.replaced && bothHold(sess, c.route.peer, c.zone, s.cfg.Revocations):
			s.setRouteZoneLocked(sess, c.number, c.route, c.zone)
		case sess.routeTo(c.number) == c.route.peer:
			if removed, ok := s.removeRouteLocked(sess, c.number); ok {
				out = append(out,
					outbound{removed.peer, mtrp.ControlMessage{Type: mtrp.ControlRouteClose, Route: removed.peerRoute, RouteClose: mtrp.RouteCloseRevoked}},
					outbound{sess, mtrp.ControlMessage{Type: mtrp.ControlRouteClose, Route: c.number, RouteClose: mtrp.RouteCloseRevoked}},
				)
			}
		}
	}
	s.routeMu.Unlock()
	s.flush(out)
}

// setRouteZoneLocked records the zone a route now rests on, on both halves.
// Called with routeMu held.
func (s *Server) setRouteZoneLocked(sess *session, n uint32, r route, zone mtrp.Zone) {
	sess.mu.Lock()
	if current, ok := sess.routes[n]; ok && current.peer == r.peer {
		current.zone = zone
		sess.routes[n] = current
	}
	sess.mu.Unlock()
	r.peer.mu.Lock()
	if back, ok := r.peer.routes[r.peerRoute]; ok && back.peer == sess {
		back.zone = zone
		r.peer.routes[r.peerRoute] = back
	}
	r.peer.mu.Unlock()
}
