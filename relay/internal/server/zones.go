package server

import (
	"time"

	"meshtransit.net/shared/mtrp"
)

// reackInterval bounds how often a TICKET_ACK is repeated for ZONES frames
// of a ticket already in force (the node missed the first one).
const reackInterval = time.Second

// stageZones starts assembling the zones of an MTT2 ticket that does not
// carry them all inline (mtrp-v1 §5.4). A renewal may reuse the zones the
// session already holds: only the growth is reserved, so a session at its
// share of a full budget can still renew. It reports false when the relay
// will not hold that many zones: the caller then puts the ticket in force
// with its inline zones only (the Network and the oldest Trust Contracts),
// and the acknowledgement tells the node to stop sending ZONES.
func (s *Server) stageZones(sess *session, ticket mtrp.Ticket) bool {
	if ticket.ZoneTotal > s.cfg.MaxSessionZones {
		s.cfg.Metrics.Control("zones_refused")
		return false
	}
	assembly, ok := mtrp.NewZoneAssembly(ticket)
	if !ok {
		return false
	}
	sess.mu.Lock()
	if sess.closed || ticket.IssuedAtMS < sess.ticket.IssuedAtMS || ticket.NotAfterMS < sess.ticket.NotAfterMS ||
		sess.pending != nil && ticket.IssuedAtMS < sess.pending.Ticket().IssuedAtMS {
		sess.mu.Unlock()
		s.cfg.Metrics.Control("stale_ticket_update")
		s.ackTicket(sess, ticket) // nothing to apply; the node stops sending its zones
		return true
	}
	charge := max(0, ticket.ZoneTotal-sess.chargedCurrent)
	if !s.reserveZones(charge) {
		sess.mu.Unlock()
		s.cfg.Metrics.Control("zones_refused")
		return false
	}
	s.releaseZones(sess.chargedPending)
	sess.pending, sess.chargedPending = assembly, charge
	sess.mu.Unlock()
	return true
}

// addZones records a ZONES frame; once the list is complete and matches the
// ticket's digest, the ticket comes into force and is acknowledged. Frames
// for the ticket already in force mean the node missed the acknowledgement,
// which is repeated (at most once a second).
func (s *Server) addZones(sess *session, msg mtrp.ControlMessage) {
	now := s.cfg.Now()
	sess.mu.Lock()
	assembly := sess.pending
	if assembly == nil || assembly.Ticket().ID != msg.TicketID {
		current := sess.ticket
		reack := current.ID == msg.TicketID && !now.Before(sess.reackAt)
		if reack {
			sess.reackAt = now.Add(reackInterval)
		}
		sess.mu.Unlock()
		if reack {
			s.ackTicket(sess, current)
			return
		}
		s.cfg.Metrics.Control("zones_unexpected")
		return
	}
	if !assembly.Add(msg) {
		sess.mu.Unlock()
		s.cfg.Metrics.Control("zones_invalid")
		return
	}
	if assembly.Missing() != 0 {
		sess.mu.Unlock()
		return
	}
	ticket, ok := assembly.Complete()
	if !ok {
		sess.mu.Unlock()
		s.cfg.Metrics.Control("zones_digest_mismatch")
		return
	}
	charge := sess.chargedPending
	sess.pending, sess.chargedPending = nil, 0
	sess.mu.Unlock()
	// The ticket was verified when it was staged; Core may have revoked it
	// or retired its key while its zones were in flight.
	if !now.Before(ticket.NotAfter()) || !s.stillTrusted(ticket) {
		s.releaseZones(charge)
		s.cfg.Metrics.Control("zones_ticket_ended")
		s.ackTicket(sess, ticket)
		return
	}
	s.cfg.Metrics.Control("zones_complete")
	s.applyTicket(sess, ticket, charge)
}

// stillTrusted reports whether a verified ticket's signing key is still
// trusted and nothing revoked it since.
func (s *Server) stillTrusted(ticket mtrp.Ticket) bool {
	public, ok := s.cfg.Keys.SigningKey(ticket.KeyID)
	return ok && public.ID() == ticket.KeyID && !mtrp.IsRevoked(ticket, s.cfg.Revocations)
}

// sweepPendingZones drops an assembly whose ticket expired or, after a
// revocation change, was revoked, so its zones return to the budget.
func (s *Server) sweepPendingZones(sess *session, now time.Time, checkRevocations bool) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.pending == nil {
		return
	}
	ticket := sess.pending.Ticket()
	if now.Before(ticket.NotAfter()) && (!checkRevocations || s.stillTrusted(ticket)) {
		return
	}
	s.releaseZones(sess.chargedPending)
	sess.pending, sess.chargedPending = nil, 0
}

// reserveZones charges n zones to the relay-wide budget.
func (s *Server) reserveZones(n int) bool {
	for {
		held := s.zonesHeld.Load()
		if held+int64(n) > int64(s.cfg.ZoneBudget) {
			return false
		}
		if s.zonesHeld.CompareAndSwap(held, held+int64(n)) {
			return true
		}
	}
}

func (s *Server) releaseZones(n int) {
	if n > 0 {
		s.zonesHeld.Add(-int64(n))
	}
}

// allowZoneFrame charges one ZONES frame.
func (s *session) allowZoneFrame(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.zoneFrames.Allow(now, 1)
}
