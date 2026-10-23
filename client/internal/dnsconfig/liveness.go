package dnsconfig

import (
	"net/netip"
	"slices"
)

// ResolverLiveness tells a zone which of its resolver Devices stopped
// answering the node's pings (DNS design D1b §5.6), and learns which are in
// use, so the node pings only those.
type ResolverLiveness interface {
	// Stopped reports a resolver Device that answered the node's pings
	// before and no longer does. One that never answered is never
	// reported: an idle peer is not a dead one.
	Stopped(netip.Addr) bool
	// Asked notes that a question is about to go to the resolver at the
	// address. It must return immediately.
	Asked(netip.Addr)
}

// setLiveness replaces the liveness the zones' resolvers are ordered by;
// nil orders none.
func (e *resolverEngine) setLiveness(liveness ResolverLiveness) {
	if liveness == nil {
		e.liveness.Store(nil)
		return
	}
	e.liveness.Store(&liveness)
}

// byLiveness returns targets with the zone's own resolvers the liveness
// reports stopped moved to the end, in their order: the others answer first,
// and a stopped one is still asked when none of them answers within the
// zone's time, so a wrong report costs time, or rarely, when the resolvers
// before it use up the zone's time, its answer. It notes every own resolver
// as asked.
func (e *resolverEngine) byLiveness(targets, own []netip.AddrPort) []netip.AddrPort {
	pointer := e.liveness.Load()
	if pointer == nil || len(targets) == 0 {
		return targets
	}
	liveness := *pointer
	alive := make([]netip.AddrPort, 0, len(targets))
	var stopped []netip.AddrPort
	for _, target := range targets {
		if !slices.Contains(own, target) {
			alive = append(alive, target)
			continue
		}
		liveness.Asked(target.Addr())
		if liveness.Stopped(target.Addr()) {
			stopped = append(stopped, target)
		} else {
			alive = append(alive, target)
		}
	}
	return append(alive, stopped...)
}

// SetResolverLiveness orders the zones' resolvers by liveness; nil orders
// none.
func (s *Server) SetResolverLiveness(liveness ResolverLiveness) {
	if s != nil {
		s.engine.setLiveness(liveness)
	}
}

// SetResolverLiveness orders the zones' resolvers by liveness; nil orders
// none.
func (r *PacketResolver) SetResolverLiveness(liveness ResolverLiveness) {
	if r != nil {
		r.engine.setLiveness(liveness)
	}
}

// SetResolverLiveness passes liveness to the manager's resolver, when it
// orders resolvers by it.
func (m *Manager) SetResolverLiveness(liveness ResolverLiveness) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if resolver, ok := m.resolver.(interface{ SetResolverLiveness(ResolverLiveness) }); ok {
		resolver.SetResolverLiveness(liveness)
	}
}
