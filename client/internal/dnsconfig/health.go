package dnsconfig

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/overlayframe"
)

// Resolver health (DNS design D1b §9): how the node's resolver sees each
// resolver of the zones it applies, reported to Core.

// maxHealthEntries bounds the resolvers remembered; past it the oldest
// are forgotten first.
const maxHealthEntries = 1024

// resolverOutcome is what the node last saw of one resolver.
type resolverOutcome struct {
	lastOK   time.Time // its last answer of any kind but SERVFAIL or REFUSED
	refusing bool      // its last answer was SERVFAIL or REFUSED
	touched  time.Time
}

// resolverHealthTracker is safe for concurrent use; its zero value is not:
// use newResolverHealthTracker.
type resolverHealthTracker struct {
	mu       sync.Mutex
	now      func() time.Time
	outcomes map[netip.AddrPort]*resolverOutcome
}

func newResolverHealthTracker(now func() time.Time) *resolverHealthTracker {
	return &resolverHealthTracker{now: now, outcomes: make(map[netip.AddrPort]*resolverOutcome)}
}

// answered notes an answer from resolver; refused is SERVFAIL or REFUSED.
func (t *resolverHealthTracker) answered(resolver netip.AddrPort, refused bool) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	outcome, found := t.outcomes[resolver]
	if !found {
		if len(t.outcomes) >= maxHealthEntries {
			t.forgetOldestLocked()
		}
		outcome = &resolverOutcome{}
		t.outcomes[resolver] = outcome
	}
	outcome.refusing, outcome.touched = refused, now
	if !refused {
		outcome.lastOK = now
	}
}

// retain forgets every resolver but those of zones: a resolver that leaves
// the plan and comes back later is idle again until asked (mtcp-v1 §8.6).
func (t *resolverHealthTracker) retain(zones map[netip.AddrPort]struct{}) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for resolver := range t.outcomes {
		if _, kept := zones[resolver]; !kept {
			delete(t.outcomes, resolver)
		}
	}
}

func (t *resolverHealthTracker) forgetOldestLocked() {
	var oldest netip.AddrPort
	var oldestAt time.Time
	for resolver, outcome := range t.outcomes {
		if oldestAt.IsZero() || outcome.touched.Before(oldestAt) {
			oldest, oldestAt = resolver, outcome.touched
		}
	}
	delete(t.outcomes, oldest)
}

func (t *resolverHealthTracker) outcome(resolver netip.AddrPort) (resolverOutcome, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	outcome, found := t.outcomes[resolver]
	if !found {
		return resolverOutcome{}, false
	}
	return *outcome, true
}

// zoneResolvers lists the resolvers of plan's zones, the root zone's first
// then each route's in order; repeats stay.
func zoneResolvers(plan Plan) []netip.AddrPort {
	var resolvers []netip.AddrPort
	if plan.Root != nil {
		resolvers = append(resolvers, plan.Root.Resolvers...)
	}
	for _, route := range plan.Routes {
		resolvers = append(resolvers, route.Resolvers...)
	}
	return resolvers
}

// adoptHealth keeps what the resolver saw of the resolvers plan still has
// and forgets the others.
func (e *resolverEngine) adoptHealth(plan Plan) {
	resolvers := zoneResolvers(plan)
	zones := make(map[netip.AddrPort]struct{}, len(resolvers))
	for _, resolver := range resolvers {
		zones[resolver] = struct{}{}
	}
	e.health.retain(zones)
	e.relayHealth.retain(zones)
}

// resolverHealth returns how the resolver sees the resolvers of plan's
// zones, the root zone's first then each route's in order, each once, at
// most maximum: skipped by its breaker, a resolver Device that stopped
// answering, its last answer SERVFAIL or REFUSED, never asked, or fine.
func (e *resolverEngine) resolverHealth(plan Plan, maximum int) []controlplane.ResolverHealth {
	resolvers := zoneResolvers(plan)
	health := make([]controlplane.ResolverHealth, 0, min(len(resolvers), maximum))
	seen := make(map[netip.AddrPort]struct{}, len(resolvers))
	liveness := e.liveness.Load()
	// What is reported is the way the resolver is asked now: through the
	// exit node while one is in use (DNS design D1c §5).
	gate := e.zoneGate(nil, e.relayVia(plan))
	for _, resolver := range resolvers {
		if _, dup := seen[resolver]; dup || len(health) == maximum {
			continue
		}
		seen[resolver] = struct{}{}
		breaker, tracker := gate.path(resolver)
		outcome, asked := tracker.outcome(resolver)
		state := controlplane.ResolverOK
		address := resolver.Addr().Unmap()
		switch {
		case breaker.open(resolver):
			state = controlplane.ResolverBroken
		case liveness != nil && overlayframe.Contains(netip.PrefixFrom(address, address.BitLen())) &&
			(*liveness).Stopped(address):
			state = controlplane.ResolverStopped
		case !asked:
			state = controlplane.ResolverIdle
		case outcome.refusing:
			state = controlplane.ResolverRefusing
		}
		health = append(health, controlplane.ResolverHealth{Resolver: resolver, State: state, LastOK: outcome.lastOK})
	}
	return health
}

// answeredWith reports an error that is an answer: SERVFAIL or REFUSED.
func answeredWith(err error) bool {
	return errors.Is(err, errUpstreamServerFailure) || errors.Is(err, errUpstreamRefused)
}

// maximumReportedResolvers bounds a health report (mtcp-v1 §8.6).
const maximumReportedResolvers = 64

// ResolverHealth returns how the resolver sees the resolvers of the zones
// it applies (DNS design D1b §9).
func (s *Server) ResolverHealth() []controlplane.ResolverHealth {
	if s == nil {
		return nil
	}
	return s.engine.resolverHealth(*s.plan.Load(), maximumReportedResolvers)
}

// ResolverHealth returns how the resolver sees the resolvers of the zones
// it applies (DNS design D1b §9).
func (r *PacketResolver) ResolverHealth() []controlplane.ResolverHealth {
	if r == nil {
		return nil
	}
	plan := r.plan.Load()
	if plan == nil {
		return []controlplane.ResolverHealth{}
	}
	return r.engine.resolverHealth(*plan, maximumReportedResolvers)
}

// ResolverHealth returns the manager's resolver health, when its resolver
// measures it; false otherwise.
func (m *Manager) ResolverHealth() ([]controlplane.ResolverHealth, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.Lock()
	resolver := m.resolver
	m.mu.Unlock()
	measured, ok := resolver.(interface {
		ResolverHealth() []controlplane.ResolverHealth
	})
	if !ok {
		return nil, false
	}
	return slices.Clone(measured.ResolverHealth()), true
}
