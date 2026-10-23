package dnsconfig

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"meshtransit.net/shared/internet"
)

// Time budgets of a forward zone that fails open: its resolvers get part of
// the 5 seconds a stub resolver waits, the host's own resolvers (or the exit
// node's forwarder) the rest, so a dead zone still answers in time.
const (
	failOpenPrimaryBudget  = 3 * time.Second
	failOpenFallbackBudget = 2 * time.Second
)

// zoneQuery is one question for a name a forward zone's route covers.
type zoneQuery struct {
	plan      Plan
	route     Route
	query     []byte
	message   dnsmessage.Message
	question  dnsmessage.Question
	transport string
}

// resolveZone answers a name of a forward zone (a route with resolvers, or
// unavailable) from the zone's resolvers that the breaker does not skip,
// Internet ones through the exit node while one is in use.
// SERVFAIL or REFUSED from one moves on to the next; when none answers
// otherwise, the first such answer is the zone's. When none answers at all
// or none can be used, a zone that fails open asks the
// host's own resolvers (the exit node's forwarder while one is in use, never
// the host's network then); one that fails closed answers SERVFAIL (DNS
// design D1 §5.3).
func (e *resolverEngine) resolveZone(ctx context.Context, zone zoneQuery) ([]byte, error) {
	targets, captiveWindow, noData := e.zoneTargets(zone.plan, zone.route, zone.question)
	if noData {
		return zone.noData()
	}
	select {
	case e.forwardSlots <- struct{}{}:
		defer func() { <-e.forwardSlots }()
	default:
		return e.zoneFailure(zone, errForwardBusy)
	}
	budget := queryTimeout
	if zone.route.FailOpen {
		budget = failOpenPrimaryBudget
	}
	err := errNoResolver
	if len(targets) != 0 {
		forwardCtx, cancel := context.WithTimeout(ctx, budget)
		var response []byte
		via := netip.AddrPort{}
		if !captiveWindow {
			// In a captive portal window the network's resolvers are asked
			// directly.
			via = e.relayVia(zone.plan)
		}
		response, err = forwardVia(forwardCtx, zone.query, zone.question,
			e.byLiveness(targets, zone.route.Resolvers), zone.transport, e.zoneGate(zone.route.Resolvers, via), via)
		cancel()
		if err == nil {
			return e.zoneAnswer(zone, response, captiveWindow)
		}
		// Every resolver asked, one at least answered SERVFAIL or REFUSED:
		// that is the zone's answer (DNS design D1b §5.3). Failing open past
		// it would send a name a filter blocks, or DNSSEC failed, to the
		// network.
		if answered, ok := upstreamAnswer(err); ok {
			if e.failuresAsNXDOMAIN {
				return e.zoneFailure(zone, err)
			}
			return zone.answer(answered, captiveWindow)
		}
		// An exit node that does not relay answered from its own upstreams:
		// a zone that fails open takes it, one that fails closed does not
		// (DNS design D1c Q3).
		if old, ok := oldExitAnswer(err); ok && zone.route.FailOpen {
			return e.zoneAnswer(zone, old, captiveWindow)
		}
	}
	if !zone.route.FailOpen || ctx.Err() != nil {
		return e.zoneFailure(zone, err)
	}
	// A route without resolvers (a name of a zone that leaves the rest to
	// the host) asks the host first, with the whole budget.
	fallbackBudget := failOpenFallbackBudget
	if len(targets) == 0 {
		fallbackBudget = queryTimeout
	}
	fallbackCtx, cancel := context.WithTimeout(ctx, fallbackBudget)
	defer cancel()
	fallback, captiveFallback, noData := e.failOpenTargets(zone.plan, zone.question)
	if noData {
		return zone.noData()
	}
	// Resolvers that just failed (the network's in a captive portal window)
	// are not asked twice.
	fallback = slices.DeleteFunc(fallback, func(resolver netip.AddrPort) bool {
		return slices.Contains(targets, resolver)
	})
	if len(fallback) == 0 {
		return e.zoneFailure(zone, errors.Join(err, errNoResolver))
	}
	response, fallbackErr := forwardQuery(fallbackCtx, zone.query, zone.question, fallback, zone.transport, nil)
	if fallbackErr != nil {
		return e.zoneFailure(zone, errors.Join(err, fallbackErr))
	}
	return e.zoneAnswer(zone, response, captiveFallback)
}

// zoneTargets are the resolvers a zone's question goes to first, in the
// zone's order. Without an exit node they are the zone's own. While one is
// in use, resolvers in the mesh or a private network are asked directly and
// Internet resolvers through the exit node's forwarder (DNS design D1c §5),
// so no question leaves through the host's own network; an IPv6 one is
// left out when the exit node carries no IPv6. A zone with Internet
// resolvers only is asked like any name the exit node answers: the
// network's resolvers in a captive portal window, no data for AAAA when the
// exit node carries no IPv6.
func (e *resolverEngine) zoneTargets(plan Plan, route Route, question dnsmessage.Question) (
	targets []netip.AddrPort, captiveWindow, noData bool,
) {
	exit := plan.Exit
	if e.exitPending(plan) {
		// Only the zone's resolvers in the mesh or a private network.
		return slices.DeleteFunc(slices.Clone(route.Resolvers), func(resolver netip.AddrPort) bool {
			return internet.Contains(resolver.Addr().Unmap())
		}), false, false
	}
	if exit == nil || len(route.Resolvers) == 0 {
		return slices.Clone(route.Resolvers), false, false
	}
	internetOnly := !slices.ContainsFunc(route.Resolvers, func(resolver netip.AddrPort) bool {
		return !internet.Contains(resolver.Addr().Unmap())
	})
	if internetOnly {
		// A captive portal window lends the network's resolvers to a zone
		// that fails open only: a closed zone's names never reach the
		// network.
		if network := e.captiveResolvers(); len(network) != 0 {
			if !route.FailOpen {
				return nil, false, false
			}
			return network, true, false
		}
		if question.Type == dnsmessage.TypeAAAA && !exit.IPv6 {
			return nil, false, true
		}
	}
	via := e.relayVia(plan)
	for _, resolver := range route.Resolvers {
		address := resolver.Addr().Unmap()
		if internet.Contains(address) && (!via.IsValid() || (address.Is6() && !exit.IPv6)) {
			continue
		}
		targets = append(targets, resolver)
	}
	return targets, false, false
}

// failOpenTargets are the resolvers a zone that fails open falls back to:
// the exit node's forwarder while one is in use (the network's resolvers in
// a captive portal window), otherwise the host's network resolvers, asked
// from the client's own sockets.
func (e *resolverEngine) failOpenTargets(plan Plan, question dnsmessage.Question) (
	targets []netip.AddrPort, captiveWindow, noData bool,
) {
	exit := plan.Exit
	pending := e.exitPending(plan)
	if exit == nil && !pending {
		return e.networkTargets(), false, false
	}
	// A captive portal window wins: the portal's names must resolve to
	// sign in, also while the exit node is chosen but not yet in the plan.
	if network := e.captiveResolvers(); len(network) != 0 {
		return network, true, false
	}
	if pending {
		return nil, false, false
	}
	if question.Type == dnsmessage.TypeAAAA && !exit.IPv6 {
		return nil, false, true
	}
	return slices.Clone(exit.Resolvers), false, false
}

func (zone zoneQuery) answer(response []byte, captiveWindow bool) ([]byte, error) {
	var err error
	if response, err = sanitizeAnswer(zone.plan, zone.question, response); err != nil {
		return zone.failure(err)
	}
	if captiveWindow {
		if response, err = capTTLs(response, uint32(positiveTTL/time.Second)); err != nil {
			return zone.failure(err)
		}
	}
	return limitUDPResponse(zone.query, response, zone.transport)
}

func (zone zoneQuery) noData() ([]byte, error) {
	response, err := noDataResponse(zone.message, zone.question, zone.plan)
	if err != nil {
		return nil, err
	}
	return limitUDPResponse(zone.query, response, zone.transport)
}

func (zone zoneQuery) failure(cause error) ([]byte, error) {
	return failureResponse(zone.query, zone.message, zone.question, zone.plan, zone.transport, cause)
}

// zoneGate puts the breaker in front of the zone's own resolvers only: the
// exit node's forwarder and the network's resolvers are always asked. A
// resolver asked through the exit node (via) has a breaker and health of
// its own, apart from the same resolver asked directly (DNS design D1c §5).
type zoneGate struct {
	engine *resolverEngine
	own    []netip.AddrPort
	via    netip.AddrPort
}

// zoneGate is the gate of a zone whose resolvers are own.
func (e *resolverEngine) zoneGate(own []netip.AddrPort, via netip.AddrPort) zoneGate {
	return zoneGate{engine: e, own: own, via: via}
}

func (gate zoneGate) path(resolver netip.AddrPort) (*resolverBreaker, *resolverHealthTracker) {
	if relayed(resolver, gate.via) {
		return gate.engine.relayBreaker, gate.engine.relayHealth
	}
	return gate.engine.breaker, gate.engine.health
}

func (gate zoneGate) allow(resolver netip.AddrPort) bool {
	if !slices.Contains(gate.own, resolver) {
		return true
	}
	breaker, _ := gate.path(resolver)
	return breaker.allow(resolver)
}

// record ends one trial of resolver: an answer (SERVFAIL and REFUSED
// included) closes its breaker, a failure counts against it.
func (gate zoneGate) record(resolver netip.AddrPort, err error) {
	if !slices.Contains(gate.own, resolver) {
		return
	}
	breaker, health := gate.path(resolver)
	if err == nil || answeredWith(err) {
		breaker.record(resolver, nil)
		health.answered(resolver, err != nil)
		return
	}
	breaker.record(resolver, err)
}

func (gate zoneGate) release(resolver netip.AddrPort) {
	if slices.Contains(gate.own, resolver) {
		breaker, _ := gate.path(resolver)
		breaker.release(resolver)
	}
}

// networkResolverTTL bounds how long the host's network resolvers, looked
// up for zones that fail open, are reused: looking them up can run a
// command (scutil on macOS), never on every question.
const networkResolverTTL = 10 * time.Second

// networkResolverCache keeps the last lookup of the host's network
// resolvers, an empty one included. Its zero value is ready.
type networkResolverCache struct {
	mu         sync.Mutex
	at         time.Time
	generation uint64
	cached     []netip.AddrPort
}

// resolvers returns lookup's resolvers, looked up again once they are
// networkResolverTTL old or generation differs from theirs.
func (cache *networkResolverCache) resolvers(lookup func() []netip.AddrPort, generation uint64) []netip.AddrPort {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.at.IsZero() || time.Since(cache.at) >= networkResolverTTL || cache.generation != generation {
		cache.cached, cache.at, cache.generation = lookup(), time.Now(), generation
	}
	return slices.Clone(cache.cached)
}
