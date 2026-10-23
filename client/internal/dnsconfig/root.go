package dnsconfig

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/net/dns/dnsmessage"

	"meshtransit.net/client/internal/overlayframe"
)

// The root zone (DNS design D1b §5): every name no route holds goes to its
// resolvers, as a zone; the names below are the exceptions.

// ownNames are the names the node answers itself while it has a root zone
// (DNS design D1b §5.5), so applications do not leave the root zone's
// resolvers for one of their own: Firefox's canary for DNS over HTTPS and
// iCloud Private Relay; discoveryZone holds DNS resolver discovery's names
// (RFC 9462: SVCB for _dns.resolver.arpa), all without data: no designated
// resolver.
var ownNames = map[string]dnsmessage.RCode{
	"use-application-dns.net": dnsmessage.RCodeNameError,
	"mask.icloud.com":         dnsmessage.RCodeNameError,
	"mask-h2.icloud.com":      dnsmessage.RCodeNameError,
}

const discoveryZone = "resolver.arpa"

// privateReverse are the address ranges whose reverse names never go to the
// root zone's resolvers or an exit node (RFC 6303, DNS design D1b §5.7): the
// node's LAN, link-local and loopback addresses are no business of theirs.
var privateReverse = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// ownNameAnswer answers a name the node answers itself while it has a root
// zone; false for any other name or without a root zone.
func ownNameAnswer(plan Plan, message dnsmessage.Message, question dnsmessage.Question, name string) (
	[]byte, bool, error,
) {
	if plan.Root == nil {
		return nil, false, nil
	}
	rcode, own := ownNames[name]
	if dnsSuffixContains(discoveryZone, name) {
		rcode, own = dnsmessage.RCodeSuccess, true
	}
	if !own {
		return nil, false, nil
	}
	response, err := negativeResponse(message, question, rcode, ".", plan)
	return response, true, err
}

// resolveUnrouted answers a name no route holds while the host sends the
// resolver every name: the reverse names of private and mesh addresses
// first (with a root zone or an exit node), then the names of MeshTransit's
// own infrastructure, then the root zone; ok is false when the plan has no
// root zone and the name is not a reverse name it answers.
func (e *resolverEngine) resolveUnrouted(ctx context.Context, zone zoneQuery, name string) ([]byte, bool, error) {
	// Only a root zone or an exit node would send these reverse names out of
	// the network: with only the Network's own resolvers they keep going
	// there, as an office DNS may hold the LAN's reverse zone.
	keepsReverse := zone.plan.Root != nil || zone.plan.Exit != nil || e.exitPending(zone.plan)
	if zone.question.Type == dnsmessage.TypePTR && keepsReverse {
		if response, handled, err := e.privateReverseAnswer(ctx, zone, name); handled {
			return response, true, err
		}
	}
	root := zone.plan.Root
	if root == nil {
		return nil, false, nil
	}
	if e.infrastructureName(name) {
		response, err := e.resolveOutsideRoot(ctx, zone)
		return response, true, err
	}
	zone.route = *root
	exit := zone.plan.Exit
	if (exit != nil || e.exitPending(zone.plan)) && len(e.captiveResolvers()) != 0 {
		// A captive portal window wins over a root zone that fails closed:
		// the portal's names must resolve to sign in (DNS design D1b Q6).
		zone.route.FailOpen = true
	} else if exit != nil && zone.question.Type == dnsmessage.TypeAAAA && !exit.IPv6 {
		// Without IPv6 at the exit node, AAAA has no data at once, as for
		// any name the exit node answers.
		response, err := zone.noData()
		return response, true, err
	}
	response, err := e.resolveZone(ctx, zone)
	return response, true, err
}

// privateReverseAnswer answers the reverse name of a mesh or private
// address the plan holds no name for: NXDOMAIN for a mesh address; for a
// private one the network's resolvers while no exit node is in use, and
// NXDOMAIN while one is, whose forwarder knows nothing of this LAN.
func (e *resolverEngine) privateReverseAnswer(ctx context.Context, zone zoneQuery, name string) (
	[]byte, bool, error,
) {
	address, ok := parseReverseName(name)
	if !ok {
		return nil, false, nil
	}
	address = address.Unmap()
	mesh := overlayframe.Contains(netip.PrefixFrom(address, address.BitLen()))
	private := slices.ContainsFunc(privateReverse, func(prefix netip.Prefix) bool { return prefix.Contains(address) })
	switch {
	case !mesh && !private:
		return nil, false, nil
	case mesh || zone.plan.Exit != nil || e.exitPending(zone.plan):
		response, err := negativeResponse(zone.message, zone.question, dnsmessage.RCodeNameError, ".", zone.plan)
		if err != nil {
			return nil, true, err
		}
		response, err = limitUDPResponse(zone.query, response, zone.transport)
		return response, true, err
	default:
		response, err := e.forwardOutside(ctx, zone, e.networkTargets(), false)
		return response, true, err
	}
}

// resolveOutsideRoot answers a name of MeshTransit's own infrastructure
// beside the root zone: from the network's resolvers, or the exit node's
// forwarder while one is in use, never from a resolver a filter may block it
// on (DNS design D1b §5.8).
func (e *resolverEngine) resolveOutsideRoot(ctx context.Context, zone zoneQuery) ([]byte, error) {
	targets, captiveWindow, noData := e.failOpenTargets(zone.plan, zone.question)
	if noData {
		return zone.noData()
	}
	return e.forwardOutside(ctx, zone, targets, captiveWindow)
}

// forwardOutside asks targets in order, outside any zone's breaker.
func (e *resolverEngine) forwardOutside(ctx context.Context, zone zoneQuery, targets []netip.AddrPort,
	captiveWindow bool,
) ([]byte, error) {
	if len(targets) == 0 {
		return zone.failure(errNoResolver)
	}
	select {
	case e.forwardSlots <- struct{}{}:
		defer func() { <-e.forwardSlots }()
	default:
		return zone.failure(errForwardBusy)
	}
	forwardCtx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	response, err := forwardQuery(forwardCtx, zone.query, zone.question, targets, zone.transport, nil)
	if err != nil {
		if answered, ok := upstreamAnswer(err); ok {
			return zone.answer(answered, captiveWindow)
		}
		return zone.failure(err)
	}
	return zone.answer(response, captiveWindow)
}

// infrastructureName reports a name of MeshTransit's own infrastructure:
// matched exactly, never by suffix.
func (e *resolverEngine) infrastructureName(name string) bool {
	names := e.infrastructure.Load()
	if names == nil {
		return false
	}
	_, found := (*names)[name]
	return found
}

// setInfrastructureNames replaces the names of MeshTransit's own
// infrastructure (Core, relays) the root zone never answers.
func (e *resolverEngine) setInfrastructureNames(names []string) {
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		if canonical := strings.ToLower(strings.TrimSuffix(name, ".")); canonical != "" {
			set[canonical] = struct{}{}
		}
	}
	e.infrastructure.Store(&set)
}

// SetInfrastructureNames names MeshTransit's own infrastructure (Core,
// relays) for the root zone to leave to the network's resolvers.
func (s *Server) SetInfrastructureNames(names []string) {
	if s != nil {
		s.engine.setInfrastructureNames(names)
	}
}

// SetInfrastructureNames names MeshTransit's own infrastructure (Core,
// relays) for the root zone to leave to the network's resolvers.
func (r *PacketResolver) SetInfrastructureNames(names []string) {
	if r != nil {
		r.engine.setInfrastructureNames(names)
	}
}

// SetInfrastructureNames passes names to the manager's resolver, when it
// takes them.
func (m *Manager) SetInfrastructureNames(names []string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if resolver, ok := m.resolver.(interface{ SetInfrastructureNames([]string) }); ok {
		resolver.SetInfrastructureNames(names)
	}
}
