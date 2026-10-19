package dataplane

import (
	"net/netip"
	"time"

	"meshtransit.net/client/internal/packetmeta"
	"meshtransit.net/shared/routedigest"
)

// servedFilter is the router's part of the packet filter (design §8.1,
// layer 1): what it forwards into, its own addresses outside the mesh, and
// the route digest of what it serves.
type servedFilter struct {
	prefixes *prefixIndex[struct{}]
	// local are the router's own addresses outside the mesh: the mesh
	// reaches them only as the router's own services, which the Device's
	// policy governs, never through a served prefix.
	local   map[netip.Addr]struct{}
	digest  routedigest.Digest
	entries int
}

// SetServedInstalled records what the helper forwards into and the router's
// own addresses, and the route digest of entries.
func (f *policyFilter) SetServedInstalled(entries []routedigest.Entry, local []netip.Addr) {
	if f == nil {
		return
	}
	digest, count, err := routedigest.Compute(entries)
	if err != nil {
		// Entries come from a validated map; a digest that cannot be
		// computed reports nothing served rather than a wrong digest.
		entries, local = nil, nil
		digest, count, _ = routedigest.Compute(nil)
	}
	served := servedFilter{
		prefixes: newPrefixIndex[struct{}](len(entries)), local: map[netip.Addr]struct{}{},
		digest: digest, entries: count,
	}
	for _, entry := range entries {
		served.prefixes.add(entry.Prefix, struct{}{})
	}
	for _, address := range local {
		served.local[address.Unmap()] = struct{}{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.served = served
}

func (served servedFilter) contains(address netip.Addr) bool {
	_, _, found := served.prefixes.lookup(address)
	return found
}

// servedInboundLocked admits a packet from a peer into a served prefix as
// the routed rules allow; the kernel tracks the connection from there.
func (f *policyFilter) servedInboundLocked(header packetmeta.Header, now time.Time) bool {
	if _, own := f.served.local[header.Destination]; own || !f.served.contains(header.Destination) {
		return false
	}
	return f.peerUsableAt(header.Source, now) && rulesAllow(f.rules, header)
}

// servedOutboundLocked admits a Site's packet to a peer: the kernel lets
// only answers through (design §8.1, layer 2).
func (f *policyFilter) servedOutboundLocked(header packetmeta.Header, now time.Time) bool {
	return f.served.contains(header.Source) && f.peerUsableAt(header.Destination, now)
}

// isTrackedErrorLocked admits an ICMP error about a flow this node opened,
// such as "fragmentation needed": without it path MTU discovery fails. The
// error may come from the peer or from inside a routed Site.
func (f *policyFilter) isTrackedErrorLocked(header packetmeta.Header, packet []byte, now time.Time) bool {
	if header.Protocol != packetmeta.ProtocolICMPv4 && header.Protocol != packetmeta.ProtocolICMPv6 {
		return false
	}
	quoted, ok := packetmeta.ICMPErrorQuote(packet)
	if !ok || quoted.Source.Unmap() != header.Destination {
		return false
	}
	if !f.peerUsableAt(header.Source, now) && !f.routedUsableAt(header.Source, now) {
		return false
	}
	quoted.Source, quoted.Destination = quoted.Source.Unmap(), quoted.Destination.Unmap()
	key, stateful := outboundFlowKey(quoted)
	if !stateful {
		return false
	}
	state, tracked := f.flows[key]
	return tracked && state.expiresAt.After(now)
}
