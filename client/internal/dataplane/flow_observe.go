package dataplane

import (
	"net/netip"
	"time"

	"meshtransit.net/client/internal/flowcount"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/overlayframe"
	"meshtransit.net/client/internal/packetmeta"
	"meshtransit.net/shared/internet"
)

// SetFlowCounter starts counting the filter's decisions into counter for
// connection logs, or stops with nil. A packet already being processed may
// still land in the previous counter, so drain it once more after a swap.
func (f *policyFilter) SetFlowCounter(counter *flowcount.Counter) {
	if f != nil {
		f.counter.Store(counter)
	}
}

// SetFlowCounter starts counting the packet filter's decisions into counter
// for connection logs (flowlog-v1 §6), or stops with nil. Counting costs
// nothing while it is off.
func (e *WireGuardEngine) SetFlowCounter(counter *flowcount.Counter) {
	if e != nil {
		e.filter.SetFlowCounter(counter)
	}
}

// processAndObserveLocked decides a packet as ProcessPacket always does and
// labels the decision for the counter.
func (f *policyFilter) processAndObserveLocked(direction PacketDirection, header packetmeta.Header, packet []byte,
	now time.Time,
) (bool, flowcount.Observation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Each lookup is made once: the labels read the same state the decision
	// does, and nothing else changes it under the lock.
	decision := packetDecision{
		ownSource: containsAddress(f.self, header.Source), ownDestination: containsAddress(f.self, header.Destination),
	}
	decision.grant, decision.aliased = f.aliases[remoteOf(direction, header)]
	if decision.aliased {
		// The decision may rewrite an alias packet's addresses.
		_, err := packetmeta.CheckAliasPacket(packet)
		decision.malformed = err != nil
	} else {
		decision.openedBefore = f.openedHereLocked(direction, header, decision.own(direction))
	}
	decision.allowed = f.processPacketLocked(direction, header, packet, now)
	return decision.allowed, f.observationLocked(direction, header, decision, now)
}

// packetDecision is what labelling needs of one decision.
type packetDecision struct {
	allowed, openedBefore, malformed bool
	ownSource, ownDestination        bool
	aliased                          bool
	grant                            aliasPacketGrant
}

// own reports whether this node is the packet's end on its side: the
// sender of an outbound packet, the receiver of an inbound one.
func (decision packetDecision) own(direction PacketDirection) bool {
	if direction == PacketOutbound {
		return decision.ownSource
	}
	return decision.ownDestination
}

// openedHereLocked reports whether this node opened the flow of a packet
// between itself and a peer. A packet this node only forwards is never its
// own. TCP and ICMP echo follow the flow table, which only this node's SYNs
// and echo requests start. UDP has no handshake, so in order: a question to
// the exit node's DNS forwarder is the consumer's; a table entry local rules
// could not have admitted is this node's; failing that the side on a
// well-known port (below 1024) is the server; otherwise the remote opened
// it, as local rules admitting the remote suggests.
func (f *policyFilter) openedHereLocked(direction PacketDirection, header packetmeta.Header, own bool) bool {
	if !own {
		return false
	}
	key, stateful := outboundFlowKey(header)
	if !stateful {
		return false
	}
	local, remote := header.SourcePort, header.DestinationPort
	if direction == PacketInbound {
		key.source, key.destination = key.destination, key.source
		local, remote = remote, local
	}
	state, tracked := f.flows[key]
	if header.Protocol != packetmeta.ProtocolUDP {
		return tracked
	}
	switch {
	case f.exit.active && local == 53:
		return false
	case tracked && !state.admittedByLocalRules:
		return true
	case (local < 1024) != (remote < 1024):
		return remote < 1024
	default:
		return false
	}
}

// observationLocked labels a decision ProcessPacket made: the class and
// direction of the packet's flow and, when denied, why (flowlog-v1 §6). It
// never decides anything; a packet it cannot place is noise, not counted.
// decision.openedBefore is openedHereLocked before the decision, which may
// have started or ended the flow.
func (f *policyFilter) observationLocked(direction PacketDirection, header packetmeta.Header,
	decision packetDecision, now time.Time,
) flowcount.Observation {
	noise := flowcount.Observation{Deny: flowcount.DenyNoise}
	if f.suspended || !f.selfAuthority.usableAt(now) {
		return noise
	}
	// ICMP errors, neighbour discovery and other non-echo ICMP belong to no
	// flow of their own.
	if isICMP(header.Protocol) && !isICMPEchoRequest(header) && !isICMPEchoReply(header) {
		return noise
	}
	allowed := decision.allowed
	if decision.aliased {
		return f.aliasObservationLocked(direction, header, decision.grant, allowed, decision.malformed, now)
	}
	own := decision.own(direction)
	opened := own && (decision.openedBefore || f.openedHereLocked(direction, header, own))
	switch {
	case own && direction == PacketOutbound:
		return f.sentObservationLocked(header, allowed, opened, now)
	case own:
		return f.receivedObservationLocked(header, allowed, opened, now)
	case direction == PacketInbound:
		return f.forwardedObservationLocked(header, allowed, now)
	default:
		return f.forwardedReplyObservationLocked(header, allowed)
	}
}

// aliasObservationLocked labels a share's packet. Each side names only the
// contract; the header keeps this node's canonical address and the peer's
// alias address.
func (f *policyFilter) aliasObservationLocked(direction PacketDirection, header packetmeta.Header,
	grant aliasPacketGrant, allowed, malformed bool, now time.Time,
) flowcount.Observation {
	spoofed := direction == PacketOutbound && header.Source != grant.canonical ||
		direction == PacketInbound && header.Destination != grant.local
	if direction == PacketInbound {
		header.Destination = grant.canonical
	}
	consumer := grant.binding.Role == networkmap.AliasConsumer
	observation := flowcount.Observation{
		Header: header, Class: flowcount.ClassShare, Direction: flowcount.DirectionInbound, Scope: grant.contract,
		// The consumer opens; the provider answers.
		Reply: (direction == PacketOutbound) != consumer,
	}
	if consumer {
		observation.Direction = flowcount.DirectionOutbound
	}
	if allowed {
		return observation
	}
	switch {
	case !now.Before(grant.binding.ExpiresAt):
		observation.Deny = flowcount.DenyShareExpired
	case !f.peerUsableAt(remoteOf(direction, header), now):
		observation.Deny = flowcount.DenyPeerUnusable
	case observation.Reply || spoofed || malformed || staleReply(header):
		// An answer to no flow, a late packet of an ended one, a forged
		// address or a malformed packet is not a decision worth a record.
		observation.Deny = flowcount.DenyNoise
	case !aliasServiceAllows(grant.binding.Services, header) || !consumer && !rulesAllow(f.rules, header):
		observation.Deny = flowcount.DenyShareService
	case len(f.flows) >= f.maximumFlows:
		// The service allows it: the flow table is full.
		observation.Deny = flowcount.DenyCapacity
	default:
		observation.Deny = flowcount.DenyNoise
	}
	return observation
}

// sentObservationLocked labels a packet this node sends: to a peer, a Site
// or the exit node, by the authority the filter used (remoteAuthority).
func (f *policyFilter) sentObservationLocked(header packetmeta.Header, allowed, opened bool,
	now time.Time,
) flowcount.Observation {
	observation := flowcount.Observation{
		Header: header, Class: flowcount.ClassMesh, Direction: flowcount.DirectionOutbound,
	}
	if peer, known := f.peers[header.Destination]; known {
		observation.Peer = peer.flowID
		switch {
		case !allowed && !peer.usableAt(now):
			observation.Deny = flowcount.DenyPeerUnusable
		case !allowed:
			observation.Deny = flowcount.DenyNoise
		case !opened:
			// This node answers a flow the peer opened.
			observation.Direction, observation.Reply = flowcount.DirectionInbound, true
		}
		return observation
	}
	prefix, site, routed := f.routed.lookup(header.Destination)
	_, installed := f.routedInstalled[prefix]
	exit := f.routedExitLocked()
	internetBound := exit != nil && internet.Contains(header.Destination)
	switch {
	case routed && (installed || !internetBound):
		// An installed Site prefix, or a Site that cannot be reached.
		observation.Class, observation.Scope = flowcount.ClassSite, site.id
	case internetBound:
		observation.Class, observation.Scope = flowcount.ClassExit, exit.poolID
	case !allowed && inOverlay(header.Destination):
		// A mesh address the map does not give this node: no rule reaches it.
		observation.Deny = flowcount.DenyNotInMap
		return observation
	default:
		return flowcount.Observation{Deny: flowcount.DenyNoise}
	}
	if !allowed {
		observation.Deny = flowcount.DenyRouteNotInstalled
	}
	return observation
}

// receivedObservationLocked labels a packet to this node: from a peer, or
// an answer from a Site or the Internet through the exit node.
func (f *policyFilter) receivedObservationLocked(header packetmeta.Header, allowed, opened bool,
	now time.Time,
) flowcount.Observation {
	observation := flowcount.Observation{
		Header: header, Class: flowcount.ClassMesh, Direction: flowcount.DirectionInbound,
	}
	if peer, known := f.peers[header.Source]; known {
		observation.Peer = peer.flowID
		switch {
		case !allowed && !peer.usableAt(now):
			observation.Deny = flowcount.DenyPeerUnusable
		case !allowed && (opened || staleReply(header)):
			// A late answer to a flow that ended is no one's decision.
			observation.Deny = flowcount.DenyNoise
		case !allowed:
			observation.Deny = flowcount.DenyPortNotAllowed
		case opened:
			observation.Direction, observation.Reply = flowcount.DirectionOutbound, true
		}
		return observation
	}
	if !allowed {
		// Routes grant reaching a Site, never being reached from it.
		return flowcount.Observation{Deny: flowcount.DenyNoise}
	}
	observation.Direction, observation.Reply = flowcount.DirectionOutbound, true
	if prefix, site, routed := f.routed.lookup(header.Source); routed {
		if _, installed := f.routedInstalled[prefix]; installed {
			observation.Class, observation.Scope = flowcount.ClassSite, site.id
			return observation
		}
	}
	if exit := f.routedExitLocked(); exit != nil {
		observation.Class, observation.Scope = flowcount.ClassExit, exit.poolID
		return observation
	}
	return flowcount.Observation{Deny: flowcount.DenyNoise}
}

// staleReply is a denied packet that can only answer something: TCP
// without a bare SYN, an ICMP echo reply.
func staleReply(header packetmeta.Header) bool {
	const (
		tcpSYN = 0x02
		tcpACK = 0x10
	)
	if header.Protocol == packetmeta.ProtocolTCP {
		return header.TCPFlags&(tcpSYN|tcpACK) != tcpSYN
	}
	return isICMPEchoReply(header)
}

// forwardedObservationLocked labels a peer's packet a router passes into a
// Site or an exit node to the Internet.
func (f *policyFilter) forwardedObservationLocked(header packetmeta.Header, allowed bool,
	now time.Time,
) flowcount.Observation {
	if _, own := f.served.local[header.Destination]; own {
		return flowcount.Observation{Deny: flowcount.DenyNoise}
	}
	peer, known := f.peers[header.Source]
	observation := flowcount.Observation{
		Header: header, Direction: flowcount.DirectionForwarded, Peer: peer.flowID,
	}
	exit := false
	if site, served := f.served.site(header.Destination); served {
		observation.Class, observation.Scope = flowcount.ClassSite, site
	} else if f.exit.active && f.internetLocked(header.Destination) {
		observation.Class, observation.Scope, exit = flowcount.ClassExit, f.exit.pool, true
	} else {
		return flowcount.Observation{Deny: flowcount.DenyNoise}
	}
	switch {
	case allowed:
	case !known || !peer.usableAt(now):
		observation.Deny = flowcount.DenyPeerUnusable
	case staleReply(header):
		observation.Deny = flowcount.DenyNoise
	case exit && rulesAllow(f.exit.rules, header):
		// The pool's rules allow it: the exit node's consumer limit refused it.
		observation.Deny = flowcount.DenyCapacity
	default:
		observation.Deny = flowcount.DenyPortNotAllowed
	}
	return observation
}

// forwardedReplyObservationLocked labels a Site's or the Internet's answer a
// router or exit node passes back to a peer.
func (f *policyFilter) forwardedReplyObservationLocked(header packetmeta.Header,
	allowed bool,
) flowcount.Observation {
	if !allowed {
		return flowcount.Observation{Deny: flowcount.DenyNoise}
	}
	observation := flowcount.Observation{
		Header: header, Direction: flowcount.DirectionForwarded, Reply: true,
		Peer: f.peers[header.Destination].flowID,
	}
	if site, served := f.served.site(header.Source); served {
		observation.Class, observation.Scope = flowcount.ClassSite, site
		return observation
	}
	observation.Class, observation.Scope = flowcount.ClassExit, f.exit.pool
	return observation
}

func (f *policyFilter) routedExitLocked() *routedExit {
	if f.routed == nil || !f.exitRouted {
		return nil
	}
	return f.routed.exit
}

func remoteOf(direction PacketDirection, header packetmeta.Header) netip.Addr {
	if direction == PacketOutbound {
		return header.Destination
	}
	return header.Source
}

// inOverlay reports a mesh or alias address: one only the map can make
// reachable.
func inOverlay(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsValid() && overlayframe.Contains(netip.PrefixFrom(address, address.BitLen()))
}
