package dataplane

import (
	"maps"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/packetmeta"
)

type aliasPacketGrant struct {
	peerID    uint64
	canonical netip.Addr
	local     netip.Addr
	binding   networkmap.AliasBinding
}

func snapshotHasAliases(snapshot networkmap.Snapshot) bool {
	if snapshot.Self.Alias != nil {
		return true
	}
	return slices.ContainsFunc(snapshot.Peers, func(peer networkmap.Node) bool { return peer.Alias != nil })
}

func aliasPacketGrants(snapshot networkmap.Snapshot) map[netip.Addr]aliasPacketGrant {
	grants := make(map[netip.Addr]aliasPacketGrant)
	for _, peer := range snapshot.Peers {
		if peer.Alias == nil {
			continue
		}
		binding := *peer.Alias
		binding.Services = slices.Clone(binding.Services)
		for _, prefix := range peer.Addresses {
			address := prefix.Addr()
			local := binding.SelfIPv6
			if address.Is4() {
				local = binding.SelfIPv4
			}
			for _, self := range snapshot.Self.Addresses {
				if self.Addr().Is4() == address.Is4() {
					grants[address] = aliasPacketGrant{peerID: peer.ID, canonical: self.Addr(), local: local, binding: binding}
				}
			}
		}
	}
	return grants
}

func equalAliasPacketGrants(first, second map[netip.Addr]aliasPacketGrant) bool {
	return maps.EqualFunc(first, second, func(left, right aliasPacketGrant) bool {
		return left.peerID == right.peerID && left.canonical == right.canonical && left.local == right.local &&
			networkmap.EqualAlias(&left.binding, &right.binding)
	})
}

// ProcessPacket filters and translates under the same authority lock. WireGuard
// has already authenticated ingress source ownership before this TUN boundary.
// Denial never changes packet bytes; ordinary peers retain existing behavior.
func (f *policyFilter) ProcessPacket(direction PacketDirection, packet []byte) bool {
	if f == nil || f.clock == nil {
		return false
	}
	header, err := packetmeta.Parse(packet)
	if err != nil {
		return false
	}
	now := f.clock().UTC()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.suspended || !f.selfAuthority.usableAt(now) {
		return false
	}
	address := header.Source
	if direction == PacketOutbound {
		address = header.Destination
	}
	grant, aliased := f.aliases[address]
	if !aliased {
		return f.allowOrdinaryLocked(direction, header, now)
	}
	if !f.peerUsableAt(address, now) || !now.Before(grant.binding.ExpiresAt) {
		return false
	}
	if _, err := packetmeta.CheckAliasPacket(packet); err != nil {
		return false
	}
	original := packetmeta.AddressPair{Source: header.Source, Destination: header.Destination}
	replacement := original
	switch direction {
	case PacketOutbound:
		if header.Source != grant.canonical {
			return false
		}
		if grant.binding.Role == networkmap.AliasConsumer {
			if !aliasServiceAllows(grant.binding.Services, header) {
				return false
			}
			if !f.trackAliasFlow(header, now) {
				return false
			}
		} else if !f.isAliasReply(header, now) {
			return false
		}
		replacement.Source = grant.local
	case PacketInbound:
		if header.Destination != grant.local {
			return false
		}
		header.Destination = grant.canonical
		if grant.binding.Role == networkmap.AliasProvider {
			if !aliasServiceAllows(grant.binding.Services, header) || !rulesAllow(f.rules, header) {
				return false
			}
			if !f.trackAliasFlow(header, now) {
				return false
			}
		} else if !f.isAliasReply(header, now) {
			return false
		}
		replacement.Destination = grant.canonical
	default:
		return false
	}
	return packetmeta.RewriteAddresses(packet, original, replacement) == nil
}

func aliasServiceAllows(services []networkmap.AliasService, header packetmeta.Header) bool {
	if isICMP(header.Protocol) && !isICMPEchoRequest(header) {
		return false
	}
	for _, service := range services {
		if service.Protocol != header.Protocol {
			continue
		}
		if isICMP(header.Protocol) ||
			(header.DestinationPort >= service.PortFrom && header.DestinationPort <= service.PortTo) {
			return true
		}
	}
	return false
}

// Pause admission while WireGuard keys/routes and TUN policy may represent
// different generations. The engine owns the transition and resumes only after
// every operation succeeds. No lock is held over device/helper I/O.
func (f *policyFilter) suspendFor(snapshot networkmap.Snapshot) {
	f.mu.Lock()
	f.suspended = len(f.aliases) != 0 || snapshotHasAliases(snapshot)
	f.mu.Unlock()
}

func (f *policyFilter) resume() {
	f.mu.Lock()
	f.suspended = false
	f.mu.Unlock()
}

func (f *policyFilter) validateAliasTransition(snapshot networkmap.Snapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.validateAliasTransitionLocked(snapshot)
}

func (f *policyFilter) validateAliasTransitionLocked(snapshot networkmap.Snapshot) error {
	previous := make(map[uint64]networkmap.AliasBinding)
	for _, grant := range f.aliases {
		previous[grant.peerID] = grant.binding
	}
	for _, peer := range snapshot.Peers {
		if binding, exists := previous[peer.ID]; exists {
			if err := networkmap.ValidateAliasAdvance(&binding, peer.Alias); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *policyFilter) trackAliasFlow(header packetmeta.Header, now time.Time) bool {
	key, stateful := outboundFlowKey(header)
	if !stateful {
		return false
	}
	if state, exists := f.flows[key]; exists && now.Before(state.expiresAt) {
		f.trackOutbound(header, now)
		return true
	}
	if !startsTrackableFlow(header) {
		return false
	}
	f.trackOutbound(header, now)
	state, exists := f.flows[key]
	return exists && now.Before(state.expiresAt)
}

func (f *policyFilter) isAliasReply(header packetmeta.Header, now time.Time) bool {
	if header.Protocol == packetmeta.ProtocolTCP && header.TCPFlags&0x02 != 0 && header.TCPFlags&0x10 == 0 {
		return false // A bare SYN is initiation, even on a previously admitted tuple.
	}
	return f.isTrackedReply(header, now)
}
