package dataplane

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
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
	return maps.EqualFunc(first, second, equalAliasPacketGrant)
}

func equalAliasPacketGrant(left, right aliasPacketGrant) bool {
	return left.peerID == right.peerID && left.canonical == right.canonical && left.local == right.local &&
		networkmap.EqualAlias(&left.binding, &right.binding)
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
		return f.allowOrdinaryLocked(direction, header, packet, now)
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
		// The endpoint's newest grant, also when its peer left the map.
		if peer.Alias != nil {
			if err := f.checkAliasMarkLocked(*peer.Alias); err != nil {
				return err
			}
		}
	}
	return nil
}

// aliasGrantKey names one alias endpoint grant between two node keys: a
// provider endpoint has a grant per consumer, and a new key of either node
// starts a new grant (a grant for an old self key is never usable again).
// It is a digest of the contract, endpoint and both keys, to keep marks small.
type aliasGrantKey [sha256.Size]byte

func aliasGrantKeyOf(binding networkmap.AliasBinding) aliasGrantKey {
	parts := [...]string{binding.ContractID, binding.EndpointID, binding.SelfKey, binding.PeerKey}
	size := 0
	for _, part := range parts {
		size += 8 + len(part)
	}
	encoded := make([]byte, 0, size)
	for _, part := range parts {
		encoded = binary.BigEndian.AppendUint64(encoded, uint64(len(part)))
		encoded = append(encoded, part...)
	}
	return sha256.Sum256(encoded)
}

// aliasMark is what a grant's successor is checked against: the grant less
// its identity (in the key) and with its services as a digest.
type aliasMark struct {
	generation, revision, epoch uint64
	role                        networkmap.AliasRole
	selfIPv4, selfIPv6          netip.Addr
	expiresAt                   time.Time
	services                    [sha256.Size]byte
}

func aliasMarkOf(binding networkmap.AliasBinding) aliasMark {
	return aliasMark{
		generation: binding.Generation, revision: binding.GrantRevision, epoch: binding.RecoveryEpoch,
		role: binding.Role, selfIPv4: binding.SelfIPv4, selfIPv6: binding.SelfIPv6,
		expiresAt: binding.ExpiresAt, services: aliasServicesDigest(binding.Services),
	}
}

func aliasServicesDigest(services []networkmap.AliasService) [sha256.Size]byte {
	encoded := make([]byte, 0, 5*len(services))
	for _, service := range services {
		encoded = append(encoded, service.Protocol)
		encoded = binary.BigEndian.AppendUint16(encoded, service.PortFrom)
		encoded = binary.BigEndian.AppendUint16(encoded, service.PortTo)
	}
	return sha256.Sum256(encoded)
}

// checkAliasMarkLocked refuses a grant older than, or differing at the same
// revision from, the newest one accepted for its endpoint and keys.
func (f *policyFilter) checkAliasMarkLocked(next networkmap.AliasBinding) error {
	mark, exists := f.aliasMarks[aliasGrantKeyOf(next)]
	if !exists {
		return nil
	}
	services := next.Services
	previous := next
	previous.Generation, previous.GrantRevision, previous.RecoveryEpoch = mark.generation, mark.revision, mark.epoch
	previous.Role, previous.SelfIPv4, previous.SelfIPv6 = mark.role, mark.selfIPv4, mark.selfIPv6
	previous.ExpiresAt = mark.expiresAt
	previous.Services, next.Services = nil, nil
	if err := networkmap.ValidateAliasAdvance(&previous, &next); err != nil {
		return err
	}
	if mark.generation == next.Generation && mark.revision == next.GrantRevision &&
		mark.services != aliasServicesDigest(services) {
		return fmt.Errorf("%w: same alias grant changed", networkmap.ErrInvalid)
	}
	return nil
}

// withoutRegressedAliases leaves out the alias peers whose grant the marks
// refuse, as WithoutUnusableAliases does for expired ones: the older grant is
// never used, and the rest of the map stays up. It returns how many it left
// out.
func (f *policyFilter) withoutRegressedAliases(snapshot networkmap.Snapshot) (networkmap.Snapshot, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := make([]networkmap.Node, 0, len(snapshot.Peers))
	for _, peer := range snapshot.Peers {
		if peer.Alias != nil && f.checkAliasMarkLocked(*peer.Alias) != nil {
			continue
		}
		kept = append(kept, peer)
	}
	dropped := len(snapshot.Peers) - len(kept)
	if dropped != 0 {
		snapshot.Peers = kept
	}
	return snapshot, dropped
}

// maxAliasMarks bounds the grants remembered, twice Core's largest map.
// Past it, marks go until a tenth of the room is free again, so the next
// maps do not each pay for a sort.
const maxAliasMarks = 20_000

// markAliasGrantsLocked records the grants of an accepted map. An empty or
// refused map records nothing and forgets nothing. The map's grants are
// recorded although applying the map may still fail later: they are Core's
// grants all the same. Past the bound, expired marks go first, then those
// ending soonest, never the map's own. Only there can an older grant of an
// evicted mark be accepted again (one that outlives the newer grant).
func (f *policyFilter) markAliasGrantsLocked(snapshot networkmap.Snapshot, now time.Time) {
	if f.aliasMarks == nil {
		f.aliasMarks = make(map[aliasGrantKey]aliasMark)
	}
	current := make(map[aliasGrantKey]struct{})
	for _, peer := range snapshot.Peers {
		if peer.Alias == nil {
			continue
		}
		key := aliasGrantKeyOf(*peer.Alias)
		f.aliasMarks[key] = aliasMarkOf(*peer.Alias)
		current[key] = struct{}{}
	}
	limit := f.aliasMarkLimit
	if limit <= 0 {
		limit = maxAliasMarks
	}
	if len(f.aliasMarks) <= limit {
		return
	}
	limit -= limit / 10
	type candidate struct {
		key       aliasGrantKey
		expiresAt time.Time
	}
	candidates := make([]candidate, 0, len(f.aliasMarks)-len(current))
	for key, mark := range f.aliasMarks {
		if _, kept := current[key]; kept {
			continue
		}
		if !now.Before(mark.expiresAt) {
			delete(f.aliasMarks, key)
			continue
		}
		candidates = append(candidates, candidate{key: key, expiresAt: mark.expiresAt})
	}
	slices.SortFunc(candidates, func(left, right candidate) int { return left.expiresAt.Compare(right.expiresAt) })
	for _, evicted := range candidates {
		if len(f.aliasMarks) <= limit {
			break
		}
		delete(f.aliasMarks, evicted.key)
	}
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
