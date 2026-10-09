package dataplane

import (
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/meshtransit/meshd/internal/networkmap"
	"github.com/meshtransit/meshd/internal/packetmeta"
)

const (
	defaultMaximumTrackedFlows = 4096
	tcpFlowTimeout             = 5 * time.Minute
	tcpClosingTimeout          = 10 * time.Second
	udpFlowTimeout             = 30 * time.Second
	icmpFlowTimeout            = 10 * time.Second
)

type compiledRule struct {
	sources      []networkmap.Selector
	destinations []networkmap.Destination
	protocols    []uint8
}

type flowEndpoint struct {
	address netip.Addr
	port    uint16
}

type flowKey struct {
	protocol    uint8
	source      flowEndpoint
	destination flowEndpoint
}

type flowState struct {
	expiresAt time.Time
	isClosing bool
}

// policyFilter enforces the node-specific inbound policy and keeps a bounded
// table of flows initiated by this node so their replies can return. Headscale
// reduces packet filters to destinations owned by the receiving node, so
// outbound authorization is enforced by the destination node.
type policyFilter struct {
	mu            sync.Mutex
	self          map[netip.Addr]struct{}
	peers         map[netip.Addr]packetAuthority
	selfAuthority packetAuthority
	rules         []compiledRule
	flows         map[flowKey]flowState
	clock         func() time.Time
	maximumFlows  int
	aliases       map[netip.Addr]aliasPacketGrant
	suspended     bool
}

func newPolicyFilter() *policyFilter {
	return &policyFilter{
		self:         map[netip.Addr]struct{}{},
		peers:        map[netip.Addr]packetAuthority{},
		rules:        []compiledRule{},
		flows:        map[flowKey]flowState{},
		clock:        time.Now,
		maximumFlows: defaultMaximumTrackedFlows,
		aliases:      map[netip.Addr]aliasPacketGrant{},
	}
}

// UpdateNetwork replaces all policy state and drops connection tracking from
// the previous map generation. A removed grant can therefore never survive a
// policy update through stale flow state.
func (f *policyFilter) UpdateNetwork(snapshot networkmap.Snapshot) {
	if f == nil {
		return
	}
	if snapshotHasAliases(snapshot) {
		aliasTime := time.Time{}
		if f.clock != nil {
			aliasTime = f.clock().UTC()
		}
		validated, err := networkmap.ValidateAndClone(snapshot, aliasTime)
		if err != nil {
			snapshot = networkmap.Snapshot{}
		} else {
			snapshot = validated
		}
	}
	aliases := aliasPacketGrants(snapshot)
	self := make(map[netip.Addr]struct{}, len(snapshot.Self.Addresses))
	for _, prefix := range snapshot.Self.Addresses {
		if address := prefix.Addr().Unmap(); address.IsValid() {
			self[address] = struct{}{}
		}
	}
	peers := make(map[netip.Addr]packetAuthority)
	for _, peer := range snapshot.Peers {
		for _, prefix := range peer.Addresses {
			if address := prefix.Addr().Unmap(); address.IsValid() {
				peers[address] = authorityFor(peer)
			}
		}
	}
	rules := make([]compiledRule, 0, len(snapshot.Policy))
	for _, rule := range snapshot.Policy {
		rules = append(rules, compiledRule{
			sources:      append([]networkmap.Selector{}, rule.Sources...),
			destinations: append([]networkmap.Destination{}, rule.Destinations...),
			protocols:    append([]uint8{}, rule.Protocols...),
		})
	}

	f.mu.Lock()
	if err := f.validateAliasTransitionLocked(snapshot); err != nil {
		self = map[netip.Addr]struct{}{}
		peers = map[netip.Addr]packetAuthority{}
		aliases = map[netip.Addr]aliasPacketGrant{}
		rules = nil
		snapshot = networkmap.Snapshot{}
	}
	selfAuthority := authorityFor(snapshot.Self)
	isUnchanged := maps.Equal(f.self, self) && f.selfAuthority.equal(selfAuthority) &&
		maps.EqualFunc(f.peers, peers, func(first, second packetAuthority) bool { return first.equal(second) }) &&
		slices.EqualFunc(f.rules, rules, equalCompiledRule) && equalAliasPacketGrants(f.aliases, aliases)
	f.self = self
	f.selfAuthority = selfAuthority
	f.peers = peers
	f.rules = rules
	f.aliases = aliases
	if !isUnchanged {
		f.flows = map[flowKey]flowState{}
	}
	f.mu.Unlock()
}

// Allow reports whether one plaintext packet may cross the TUN boundary.
// Malformed, fragmented, spoofed, stale, and policy-denied packets fail closed.
func (f *policyFilter) Allow(direction PacketDirection, packet []byte) bool {
	if f == nil || f.clock == nil {
		return false
	}
	header, err := packetmeta.Parse(packet)
	if err != nil {
		return false
	}
	header.Source = header.Source.Unmap()
	header.Destination = header.Destination.Unmap()
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
	if _, aliased := f.aliases[address]; aliased {
		return false // Alias traffic requires the atomic translation boundary.
	}
	return f.allowOrdinaryLocked(direction, header, now)
}

func (f *policyFilter) allowOrdinaryLocked(direction PacketDirection, header packetmeta.Header, now time.Time) bool {
	switch direction {
	case PacketOutbound:
		if !containsAddress(f.self, header.Source) || !f.peerUsableAt(header.Destination, now) {
			return false
		}
		f.trackOutbound(header, now)

		return true
	case PacketInbound:
		if !f.peerUsableAt(header.Source, now) || !containsAddress(f.self, header.Destination) {
			return false
		}
		if f.isTrackedReply(header, now) {
			return true
		}

		return rulesAllow(f.rules, header)
	default:
		return false
	}
}

func (f *policyFilter) trackOutbound(header packetmeta.Header, now time.Time) {
	key, isStateful := outboundFlowKey(header)
	if !isStateful {
		return
	}
	if state, exists := f.flows[key]; exists && state.expiresAt.After(now) {
		f.refreshFlow(key, header, now)
		return
	}
	if !startsTrackableFlow(header) {
		return
	}
	if len(f.flows) >= f.maximumFlows {
		f.purgeExpired(now)
	}
	if len(f.flows) >= f.maximumFlows {
		return
	}
	f.refreshFlow(key, header, now)
}

func (f *policyFilter) isTrackedReply(header packetmeta.Header, now time.Time) bool {
	replyKey, isStateful := outboundFlowKey(header)
	if !isStateful {
		return false
	}
	key := flowKey{
		protocol:    replyKey.protocol,
		source:      replyKey.destination,
		destination: replyKey.source,
	}
	state, exists := f.flows[key]
	if !exists {
		return false
	}
	if !state.expiresAt.After(now) {
		delete(f.flows, key)
		return false
	}
	if isICMP(header.Protocol) && !isICMPEchoReply(header) {
		return false
	}
	f.refreshFlow(key, header, now)

	return true
}

func (f *policyFilter) refreshFlow(key flowKey, header packetmeta.Header, now time.Time) {
	if header.Protocol == packetmeta.ProtocolTCP && header.TCPFlags&0x04 != 0 {
		delete(f.flows, key)
		return
	}
	timeout := flowTimeout(header)
	isClosing := header.Protocol == packetmeta.ProtocolTCP && header.TCPFlags&0x01 != 0
	if state, exists := f.flows[key]; exists && state.isClosing {
		isClosing = true
		timeout = tcpClosingTimeout
	}
	f.flows[key] = flowState{
		expiresAt: now.Add(timeout),
		isClosing: isClosing,
	}
}

func (f *policyFilter) purgeExpired(now time.Time) {
	for key, state := range f.flows {
		if !state.expiresAt.After(now) {
			delete(f.flows, key)
		}
	}
}

func rulesAllow(rules []compiledRule, header packetmeta.Header) bool {
	for _, rule := range rules {
		if !protocolsContain(rule.protocols, header.Protocol) ||
			!selectorsContain(rule.sources, header.Source) {
			continue
		}
		for _, destination := range rule.destinations {
			if destinationAllows(destination, header) {
				return true
			}
		}
	}

	return false
}

func destinationAllows(destination networkmap.Destination, header packetmeta.Header) bool {
	if !selectorContains(destination.Selector, header.Destination) {
		return false
	}
	if header.Protocol != packetmeta.ProtocolTCP && header.Protocol != packetmeta.ProtocolUDP {
		return destination.PortFrom == 0 && destination.PortTo == ^uint16(0)
	}

	return destination.PortFrom <= header.DestinationPort &&
		destination.PortTo >= header.DestinationPort
}

func protocolsContain(protocols []uint8, protocol uint8) bool {
	if len(protocols) == 0 {
		return protocol == packetmeta.ProtocolTCP || protocol == packetmeta.ProtocolUDP ||
			isICMP(protocol)
	}
	for _, candidate := range protocols {
		if candidate == protocol {
			return true
		}
	}

	return false
}

func selectorsContain(selectors []networkmap.Selector, address netip.Addr) bool {
	for _, selector := range selectors {
		if selectorContains(selector, address) {
			return true
		}
	}

	return false
}

func selectorContains(selector networkmap.Selector, address netip.Addr) bool {
	switch selector.Kind {
	case networkmap.SelectorAny:
		return true
	case networkmap.SelectorPrefix:
		return selector.Prefix.Contains(address)
	case networkmap.SelectorRange:
		if selector.RangeStart.BitLen() != address.BitLen() {
			return false
		}

		return selector.RangeStart.Compare(address) <= 0 && selector.RangeEnd.Compare(address) >= 0
	default:
		return false
	}
}

func outboundFlowKey(header packetmeta.Header) (flowKey, bool) {
	sourcePort := header.SourcePort
	destinationPort := header.DestinationPort
	if isICMP(header.Protocol) {
		if !header.HasICMPIdentifier {
			return flowKey{}, false
		}
		sourcePort = header.ICMPIdentifier
		destinationPort = header.ICMPIdentifier
	}
	isStateful := header.Protocol == packetmeta.ProtocolTCP ||
		header.Protocol == packetmeta.ProtocolUDP || isICMP(header.Protocol)
	if !isStateful {
		return flowKey{}, false
	}

	return flowKey{
		protocol: header.Protocol,
		source: flowEndpoint{
			address: header.Source,
			port:    sourcePort,
		},
		destination: flowEndpoint{
			address: header.Destination,
			port:    destinationPort,
		},
	}, true
}

func startsTrackableFlow(header packetmeta.Header) bool {
	switch header.Protocol {
	case packetmeta.ProtocolTCP:
		const (
			tcpSYN = 0x02
			tcpACK = 0x10
		)

		return header.TCPFlags&tcpSYN != 0 && header.TCPFlags&tcpACK == 0
	case packetmeta.ProtocolUDP:
		return true
	case packetmeta.ProtocolICMPv4, packetmeta.ProtocolICMPv6:
		return isICMPEchoRequest(header)
	default:
		return false
	}
}

func flowTimeout(header packetmeta.Header) time.Duration {
	switch header.Protocol {
	case packetmeta.ProtocolTCP:
		if header.TCPFlags&0x01 != 0 {
			return tcpClosingTimeout
		}

		return tcpFlowTimeout
	case packetmeta.ProtocolUDP:
		return udpFlowTimeout
	default:
		return icmpFlowTimeout
	}
}

func isICMP(protocol uint8) bool {
	return protocol == packetmeta.ProtocolICMPv4 || protocol == packetmeta.ProtocolICMPv6
}

func isICMPEchoRequest(header packetmeta.Header) bool {
	return (header.Protocol == packetmeta.ProtocolICMPv4 && header.ICMPType == 8) ||
		(header.Protocol == packetmeta.ProtocolICMPv6 && header.ICMPType == 128)
}

func isICMPEchoReply(header packetmeta.Header) bool {
	return (header.Protocol == packetmeta.ProtocolICMPv4 && header.ICMPType == 0) ||
		(header.Protocol == packetmeta.ProtocolICMPv6 && header.ICMPType == 129)
}

func containsAddress(addresses map[netip.Addr]struct{}, address netip.Addr) bool {
	_, exists := addresses[address]

	return exists
}

func equalCompiledRule(left, right compiledRule) bool {
	return slices.Equal(left.sources, right.sources) &&
		slices.Equal(left.destinations, right.destinations) &&
		slices.Equal(left.protocols, right.protocols)
}

// packetAuthority binds each host address to its mapped identity and exclusive
// deadline. A zero deadline preserves the protocol's legacy no-expiry meaning.
type packetAuthority struct {
	nodeID    uint64
	publicKey string
	expiresAt time.Time
	expired   bool
}

func authorityFor(value networkmap.Node) packetAuthority {
	return packetAuthority{nodeID: value.ID, publicKey: value.PublicKey, expiresAt: value.KeyExpiry, expired: value.Expired}
}

func (authority packetAuthority) usableAt(now time.Time) bool {
	return !authority.expired && (authority.expiresAt.IsZero() || now.Before(authority.expiresAt))
}

func (authority packetAuthority) equal(other packetAuthority) bool {
	return authority.nodeID == other.nodeID && authority.publicKey == other.publicKey &&
		authority.expired == other.expired && authority.expiresAt.Equal(other.expiresAt)
}

func (f *policyFilter) peerUsableAt(address netip.Addr, now time.Time) bool {
	authority, found := f.peers[address]
	return found && authority.usableAt(now)
}
