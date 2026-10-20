package dataplane

import (
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/packetmeta"
	"meshtransit.net/shared/policydigest"
	"meshtransit.net/shared/routedigest"
)

const (
	defaultMaximumTrackedFlows = 32768
	// fullPurgeInterval bounds the scan for expired flows while the table is
	// full, so a burst of new flows cannot turn every packet into a full scan.
	fullPurgeInterval = time.Second
	tcpFlowTimeout    = 5 * time.Minute
	tcpClosingTimeout = 10 * time.Second
	udpFlowTimeout    = 30 * time.Second
	icmpFlowTimeout   = 10 * time.Second
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
	// admittedByLocalRules marks a flow whose reverse direction local rules
	// allowed when it began, such as a local server's UDP reply: the remote
	// may have opened the exchange, so a rule change ends it.
	admittedByLocalRules bool
}

// policyFilter enforces the node-specific inbound policy and keeps a bounded
// table of flows initiated by this node so their replies can return. Packet
// filters are reduced to destinations owned by the receiving node, so outbound
// authorization is enforced by the destination node.
type policyFilter struct {
	mu            sync.Mutex
	self          map[netip.Addr]struct{}
	peers         map[netip.Addr]packetAuthority
	selfAuthority packetAuthority
	rules         []compiledRule
	flows         map[flowKey]flowState
	clock         func() time.Time
	maximumFlows  int
	lastFullPurge time.Time
	aliases       map[netip.Addr]aliasPacketGrant
	suspended     bool
	// enforced is the digest of rules, recomputed whenever they change.
	enforced EnforcedPolicy
	// dropLastRule makes the filter deliberately enforce one rule fewer
	// than it was given, to demonstrate that Core detects the mismatch.
	dropLastRule bool
	// routed holds the map's Sites; routedInstalled the prefixes the helper
	// installed on the host. Only those reach a Site (mtcp-v1 §7.6).
	routed          *routedTable
	routedInstalled map[netip.Prefix]struct{}
	// routedActivity is what this node sent to each Site and heard back,
	// by Site reference (RoutedActivity).
	routedActivity map[string]*RoutedActivity
	// served holds what the node forwards into as a router (servedFilter).
	served servedFilter
	// exit holds what the node forwards to the Internet as an exit node.
	exit exitFilter
	// unreachable limits and counts the answers to packets for a Site that
	// cannot be reached.
	unreachable *unreachableAnswerer
	// selfTest sends a subnet router's self-test packets and takes their
	// answers before any rule (design §6.5.1).
	selfTest *selfTester
}

// EnforcedPolicy is the policy digest of the rules the packet filter
// enforces and when it installed them (R1-69).
type EnforcedPolicy struct {
	Digest    policydigest.Digest
	Grants    int
	AppliedAt time.Time
	// RouteDigest covers the served routes the node forwards into, and
	// RouteEntries counts them (mtcp-v1 §8.4).
	RouteDigest  routedigest.Digest
	RouteEntries int
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
		unreachable:  newUnreachableAnswerer(time.Now),
		selfTest:     newSelfTester(),
	}
}

// UpdateNetwork replaces all policy state and keeps only the tracked flows the
// new map still authorizes (retainFlowsLocked). A removed grant can therefore
// never survive a policy update through stale flow state, while a map change
// that does not touch a flow's authority leaves the flow running.
func (f *policyFilter) UpdateNetwork(snapshot networkmap.Snapshot) {
	f.updateNetwork(snapshot, newRoutedTable(snapshot))
}

// updateNetwork is UpdateNetwork with the map's routed table already built.
func (f *policyFilter) updateNetwork(snapshot networkmap.Snapshot, routed *routedTable) {
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
	policy := snapshot.Policy

	f.mu.Lock()
	dropLastRule := f.dropLastRule
	f.mu.Unlock()
	if dropLastRule && len(policy) > 0 {
		policy = policy[:len(policy)-1]
	}
	rules := make([]compiledRule, 0, len(policy))
	for _, rule := range policy {
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
		routed = nil
		snapshot = networkmap.Snapshot{}
	}
	selfAuthority := authorityFor(snapshot.Self)
	isUnchanged := maps.Equal(f.self, self) && f.selfAuthority.equal(selfAuthority) &&
		maps.EqualFunc(f.peers, peers, func(first, second packetAuthority) bool { return first.equal(second) }) &&
		slices.EqualFunc(f.rules, rules, equalCompiledRule) && equalAliasPacketGrants(f.aliases, aliases) &&
		equalRoutedTables(f.routed, routed)
	rulesChanged := !slices.EqualFunc(f.rules, rules, equalCompiledRule)
	previous := f.flowAuthorityLocked()
	f.self = self
	f.selfAuthority = selfAuthority
	f.peers = peers
	f.rules = rules
	f.aliases = aliases
	f.routed = routed
	f.pruneRoutedActivityLocked()
	if !isUnchanged {
		f.retainFlowsLocked(previous, rulesChanged)
	}
	if rulesChanged || f.enforced.Digest.IsZero() {
		f.enforced = enforcedPolicyOf(rules, f.clock)
	}
	f.mu.Unlock()
}

// enforcedPolicyOf digests exactly the compiled rules. A digest failure
// leaves the zero value, which is never reported.
func enforcedPolicyOf(rules []compiledRule, clock func() time.Time) EnforcedPolicy {
	enforced := make([]networkmap.Rule, len(rules))
	for index, rule := range rules {
		enforced[index] = networkmap.Rule{
			Sources: rule.sources, Destinations: rule.destinations,
			Protocols: rule.protocols,
		}
	}
	digest, grants, err := networkmap.PolicyDigest(enforced)
	if err != nil || clock == nil {
		return EnforcedPolicy{}
	}
	return EnforcedPolicy{Digest: digest, Grants: grants, AppliedAt: clock().UTC()}
}

// Enforced returns the digest of the rules being enforced, if known.
func (f *policyFilter) Enforced() (EnforcedPolicy, bool) {
	if f == nil {
		return EnforcedPolicy{}, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	enforced := f.enforced
	enforced.RouteDigest, enforced.RouteEntries = f.served.digest, f.served.entries
	if enforced.RouteDigest.IsZero() {
		// Nothing installed yet serves nothing: the empty set has a digest
		// of its own (route-digest-v1 §3), never 32 zero bytes.
		enforced.RouteDigest, enforced.RouteEntries = emptyRouteDigest, 0
	}
	return enforced, !enforced.Digest.IsZero()
}

func (f *policyFilter) setDropLastRule(drop bool) {
	f.mu.Lock()
	f.dropLastRule = drop
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
	return f.allowOrdinaryLocked(direction, header, packet, now)
}

func (f *policyFilter) allowOrdinaryLocked(direction PacketDirection, header packetmeta.Header, packet []byte,
	now time.Time,
) bool {
	switch direction {
	case PacketOutbound:
		if !containsAddress(f.self, header.Source) {
			// A router forwards a Site's answers to the mesh, an exit node
			// the Internet's.
			return f.servedOutboundLocked(header, now) || f.exitOutboundLocked(header, now)
		}
		if !f.peerUsableAt(header.Destination, now) {
			if !f.routedUsableAt(header.Destination, now) {
				return false
			}
			f.noteRoutedLocked(header.Destination, true, now)
		}
		f.trackOutbound(header, now)

		return true
	case PacketInbound:
		if !containsAddress(f.self, header.Destination) {
			// A router forwards what its rules admit into a Site, an exit
			// node what its pool's rules admit to the Internet.
			return f.servedInboundLocked(header, now) || f.exitInboundLocked(header, now)
		}
		if f.isTrackedErrorLocked(header, packet, now) {
			return true
		}
		if !f.peerUsableAt(header.Source, now) {
			// A Site's hosts only answer flows this node opened: routes
			// grant reaching a Site, never being reached from it.
			if !f.routedUsableAt(header.Source, now) || !f.isTrackedReply(header, now) {
				return false
			}
			f.noteRoutedLocked(header.Source, false, now)
			return true
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
	if elapsed := now.Sub(f.lastFullPurge); len(f.flows) >= f.maximumFlows && (elapsed < 0 || elapsed >= fullPurgeInterval) {
		f.lastFullPurge = now
		f.purgeExpired(now)
	}
	if len(f.flows) >= f.maximumFlows {
		return
	}
	f.refreshFlow(key, header, now)
	// Only UDP can start a flow with a reply: a TCP SYN-ACK and an ICMP echo
	// reply never start one, so those flows are always opened here.
	if state, exists := f.flows[key]; exists && header.Protocol == packetmeta.ProtocolUDP {
		state.admittedByLocalRules = rulesAllow(f.rules, reversedHeader(header))
		f.flows[key] = state
	}
}

// reversedHeader is the packet header of the opposite direction of a flow.
func reversedHeader(header packetmeta.Header) packetmeta.Header {
	header.Source, header.Destination = header.Destination, header.Source
	header.SourcePort, header.DestinationPort = header.DestinationPort, header.SourcePort
	return header
}

// flowAuthority is the part of the previous map a tracked flow depended on.
type flowAuthority struct {
	self          map[netip.Addr]struct{}
	selfAuthority packetAuthority
	peers         map[netip.Addr]packetAuthority
	aliases       map[netip.Addr]aliasPacketGrant
	// routed and routedInstalled reach a Site's hosts through its primary.
	routed          *routedTable
	routedInstalled map[netip.Prefix]struct{}
}

// retainFlowsLocked drops every tracked flow whose authority the new map
// changed and keeps the rest, so an unrelated peer joining, leaving or
// rotating its key no longer breaks established connections.
//
// A flow this node opened is authorized by the remote node's filter, so it
// survives local rule changes and depends only on both ends keeping their
// identity and staying usable. A flow local rules admitted (a shared-Device
// provider flow, or a local server's reply) ends on any rule change. Alias
// flows also require the exact same alias grant.
func (f *policyFilter) retainFlowsLocked(previous flowAuthority, rulesChanged bool) {
	now := time.Time{}
	if f.clock != nil {
		now = f.clock().UTC()
	}
	if !maps.Equal(previous.self, f.self) || !previous.selfAuthority.sameIdentity(f.selfAuthority) ||
		!previous.selfAuthority.usableAt(now) || !f.selfAuthority.usableAt(now) {
		f.flows = map[flowKey]flowState{}
		return
	}
	for key, state := range f.flows {
		if !f.flowStillAuthorized(previous, key, state, rulesChanged, now) {
			delete(f.flows, key)
		}
	}
}

func (f *policyFilter) flowStillAuthorized(previous flowAuthority, key flowKey, state flowState,
	rulesChanged bool, now time.Time,
) bool {
	if !state.expiresAt.After(now) {
		return false
	}
	remote, openedHere := key.destination.address, true
	if !containsAddress(f.self, key.source.address) {
		if !containsAddress(f.self, key.destination.address) {
			return false
		}
		remote, openedHere = key.source.address, false
	}
	if rulesChanged && (!openedHere || state.admittedByLocalRules) {
		return false
	}
	before, existed := previous.remoteAuthority(remote)
	after, exists := f.flowAuthorityLocked().remoteAuthority(remote)
	// A flow whose peer lapsed before this update stays dead even when the new
	// map extends the same key: renewed authority starts with new flows.
	if !existed || !exists || !before.sameIdentity(after) || !before.usableAt(now) || !after.usableAt(now) {
		return false
	}
	oldGrant, wasAliased := previous.aliases[remote]
	newGrant, isAliased := f.aliases[remote]
	return wasAliased == isAliased && (!isAliased || equalAliasPacketGrant(oldGrant, newGrant))
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
		expiresAt:            now.Add(timeout),
		isClosing:            isClosing,
		admittedByLocalRules: f.flows[key].admittedByLocalRules,
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

// sameIdentity reports whether both values name the same node and key. A
// changed deadline alone keeps the identity: usableAt checks it per packet.
func (authority packetAuthority) sameIdentity(other packetAuthority) bool {
	return authority.nodeID == other.nodeID && authority.publicKey == other.publicKey
}

func (authority packetAuthority) equal(other packetAuthority) bool {
	return authority.nodeID == other.nodeID && authority.publicKey == other.publicKey &&
		authority.expired == other.expired && authority.expiresAt.Equal(other.expiresAt)
}

func (f *policyFilter) peerUsableAt(address netip.Addr, now time.Time) bool {
	authority, found := f.peers[address]
	return found && authority.usableAt(now)
}

// flowAuthorityLocked is what the filter's flows currently depend on.
func (f *policyFilter) flowAuthorityLocked() flowAuthority {
	return flowAuthority{
		self: f.self, selfAuthority: f.selfAuthority, peers: f.peers, aliases: f.aliases,
		routed: f.routed, routedInstalled: f.routedInstalled,
	}
}

// remoteAuthority returns the node a remote address is reached through: the
// peer itself, or the primary router of a served Site whose prefix the
// helper installed.
func (authority flowAuthority) remoteAuthority(address netip.Addr) (packetAuthority, bool) {
	if peer, found := authority.peers[address]; found {
		return peer, true
	}
	prefix, site, found := authority.routed.lookup(address)
	if !found || !site.served {
		return packetAuthority{}, false
	}
	if _, installed := authority.routedInstalled[prefix]; !installed {
		return packetAuthority{}, false
	}
	return site.primary, true
}

func (f *policyFilter) routedUsableAt(address netip.Addr, now time.Time) bool {
	if _, peer := f.peers[address]; peer {
		return false
	}
	authority, found := f.flowAuthorityLocked().remoteAuthority(address)
	return found && authority.usableAt(now)
}

// SetRoutedInstalled records the routed prefixes the helper installed; flows
// to a prefix no longer installed end.
func (f *policyFilter) SetRoutedInstalled(prefixes []netip.Prefix) {
	if f == nil {
		return
	}
	installed := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		installed[prefix] = struct{}{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if maps.Equal(f.routedInstalled, installed) {
		return
	}
	previous := f.flowAuthorityLocked()
	f.routedInstalled = installed
	f.retainFlowsLocked(previous, false)
}

// routedUnreachable reports the Site an outbound packet the filter denied
// was for, when the helper installed its prefix but the Site cannot be
// reached: the packet is answered unreachable rather than dropped silently
// (mtcp-v1 §7.6).
func (f *policyFilter) routedUnreachable(packet []byte) (string, bool) {
	if f == nil || f.clock == nil {
		return "", false
	}
	header, err := packetmeta.Parse(packet)
	if err != nil {
		return "", false
	}
	destination, source := header.Destination.Unmap(), header.Source.Unmap()
	now := f.clock().UTC()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.suspended || !containsAddress(f.self, source) {
		return "", false
	}
	if _, peer := f.peers[destination]; peer {
		return "", false
	}
	prefix, site, found := f.routed.lookup(destination)
	if !found {
		return "", false
	}
	if _, installed := f.routedInstalled[prefix]; !installed {
		return "", false
	}
	if site.served && site.primary.usableAt(now) {
		return "", false // denied for another reason, such as a full flow table
	}
	return site.ref, true
}
