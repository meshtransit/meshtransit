// Package peerprobe binds product-owned probe state to authenticated peer
// channels derived from the current validated network map. Packets use the
// disco v2 format (docs/protocol/disco-v2.md).
package peerprobe

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/disco"
	"meshtransit.net/shared/key"
)

const (
	maxPeerChannels = 256
	// maxLearnedCandidates bounds the candidates learned per peer from
	// CALL_ME_MAYBE and peer-reflexive sources (disco-v2 §4.1).
	maxLearnedCandidates = 64
	// learnedCandidateLifetime is how long a learned candidate stays without
	// being advertised or observed again.
	learnedCandidateLifetime = 5*time.Minute + 10*time.Second

	mapNodeKeyPrefix  = "nodekey:"
	mapDiscoKeyPrefix = "discokey:"
)

var (
	// ErrInactive means the registry has been closed or has no active map.
	ErrInactive = errors.New("peerprobe: registry is inactive")
	// ErrInvalidSnapshot means peer-channel input violates the validated map
	// contract or does not belong to the registry's session identity.
	ErrInvalidSnapshot = errors.New("peerprobe: invalid network snapshot")
	// ErrInvalidGeneration means a generation is malformed, belongs to another
	// session, moves backwards, or does not match the active map and socket.
	ErrInvalidGeneration = errors.New("peerprobe: invalid generation")
	// ErrInvalidProbe means product-owned probe input is malformed or targets an
	// endpoint that is not a candidate of that peer.
	ErrInvalidProbe = errors.New("peerprobe: invalid probe")
	// ErrUnknownPeer means no active authenticated channel exists for a peer or
	// packet sender.
	ErrUnknownPeer = errors.New("peerprobe: unknown peer")
	// ErrInvalidPacket means an incoming packet failed bounded parsing,
	// authentication, or its node-identity binding.
	ErrInvalidPacket = errors.New("peerprobe: invalid packet")
)

// MapDiscoveryKey formats a disco public key as the legacy control map
// carries it.
func MapDiscoveryKey(public key.DiscoPublic) string {
	return mapDiscoKeyPrefix + hex.EncodeToString(public[:])
}

func parseMapKey(text, prefix string) ([32]byte, error) {
	var raw [32]byte
	encoded, ok := strings.CutPrefix(text, prefix)
	if !ok || len(encoded) != 64 || strings.ToLower(encoded) != encoded {
		return raw, ErrInvalidSnapshot
	}
	if _, err := hex.Decode(raw[:], []byte(encoded)); err != nil || raw == ([32]byte{}) {
		return [32]byte{}, ErrInvalidSnapshot
	}
	return raw, nil
}

// IncomingMessage is one authenticated path-probe message translated into
// product-owned state.
type IncomingMessage interface {
	isIncomingMessage()
}

// IncomingPing is an authenticated request from one control-authorized peer.
type IncomingPing struct {
	id           pathdiscovery.ProbeID
	peerID       uint64
	generation   pathdiscovery.ProbeGeneration
	source       netip.AddrPort
	sentAt       int64
	nodeKey      key.NodePublic
	discoveryKey key.DiscoPublic
}

func (IncomingPing) isIncomingMessage() {}

// ID returns the authenticated transaction token.
func (p IncomingPing) ID() pathdiscovery.ProbeID { return p.id }

// PeerID returns the control-authorized peer identity.
func (p IncomingPing) PeerID() uint64 { return p.peerID }

// Generation returns the session, map, and socket generation that opened the
// packet.
func (p IncomingPing) Generation() pathdiscovery.ProbeGeneration { return p.generation }

// Source returns the canonical UDP source observed by the local socket.
func (p IncomingPing) Source() netip.AddrPort { return p.source }

// IncomingPong contains the authenticated reply accepted by ProbeManager.
type IncomingPong struct {
	reply pathdiscovery.AuthenticatedProbeReply
}

func (IncomingPong) isIncomingMessage() {}

// AuthenticatedReply returns a value suitable for ProbeManager.Complete.
func (p IncomingPong) AuthenticatedReply() pathdiscovery.AuthenticatedProbeReply {
	return p.reply
}

// IncomingCallMeMaybe is a peer's accepted request to ping its endpoints now.
type IncomingCallMeMaybe struct {
	peerID    uint64
	endpoints []netip.AddrPort
}

func (IncomingCallMeMaybe) isIncomingMessage() {}

// PeerID returns the control-authorized peer identity.
func (c IncomingCallMeMaybe) PeerID() uint64 { return c.peerID }

// Endpoints returns the advertised endpoints that may be probed.
func (c IncomingCallMeMaybe) Endpoints() []netip.AddrPort { return slices.Clone(c.endpoints) }

type learnedCandidate struct {
	kind    disco.EndpointKind
	expires time.Time
}

type peerChannel struct {
	peerID       uint64
	nodeKey      key.NodePublic
	discoveryKey key.DiscoPublic
	mapEndpoints map[netip.AddrPort]struct{}
	learned      map[netip.AddrPort]learnedCandidate
	probe        bool // eligible for scheduled probing
	wire         *disco.PeerKey
	firstSeen    time.Time
	lastPong     time.Time
}

func (p *peerChannel) isCandidate(endpoint netip.AddrPort, now time.Time) bool {
	if _, ok := p.mapEndpoints[endpoint]; ok {
		return true
	}
	learned, ok := p.learned[endpoint]
	return ok && now.Before(learned.expires)
}

func (p *peerChannel) candidates(now time.Time) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(p.mapEndpoints)+len(p.learned))
	for endpoint := range p.mapEndpoints {
		out = append(out, endpoint)
	}
	for endpoint, learned := range p.learned {
		if _, inMap := p.mapEndpoints[endpoint]; !inMap && now.Before(learned.expires) {
			out = append(out, endpoint)
		}
	}
	slices.SortFunc(out, func(a, b netip.AddrPort) int { return a.Compare(b) })
	return out
}

// learn adds or refreshes candidates, evicting the oldest learned one when
// full. It returns whether anything new was added.
func (p *peerChannel) learn(endpoints []netip.AddrPort, kind disco.EndpointKind, now time.Time) bool {
	added := false
	for endpoint := range p.learned {
		if !now.Before(p.learned[endpoint].expires) {
			delete(p.learned, endpoint)
		}
	}
	for _, endpoint := range endpoints {
		if !validEndpoint(endpoint) {
			continue
		}
		if _, inMap := p.mapEndpoints[endpoint]; inMap {
			continue
		}
		if _, known := p.learned[endpoint]; !known {
			if len(p.learned) >= maxLearnedCandidates {
				p.evictOldest()
			}
			added = true
		}
		p.learned[endpoint] = learnedCandidate{kind: kind, expires: now.Add(learnedCandidateLifetime)}
	}
	return added
}

func (p *peerChannel) evictOldest() {
	var oldest netip.AddrPort
	var at time.Time
	for endpoint, learned := range p.learned {
		if at.IsZero() || learned.expires.Before(at) {
			oldest, at = endpoint, learned.expires
		}
	}
	delete(p.learned, oldest)
}

type channelSet struct {
	localNodeKey key.NodePublic
	byID         map[uint64]*peerChannel
	byDiscovery  map[key.DiscoPublic]*peerChannel
}

// Registry owns the authenticated channels for one control-session identity.
// Replacement, packet operations, and closure are safe for concurrent use.
type Registry struct {
	identity          key.DiscoPrivate
	localDiscoveryKey key.DiscoPublic
	random            io.Reader
	guard             disco.ReplayGuard

	mu               sync.RWMutex
	generation       pathdiscovery.ProbeGeneration
	latestGeneration pathdiscovery.ProbeGeneration
	localNodeKey     key.NodePublic
	byID             map[uint64]*peerChannel
	byDiscovery      map[key.DiscoPublic]*peerChannel
	closed           bool
}

// NewRegistry creates an inactive registry tied to one session disco key.
func NewRegistry(identity key.DiscoPrivate) (*Registry, error) {
	if identity.IsZero() {
		return nil, ErrInactive
	}

	return &Registry{
		identity:          identity,
		localDiscoveryKey: identity.Public(),
		random:            rand.Reader,
	}, nil
}

// Replace atomically derives and installs channels for one validated map. A
// failed replacement leaves the previous generation active. Candidates
// learned for a peer whose keys did not change are kept.
func (r *Registry) Replace(
	snapshot networkmap.Snapshot,
	generation pathdiscovery.ProbeGeneration,
	now time.Time,
) (int, error) {
	if r == nil {
		return 0, ErrInactive
	}
	if !generation.IsValid() || snapshot.Revision != generation.MapRevision {
		return 0, ErrInvalidGeneration
	}
	r.mu.RLock()
	err := r.canReplaceLocked(generation)
	r.mu.RUnlock()
	if err != nil {
		return 0, err
	}

	next, err := buildChannelSet(r.identity, r.localDiscoveryKey, snapshot, now)
	if err != nil {
		return 0, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.canReplaceLocked(generation); err != nil {
		return 0, err
	}
	for id, peer := range next.byID {
		if previous, ok := r.byID[id]; ok && previous.discoveryKey == peer.discoveryKey &&
			previous.nodeKey == peer.nodeKey {
			peer.learned, peer.firstSeen, peer.lastPong = previous.learned, previous.firstSeen, previous.lastPong
		}
	}
	for discoveryKey := range r.byDiscovery {
		if _, kept := next.byDiscovery[discoveryKey]; !kept {
			r.guard.Forget(discoveryKey)
		}
	}
	r.generation = generation
	r.latestGeneration = generation
	r.localNodeKey = next.localNodeKey
	r.byID = next.byID
	r.byDiscovery = next.byDiscovery

	return len(next.byID), nil
}

// Deactivate invalidates the active map. The latest generation is retained
// as a rollback-prevention watermark.
func (r *Registry) Deactivate() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0
	}
	removed := len(r.byID)
	r.generation = pathdiscovery.ProbeGeneration{}
	r.localNodeKey = key.NodePublic{}
	r.byID = nil
	r.byDiscovery = nil

	return removed
}

// Len reports the number of probe-capable peers in the active generation.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.byID)
}

// SealPing authenticates a transaction for one of the peer's candidates.
func (r *Registry) SealPing(
	transaction pathdiscovery.ProbeTransaction,
	padding int,
) ([]byte, error) {
	if r == nil {
		return nil, ErrInactive
	}
	if transaction.ID.IsZero() || transaction.PeerID == 0 ||
		!transaction.Generation.IsValid() || !validEndpoint(transaction.Endpoint) ||
		transaction.StartedAt.IsZero() ||
		!transaction.Deadline.After(transaction.StartedAt) || padding < 0 {
		return nil, ErrInvalidProbe
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := r.validateGenerationLocked(transaction.Generation); err != nil {
		return nil, err
	}
	peer, exists := r.byID[transaction.PeerID]
	if !exists {
		return nil, ErrUnknownPeer
	}
	if !peer.isCandidate(transaction.Endpoint, transaction.StartedAt) {
		return nil, ErrInvalidProbe
	}
	packet, err := peer.wire.Seal(nil, disco.Ping{
		TxID:    disco.TxID(transaction.ID),
		Node:    r.localNodeKey,
		SentAt:  transaction.StartedAt.UnixMilli(),
		Padding: padding,
	}, r.random)
	if err != nil {
		return nil, fmt.Errorf("peerprobe: sealing ping: %w", err)
	}

	return packet, nil
}

// Open authenticates and translates a packet that arrived directly from
// source. The cleartext sender key only selects a channel and is not trusted
// until that channel successfully opens the packet.
func (r *Registry) Open(
	packet []byte,
	source netip.AddrPort,
	generation pathdiscovery.ProbeGeneration,
	now time.Time,
) (IncomingMessage, error) {
	if r == nil {
		return nil, ErrInactive
	}
	if !validEndpoint(source) || !generation.IsValid() {
		return nil, ErrInvalidPacket
	}
	peer, message, err := r.open(packet, generation)
	if err != nil {
		return nil, err
	}
	switch message := message.(type) {
	case disco.Ping:
		if !key.Equal(message.Node, peer.nodeKey) {
			return nil, fmt.Errorf("%w: sender node binding", ErrInvalidPacket)
		}

		return IncomingPing{
			id:           pathdiscovery.ProbeID(message.TxID),
			peerID:       peer.peerID,
			generation:   generation,
			source:       source,
			sentAt:       message.SentAt,
			nodeKey:      peer.nodeKey,
			discoveryKey: peer.discoveryKey,
		}, nil
	case disco.Pong:
		return IncomingPong{reply: pathdiscovery.AuthenticatedProbeReply{
			ID:                    pathdiscovery.ProbeID(message.TxID),
			PeerID:                peer.peerID,
			Generation:            generation,
			Source:                source,
			ObservedLocalEndpoint: message.Observed,
		}}, nil
	case disco.CallMeMaybe:
		return r.acceptCallMeMaybe(peer, message, now)
	default:
		return nil, fmt.Errorf("%w: unsupported message", ErrInvalidPacket)
	}
}

// OpenRelayed authenticates a packet that a relay delivered from peerNode.
// Only CALL_ME_MAYBE is accepted this way, and only when the relay-attested
// node key is the one paired with the packet's disco key in the map.
func (r *Registry) OpenRelayed(
	packet []byte,
	peerNode key.NodePublic,
	generation pathdiscovery.ProbeGeneration,
	now time.Time,
) (IncomingMessage, error) {
	if r == nil {
		return nil, ErrInactive
	}
	peer, message, err := r.open(packet, generation)
	if err != nil {
		return nil, err
	}
	if !key.Equal(peer.nodeKey, peerNode) {
		return nil, fmt.Errorf("%w: relay source does not match sender", ErrInvalidPacket)
	}
	callMeMaybe, ok := message.(disco.CallMeMaybe)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported relayed message", ErrInvalidPacket)
	}

	return r.acceptCallMeMaybe(peer, callMeMaybe, now)
}

func (r *Registry) open(packet []byte, generation pathdiscovery.ProbeGeneration) (*peerChannel, disco.Message, error) {
	sender, err := disco.Sender(packet)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: sender wrapper", ErrInvalidPacket)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := r.validateGenerationLocked(generation); err != nil {
		return nil, nil, err
	}
	peer, exists := r.byDiscovery[sender]
	if !exists {
		return nil, nil, ErrUnknownPeer
	}
	message, err := peer.wire.Open(packet)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: authentication failed", ErrInvalidPacket)
	}

	return peer, message, nil
}

// acceptCallMeMaybe applies the sequence, freshness and rate rules and
// records the advertised endpoints as candidates.
func (r *Registry) acceptCallMeMaybe(peer *peerChannel, message disco.CallMeMaybe, now time.Time) (IncomingMessage, error) {
	if err := r.guard.Accept(peer.discoveryKey, message); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPacket, err)
	}
	endpoints := make([]netip.AddrPort, 0, len(message.Endpoints))
	for _, endpoint := range message.Endpoints {
		if validEndpoint(endpoint.Addr) {
			endpoints = append(endpoints, endpoint.Addr)
		}
	}
	r.mu.Lock()
	if current, ok := r.byID[peer.peerID]; ok && current == peer {
		peer.learn(endpoints, disco.EndpointStatic, now)
	}
	r.mu.Unlock()

	return IncomingCallMeMaybe{peerID: peer.peerID, endpoints: endpoints}, nil
}

// SealPong authenticates a response that echoes the source observed for an
// IncomingPing. Generation and peer identity are rechecked before use.
func (r *Registry) SealPong(ping IncomingPing) ([]byte, error) {
	if r == nil {
		return nil, ErrInactive
	}
	if ping.id.IsZero() || ping.peerID == 0 || !ping.generation.IsValid() ||
		!validEndpoint(ping.source) || ping.nodeKey.IsZero() ||
		ping.discoveryKey.IsZero() {
		return nil, ErrInvalidProbe
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := r.validateGenerationLocked(ping.generation); err != nil {
		return nil, err
	}
	peer, exists := r.byID[ping.peerID]
	if !exists {
		return nil, ErrUnknownPeer
	}
	if ping.nodeKey != peer.nodeKey || ping.discoveryKey != peer.discoveryKey {
		return nil, ErrInvalidProbe
	}
	packet, err := peer.wire.Seal(nil, disco.Pong{
		TxID:     disco.TxID(ping.id),
		Observed: ping.source,
		Echo:     ping.sentAt,
	}, r.random)
	if err != nil {
		return nil, fmt.Errorf("peerprobe: sealing pong: %w", err)
	}

	return packet, nil
}

// SealCallMeMaybe authenticates a CALL_ME_MAYBE for one peer and returns the
// peer's node key, by which the relay routes it.
func (r *Registry) SealCallMeMaybe(peerID uint64, message disco.CallMeMaybe) ([]byte, key.NodePublic, error) {
	if r == nil {
		return nil, key.NodePublic{}, ErrInactive
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || !r.generation.IsValid() {
		return nil, key.NodePublic{}, ErrInactive
	}
	peer, exists := r.byID[peerID]
	if !exists {
		return nil, key.NodePublic{}, ErrUnknownPeer
	}
	packet, err := peer.wire.Seal(nil, message, r.random)
	if err != nil {
		return nil, key.NodePublic{}, fmt.Errorf("peerprobe: sealing call-me-maybe: %w", err)
	}

	return packet, peer.nodeKey, nil
}

// LearnPeerReflexive records the source of an authenticated PING as a
// candidate of its peer (disco-v2 §4.1). It returns whether it was new.
func (r *Registry) LearnPeerReflexive(peerID uint64, source netip.AddrPort, now time.Time) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	peer, exists := r.byID[peerID]
	if !exists {
		return false
	}

	return peer.learn([]netip.AddrPort{source}, disco.EndpointPeerReflexive, now)
}

// MarkPong notes an authenticated reply from a peer: it has a trusted direct
// path for a while and needs no CALL_ME_MAYBE.
func (r *Registry) MarkPong(peerID uint64, now time.Time) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if peer, exists := r.byID[peerID]; exists && now.After(peer.lastPong) {
		peer.lastPong = now
	}
	r.mu.Unlock()
}

// RecentPong reports whether the peer answered a probe within window: it
// has a direct path that was proven recently.
func (r *Registry) RecentPong(peerID uint64, now time.Time, window time.Duration) bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	peer, exists := r.byID[peerID]

	return exists && !peer.lastPong.IsZero() && now.Sub(peer.lastPong) < window
}

// PeerCandidates returns the current candidates of one peer.
func (r *Registry) PeerCandidates(peerID uint64, now time.Time) []netip.AddrPort {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	peer, exists := r.byID[peerID]
	if !exists {
		return nil
	}

	return peer.candidates(now)
}

// peerStatus is a read-only view of one peer for scheduling decisions.
type peerStatus struct {
	peerID     uint64
	probe      bool
	firstSeen  time.Time
	lastPong   time.Time
	candidates []netip.AddrPort
}

func (r *Registry) peers(now time.Time) []peerStatus {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]peerStatus, 0, len(r.byID))
	for _, peer := range r.byID {
		out = append(out, peerStatus{
			peerID: peer.peerID, probe: peer.probe, firstSeen: peer.firstSeen, lastPong: peer.lastPong,
			candidates: peer.candidates(now),
		})
	}
	slices.SortFunc(out, func(a, b peerStatus) int {
		switch {
		case a.peerID < b.peerID:
			return -1
		case a.peerID > b.peerID:
			return 1
		default:
			return 0
		}
	})

	return out
}

// Close invalidates the active generation. It does not own the disco key.
func (r *Registry) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.generation = pathdiscovery.ProbeGeneration{}
	r.latestGeneration = pathdiscovery.ProbeGeneration{}
	r.localNodeKey = key.NodePublic{}
	r.byID = nil
	r.byDiscovery = nil
}

func (r *Registry) canReplaceLocked(generation pathdiscovery.ProbeGeneration) error {
	if r.closed {
		return ErrInactive
	}
	if !r.latestGeneration.IsValid() {
		return nil
	}
	if generation.Scope != r.latestGeneration.Scope ||
		generation.MapRevision < r.latestGeneration.MapRevision ||
		generation.Socket.Generation < r.latestGeneration.Socket.Generation ||
		(generation.Socket.Generation == r.latestGeneration.Socket.Generation &&
			generation.Socket.Port != r.latestGeneration.Socket.Port) {
		return ErrInvalidGeneration
	}

	return nil
}

func (r *Registry) validateGenerationLocked(
	generation pathdiscovery.ProbeGeneration,
) error {
	if r.closed || !r.generation.IsValid() {
		return ErrInactive
	}
	if generation != r.generation {
		return ErrInvalidGeneration
	}

	return nil
}

func buildChannelSet(
	identity key.DiscoPrivate,
	localDiscoveryKey key.DiscoPublic,
	snapshot networkmap.Snapshot,
	now time.Time,
) (channelSet, error) {
	if snapshot.Revision == 0 || snapshot.Self.ID == 0 ||
		!snapshot.Self.MachineAuthorized || snapshot.Self.Expired ||
		snapshot.Self.DiscoveryKey != MapDiscoveryKey(localDiscoveryKey) ||
		len(snapshot.Peers) > maxPeerChannels {
		return channelSet{}, ErrInvalidSnapshot
	}
	localNodeKey, err := parseMapKey(snapshot.Self.PublicKey, mapNodeKeyPrefix)
	if err != nil {
		return channelSet{}, ErrInvalidSnapshot
	}

	next := channelSet{
		localNodeKey: key.NodePublic(localNodeKey),
		byID:         make(map[uint64]*peerChannel, len(snapshot.Peers)),
		byDiscovery:  make(map[key.DiscoPublic]*peerChannel, len(snapshot.Peers)),
	}
	seenIDs := map[uint64]struct{}{snapshot.Self.ID: {}}
	seenNodeKeys := map[[32]byte]struct{}{localNodeKey: {}}
	seenDiscoveryKeys := map[key.DiscoPublic]struct{}{localDiscoveryKey: {}}
	for _, node := range snapshot.Peers {
		if node.ID == 0 || node.Expired || !node.MachineAuthorized {
			return channelSet{}, ErrInvalidSnapshot
		}
		if _, exists := seenIDs[node.ID]; exists {
			return channelSet{}, ErrInvalidSnapshot
		}
		seenIDs[node.ID] = struct{}{}
		nodeKey, err := parseMapKey(node.PublicKey, mapNodeKeyPrefix)
		if err != nil {
			return channelSet{}, ErrInvalidSnapshot
		}
		if _, exists := seenNodeKeys[nodeKey]; exists {
			return channelSet{}, ErrInvalidSnapshot
		}
		seenNodeKeys[nodeKey] = struct{}{}
		if node.DiscoveryKey == "" {
			continue
		}
		rawDiscovery, err := parseMapKey(node.DiscoveryKey, mapDiscoKeyPrefix)
		if err != nil {
			return channelSet{}, ErrInvalidSnapshot
		}
		discoveryKey := key.DiscoPublic(rawDiscovery)
		if _, exists := seenDiscoveryKeys[discoveryKey]; exists {
			return channelSet{}, ErrInvalidSnapshot
		}
		seenDiscoveryKeys[discoveryKey] = struct{}{}

		endpoints := make(map[netip.AddrPort]struct{}, len(node.Endpoints))
		for _, endpoint := range node.Endpoints {
			if !validEndpoint(endpoint) {
				return channelSet{}, ErrInvalidSnapshot
			}
			if _, exists := endpoints[endpoint]; exists {
				return channelSet{}, ErrInvalidSnapshot
			}
			endpoints[endpoint] = struct{}{}
		}
		wire, err := disco.NewPeerKey(identity, discoveryKey)
		if err != nil {
			return channelSet{}, fmt.Errorf("%w: deriving peer channel", ErrInvalidSnapshot)
		}
		peer := &peerChannel{
			peerID:       node.ID,
			nodeKey:      key.NodePublic(nodeKey),
			discoveryKey: discoveryKey,
			mapEndpoints: endpoints,
			learned:      make(map[netip.AddrPort]learnedCandidate),
			probe:        !node.OnlineKnown || node.Online,
			wire:         wire,
			firstSeen:    now,
		}
		next.byID[peer.peerID] = peer
		next.byDiscovery[peer.discoveryKey] = peer
	}

	return next, nil
}

func validEndpoint(endpoint netip.AddrPort) bool {
	address := endpoint.Addr()

	return endpoint.IsValid() && endpoint.Port() != 0 && address.IsValid() &&
		address == address.Unmap() && !address.Is4In6() && address.Zone() == "" &&
		address.IsGlobalUnicast() && !address.IsUnspecified() &&
		!address.IsMulticast() && !address.IsLoopback() &&
		!address.IsLinkLocalUnicast()
}
