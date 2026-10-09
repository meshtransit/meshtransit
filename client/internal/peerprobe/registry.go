// Package peerprobe binds product-owned probe state to authenticated peer
// channels derived from the current validated network map.
package peerprobe

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"meshtransit.net/client/internal/compat/disco"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
)

const maxPeerChannels = 256

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
	// endpoint not authorized for that peer by the active map.
	ErrInvalidProbe = errors.New("peerprobe: invalid probe")
	// ErrUnknownPeer means no active authenticated channel exists for a peer or
	// packet sender.
	ErrUnknownPeer = errors.New("peerprobe: unknown peer")
	// ErrInvalidPacket means an incoming packet failed bounded parsing,
	// authentication, or its node-identity binding.
	ErrInvalidPacket = errors.New("peerprobe: invalid packet")
)

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
	nodeKey      disco.NodeKey
	discoveryKey disco.PublicKey
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

type peerChannel struct {
	peerID       uint64
	nodeKey      disco.NodeKey
	discoveryKey disco.PublicKey
	endpoints    map[netip.AddrPort]struct{}
	wire         *disco.Peer
}

type channelSet struct {
	localNodeKey disco.NodeKey
	byID         map[uint64]*peerChannel
	byDiscovery  map[disco.PublicKey]*peerChannel
}

// Registry owns the authenticated channels for one control-session identity.
// Replacement, packet operations, and closure are safe for concurrent use.
type Registry struct {
	mu                sync.RWMutex
	identity          *disco.Identity
	localDiscoveryKey disco.PublicKey
	generation        pathdiscovery.ProbeGeneration
	latestGeneration  pathdiscovery.ProbeGeneration
	localNodeKey      disco.NodeKey
	byID              map[uint64]*peerChannel
	byDiscovery       map[disco.PublicKey]*peerChannel
	closed            bool
}

// NewRegistry creates an inactive registry tied to one live session identity.
// The identity remains owned by the session and must outlive this registry.
func NewRegistry(identity *disco.Identity) (*Registry, error) {
	if identity == nil {
		return nil, ErrInactive
	}
	publicKey, err := identity.Public()
	if err != nil {
		return nil, fmt.Errorf("%w: session identity is unavailable", ErrInactive)
	}

	return &Registry{
		identity:          identity,
		localDiscoveryKey: publicKey,
	}, nil
}

// Replace atomically derives and installs channels for one validated map. A
// failed replacement leaves the previous generation active.
func (r *Registry) Replace(
	snapshot networkmap.Snapshot,
	generation pathdiscovery.ProbeGeneration,
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

	next, err := buildChannelSet(
		r.identity,
		r.localDiscoveryKey,
		snapshot,
	)
	if err != nil {
		return 0, err
	}

	r.mu.Lock()
	if err := r.canReplaceLocked(generation); err != nil {
		r.mu.Unlock()
		closeChannelSet(next)

		return 0, err
	}
	previous := channelSet{
		localNodeKey: r.localNodeKey,
		byID:         r.byID,
		byDiscovery:  r.byDiscovery,
	}
	r.generation = generation
	r.latestGeneration = generation
	r.localNodeKey = next.localNodeKey
	r.byID = next.byID
	r.byDiscovery = next.byDiscovery
	r.mu.Unlock()

	closeChannelSet(previous)

	return len(next.byID), nil
}

// Deactivate invalidates the active map and destroys all derived peer secrets.
// The latest generation is retained as a rollback-prevention watermark.
func (r *Registry) Deactivate() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()

		return 0
	}
	previous := channelSet{
		localNodeKey: r.localNodeKey,
		byID:         r.byID,
		byDiscovery:  r.byDiscovery,
	}
	r.generation = pathdiscovery.ProbeGeneration{}
	r.localNodeKey = disco.NodeKey{}
	r.byID = nil
	r.byDiscovery = nil
	r.mu.Unlock()

	closeChannelSet(previous)

	return len(previous.byID)
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

// SealPing authenticates a transaction for the map-authorized peer endpoint.
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
	if _, authorized := peer.endpoints[transaction.Endpoint]; !authorized {
		return nil, ErrInvalidProbe
	}
	packet, err := peer.wire.Seal(disco.Ping{
		ID:      disco.TransactionID(transaction.ID),
		NodeKey: r.localNodeKey,
		Padding: padding,
	})
	if err != nil {
		return nil, fmt.Errorf("peerprobe: sealing ping: %w", err)
	}

	return packet, nil
}

// Open authenticates and translates a packet from the active peer registry.
// The cleartext wrapper key is used only to select a channel and is not trusted
// until that channel successfully opens the packet.
func (r *Registry) Open(
	packet []byte,
	source netip.AddrPort,
	generation pathdiscovery.ProbeGeneration,
) (IncomingMessage, error) {
	if r == nil {
		return nil, ErrInactive
	}
	if !validEndpoint(source) || !generation.IsValid() {
		return nil, ErrInvalidPacket
	}
	sender, err := disco.Source(packet)
	if err != nil {
		return nil, fmt.Errorf("%w: sender wrapper", ErrInvalidPacket)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := r.validateGenerationLocked(generation); err != nil {
		return nil, err
	}
	peer, exists := r.byDiscovery[sender]
	if !exists {
		return nil, ErrUnknownPeer
	}
	message, err := peer.wire.Open(packet)
	if err != nil {
		return nil, fmt.Errorf("%w: authentication failed", ErrInvalidPacket)
	}

	switch message := message.(type) {
	case disco.Ping:
		if message.NodeKey != peer.nodeKey {
			return nil, fmt.Errorf("%w: sender node binding", ErrInvalidPacket)
		}

		return IncomingPing{
			id:           pathdiscovery.ProbeID(message.ID),
			peerID:       peer.peerID,
			generation:   generation,
			source:       source,
			nodeKey:      peer.nodeKey,
			discoveryKey: peer.discoveryKey,
		}, nil
	case disco.Pong:
		return IncomingPong{reply: pathdiscovery.AuthenticatedProbeReply{
			ID:                    pathdiscovery.ProbeID(message.ID),
			PeerID:                peer.peerID,
			Generation:            generation,
			Source:                source,
			ObservedLocalEndpoint: message.Source,
		}}, nil
	default:
		return nil, fmt.Errorf("%w: unsupported message", ErrInvalidPacket)
	}
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
	packet, err := peer.wire.Seal(disco.Pong{
		ID:     disco.TransactionID(ping.id),
		Source: ping.source,
	})
	if err != nil {
		return nil, fmt.Errorf("peerprobe: sealing pong: %w", err)
	}

	return packet, nil
}

// Close invalidates the active generation and destroys every derived shared
// secret. It does not close the session-owned identity.
func (r *Registry) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()

		return
	}
	previous := channelSet{
		localNodeKey: r.localNodeKey,
		byID:         r.byID,
		byDiscovery:  r.byDiscovery,
	}
	r.closed = true
	r.generation = pathdiscovery.ProbeGeneration{}
	r.latestGeneration = pathdiscovery.ProbeGeneration{}
	r.localNodeKey = disco.NodeKey{}
	r.byID = nil
	r.byDiscovery = nil
	r.mu.Unlock()

	closeChannelSet(previous)
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
	identity *disco.Identity,
	localDiscoveryKey disco.PublicKey,
	snapshot networkmap.Snapshot,
) (channelSet, error) {
	if snapshot.Revision == 0 || snapshot.Self.ID == 0 ||
		!snapshot.Self.MachineAuthorized || snapshot.Self.Expired ||
		snapshot.Self.DiscoveryKey != localDiscoveryKey.String() ||
		len(snapshot.Peers) > maxPeerChannels {
		return channelSet{}, ErrInvalidSnapshot
	}
	localNodeKey, err := disco.ParseNodeKey(snapshot.Self.PublicKey)
	if err != nil {
		return channelSet{}, ErrInvalidSnapshot
	}

	type channelSpec struct {
		peerID       uint64
		nodeKey      disco.NodeKey
		discoveryKey disco.PublicKey
		endpoints    map[netip.AddrPort]struct{}
	}
	specs := make([]channelSpec, 0, len(snapshot.Peers))
	seenIDs := map[uint64]struct{}{snapshot.Self.ID: {}}
	seenNodeKeys := map[disco.NodeKey]struct{}{localNodeKey: {}}
	seenDiscoveryKeys := map[disco.PublicKey]struct{}{localDiscoveryKey: {}}
	for _, node := range snapshot.Peers {
		if node.ID == 0 || node.Expired || !node.MachineAuthorized {
			return channelSet{}, ErrInvalidSnapshot
		}
		if _, exists := seenIDs[node.ID]; exists {
			return channelSet{}, ErrInvalidSnapshot
		}
		seenIDs[node.ID] = struct{}{}
		nodeKey, err := disco.ParseNodeKey(node.PublicKey)
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
		discoveryKey, err := disco.ParsePublicKey(node.DiscoveryKey)
		if err != nil {
			return channelSet{}, ErrInvalidSnapshot
		}
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
		specs = append(specs, channelSpec{
			peerID:       node.ID,
			nodeKey:      nodeKey,
			discoveryKey: discoveryKey,
			endpoints:    endpoints,
		})
	}

	next := channelSet{
		localNodeKey: localNodeKey,
		byID:         make(map[uint64]*peerChannel, len(specs)),
		byDiscovery:  make(map[disco.PublicKey]*peerChannel, len(specs)),
	}
	for _, spec := range specs {
		wire, err := identity.Peer(spec.discoveryKey)
		if err != nil {
			closeChannelSet(next)

			return channelSet{}, fmt.Errorf(
				"%w: deriving peer channel",
				ErrInvalidSnapshot,
			)
		}
		peer := &peerChannel{
			peerID:       spec.peerID,
			nodeKey:      spec.nodeKey,
			discoveryKey: spec.discoveryKey,
			endpoints:    spec.endpoints,
			wire:         wire,
		}
		next.byID[peer.peerID] = peer
		next.byDiscovery[peer.discoveryKey] = peer
	}

	return next, nil
}

func closeChannelSet(channels channelSet) {
	for _, peer := range channels.byID {
		peer.wire.Close()
	}
}

func validEndpoint(endpoint netip.AddrPort) bool {
	address := endpoint.Addr()

	return endpoint.IsValid() && endpoint.Port() != 0 && address.IsValid() &&
		address == address.Unmap() && !address.Is4In6() && address.Zone() == "" &&
		address.IsGlobalUnicast() && !address.IsUnspecified() &&
		!address.IsMulticast() && !address.IsLoopback() &&
		!address.IsLinkLocalUnicast()
}
