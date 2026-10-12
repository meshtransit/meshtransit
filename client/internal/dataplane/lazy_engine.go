package dataplane

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/client/internal/wghandshake"
)

// lazyFactory is implemented by device factories whose devices call the lazy
// peer hooks from their TUN and bind.
type lazyFactory interface {
	setLazyPeers(*lazyPeers)
}

// SetLazyPeers turns lazy peers on (the default) or off. Call it before the
// first Apply.
func (e *WireGuardEngine) SetLazyPeers(enabled bool) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lazyDisabled = !enabled
}

// lazyActive reports whether a map of peers peers installs them on demand.
// Once active, it stays so down to 90% of the threshold, so a map near the
// threshold does not rewrite every peer at each change.
func (e *WireGuardEngine) lazyActive(peers int) bool {
	threshold := e.lazyThreshold
	if e.lazyPlanPeers != nil {
		threshold = threshold * 9 / 10
	}
	return e.lazy != nil && e.lazySupported && !e.lazyDisabled && peers > threshold
}

// forgetLazyPeers drops the lazy state of a closed device. The responder is
// cleared only here: no packet path runs once the device has closed.
func (e *WireGuardEngine) forgetLazyPeers() {
	e.lazy.reset()
	e.lazyPlanPeers, e.lazyPreferred, e.lazyTrafficBase = nil, nil, nil
	if e.lazyResponder != nil {
		e.lazyResponder.Clear()
		e.lazyResponder = nil
	}
}

// restrictLazyPlan returns plan unchanged when the map installs every peer.
// Otherwise it publishes the map's lazy index and returns plan narrowed to the
// peers wireguard-go already holds, clearing plan's own configuration; the
// caller clears the returned plan's secrets, which include the shared relay
// configuration.
// It runs after the decisions that close the device, so a closed device keeps
// no peers.
func (e *WireGuardEngine) restrictLazyPlan(
	plan wireGuardPlan,
	privateKey NodePrivateKey,
) (wireGuardPlan, error) {
	if !e.lazyActive(len(plan.peers)) {
		if e.lazy != nil {
			e.lazy.index.Store(nil)
		}
		e.lazyPlanPeers, e.lazyPreferred, e.lazyTrafficBase = nil, nil, nil

		return plan, nil
	}
	responder := e.lazyResponder
	if !responder.Matches([32]byte(privateKey)) {
		created, err := wghandshake.NewResponder([32]byte(privateKey))
		if err != nil {
			// plan, so the caller still clears its secrets.
			return plan, errors.New("dataplane: preparing lazy peer handshakes failed")
		}
		// A replaced responder may still be in use by a packet path; it is
		// left to the collector rather than cleared.
		responder = created
		e.lazyResponder = created
	}
	previous := e.lazy.index.Load()
	index := &lazyIndex{
		byID:      make(map[uint64]*lazyPeer, len(plan.peers)),
		byAddr:    make(map[netip.Addr]*lazyPeer, len(plan.peers)),
		byKey:     make(map[[32]byte]*lazyPeer, len(plan.peers)),
		responder: responder,
	}
	planPeers := make(map[uint64]wireGuardPeerPlan, len(plan.peers))
	preferred := make(map[uint64]netip.AddrPort)
	trafficBase := make(map[uint64]peerTraffic)
	installed := make([]wireGuardPeerPlan, 0, len(e.peers))
	now := e.now().UnixNano()
	for _, peer := range plan.peers {
		peer.lazy = true
		var tracked *lazyPeer
		if previous != nil {
			if known := previous.byID[peer.id]; known != nil && known.key == peer.key {
				tracked = known
			}
		}
		if tracked == nil {
			tracked = &lazyPeer{id: peer.id, key: peer.key}
			tracked.lastActive.Store(now)
		}
		current, exists := e.peers[peer.id]
		isInstalled := exists && current.key == peer.key
		tracked.installed.Store(isInstalled)
		if isInstalled {
			installed = append(installed, peer)
		}
		index.byID[peer.id] = tracked
		index.byKey[peer.key] = tracked
		for _, prefix := range peer.allowedIPs {
			index.byAddr[prefix.Addr()] = tracked
		}
		planPeers[peer.id] = peer
		if base, counted := e.lazyTrafficBase[peer.id]; counted {
			if old, known := e.lazyPlanPeers[peer.id]; known && old.key == peer.key {
				trafficBase[peer.id] = base
			}
		}
		// A remembered path survives only an unchanged endpoint authority, as
		// an installed peer's preferred endpoint does.
		if endpoint, remembered := e.lazyPreferred[peer.id]; remembered {
			if old, known := e.lazyPlanPeers[peer.id]; known && old.key == peer.key &&
				old.discoveryKey == peer.discoveryKey &&
				slices.Equal(old.authorizedEndpoints, peer.authorizedEndpoints) {
				preferred[peer.id] = endpoint
			}
		}
	}

	header := plan.configuration[:len(plan.configuration)-len(plan.peerConfiguration)]
	var peerConfiguration bytes.Buffer
	peerConfiguration.WriteString("replace_peers=true\n")
	for _, peer := range installed {
		writeWireGuardPeerConfiguration(&peerConfiguration, peer)
	}
	configuration := make([]byte, 0, len(header)+peerConfiguration.Len())
	configuration = append(configuration, header...)
	configuration = append(configuration, peerConfiguration.Bytes()...)
	// The hash names the map and the mode, not which peers are installed:
	// equalPeerDataConfiguration compares those.
	hash := sha256.New()
	hash.Write(plan.configuration)
	hash.Write([]byte("lazy_peers=true\n"))

	restricted := plan
	restricted.configuration = configuration
	restricted.peerConfiguration = peerConfiguration.Bytes()
	copy(restricted.configurationHash[:], hash.Sum(nil))
	restricted.peers = installed
	restricted.mapPeers = len(plan.peers)
	clear(plan.configuration)
	clear(plan.peerConfiguration)

	e.lazyPlanPeers = planPeers
	e.lazyPreferred = preferred
	e.lazyTrafficBase = trafficBase
	e.lazy.index.Store(index)

	return restricted, nil
}

// installLazyPeer adds one map peer to wireguard-go; the activation worker
// calls it.
func (e *WireGuardEngine) installLazyPeer(peer *lazyPeer) {
	e.mu.Lock()
	defer e.mu.Unlock()
	index := e.lazy.index.Load()
	if e.device == nil || index == nil || index.byID[peer.id] != peer || peer.installed.Load() {
		return
	}
	planned, exists := e.lazyPlanPeers[peer.id]
	if !exists {
		return
	}
	written := planned
	if endpoint, remembered := e.lazyPreferred[peer.id]; remembered {
		written.baseEndpoint, written.basePath = endpoint.String(), peerPathDirect
	}
	var configuration bytes.Buffer
	writeWireGuardPeerConfiguration(&configuration, written)
	// The remembered path is used once: if it is what fails, the next
	// activation uses the map endpoint.
	delete(e.lazyPreferred, peer.id)
	if err := e.device.Configure(bytes.NewReader(configuration.Bytes())); err != nil {
		// Undo whatever part was applied; only if that fails too do the
		// device and the engine disagree, and the device is rebuilt.
		var undo bytes.Buffer
		writeWireGuardPeerKey(&undo, planned.key)
		undo.WriteString("remove=true\n")
		if err := e.device.Configure(bytes.NewReader(undo.Bytes())); err != nil {
			e.failLazyDevice("installing a lazy peer failed")

			return
		}
		if e.logger != nil {
			e.logger.Warn("installing a lazy peer failed", "peer", peer.id)
		}

		return
	}
	state := wireGuardPeerState{
		key:                 planned.key,
		discoveryKey:        planned.discoveryKey,
		baseEndpoint:        planned.baseEndpoint,
		basePath:            planned.basePath,
		currentEndpoint:     written.baseEndpoint,
		currentPath:         written.basePath,
		authorizedEndpoints: append([]netip.AddrPort(nil), planned.authorizedEndpoints...),
		allowedIPs:          append([]netip.Prefix(nil), planned.allowedIPs...),
		lazy:                true,
	}
	now := e.now()
	if state.currentPath == peerPathRelay {
		state.relayStartedAt = now
		e.relayBootstraps++
	}
	if e.peers == nil {
		e.peers = make(map[uint64]wireGuardPeerState)
	}
	e.peers[peer.id] = state
	peer.lastActive.Store(now.UnixNano())
	peer.installed.Store(true)
	e.lazy.activations.Add(1)
	if e.logger != nil {
		e.logger.Debug("lazy peer installed", "peer", peer.id, "path", state.currentPath.String())
	}
}

// evictIdleLazyPeers removes the installed peers that carried no packet
// through the TUN and completed no handshake for lazyIdleTimeout. Both sides
// have then dropped the session's keys (REJECT_AFTER_TIME is 180 s), so the
// next packet either way starts a handshake, which the hooks see.
func (e *WireGuardEngine) evictIdleLazyPeers(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	index := e.lazy.index.Load()
	if e.device == nil || index == nil {
		return
	}
	reporting, ok := e.device.(trafficReportingDevice)
	if !ok {
		return
	}
	traffic, err := reporting.PeerTraffic()
	if err != nil {
		if e.logger != nil {
			e.logger.Warn("reading peer activity for lazy eviction failed", "error", err)
		}
		return
	}
	idleSince := now.Add(-lazyIdleTimeout)
	var configuration bytes.Buffer
	evicted := make([]*lazyPeer, 0)
	for id, state := range e.peers {
		peer := index.byID[id]
		if !state.lazy || peer == nil || peer.key != state.key ||
			peer.lastActive.Load() > idleSince.UnixNano() {
			continue
		}
		if handshake := traffic[state.key].handshake; handshake != 0 &&
			time.Unix(int64(min(handshake, uint64(1)<<62)), 0).After(idleSince) {
			continue
		}
		// Clear installed before reading lastActive again (see use).
		peer.installed.Store(false)
		if peer.lastActive.Load() > idleSince.UnixNano() {
			peer.installed.Store(true)
			continue
		}
		writeWireGuardPeerKey(&configuration, state.key)
		configuration.WriteString("remove=true\n")
		evicted = append(evicted, peer)
	}
	if len(evicted) == 0 {
		return
	}
	if err := e.device.Configure(bytes.NewReader(configuration.Bytes())); err != nil {
		e.failLazyDevice("evicting idle lazy peers failed")

		return
	}
	for _, peer := range evicted {
		state := e.peers[peer.id]
		if state.currentPath == peerPathDirect && state.currentEndpoint != state.baseEndpoint {
			if endpoint, err := netip.ParseAddrPort(state.currentEndpoint); err == nil {
				e.lazyPreferred[peer.id] = endpoint
			}
		}
		counters := traffic[state.key]
		base := e.lazyTrafficBase[peer.id]
		e.lazyTrafficBase[peer.id] = peerTraffic{rx: base.rx + counters.rx, tx: base.tx + counters.tx}
		delete(e.peers, peer.id)
		e.lazy.evictions.Add(1)
	}
	if e.logger != nil {
		e.logger.Debug("idle lazy peers evicted", "count", len(evicted))
	}
}

// failLazyDevice closes a device whose peers no longer match the engine's
// and has the daemon rebuild it, as when a device stops on its own.
func (e *WireGuardEngine) failLazyDevice(reason string) {
	if e.logger != nil {
		e.logger.Warn(reason + "; rebuilding the wireguard device")
	}
	_ = e.closeLocked()
	select {
	case e.deviceStops <- struct{}{}:
	default: // a signal is already pending
	}
}

// lazyPreferredEndpoint records or clears the path chosen for a map peer
// wireguard-go does not hold; installLazyPeer applies it. It reports false for
// a peer that is not lazy.
func (e *WireGuardEngine) lazyPreferredEndpoint(peerID uint64, endpoint netip.AddrPort, restore bool) (bool, error) {
	planned, exists := e.lazyPlanPeers[peerID]
	if !exists {
		return false, nil
	}
	if restore {
		if planned.baseEndpoint == "" {
			return true, ErrPeerEndpointUnavailable
		}
		delete(e.lazyPreferred, peerID)

		return true, nil
	}
	if !slices.Contains(planned.authorizedEndpoints, endpoint) && !validDatagramEndpoint(endpoint) {
		return true, ErrPeerEndpointUnauthorized
	}
	if e.lazyPreferred == nil {
		e.lazyPreferred = make(map[uint64]netip.AddrPort)
	}
	e.lazyPreferred[peerID] = endpoint

	return true, nil
}
