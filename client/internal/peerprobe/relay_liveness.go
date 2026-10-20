package peerprobe

import (
	"context"
	"crypto/rand"
	"slices"
	"time"

	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/disco"
)

// Liveness through the relay (disco-v2 §3.2.1): a node pings, through the
// relay, peers it must know are up while it has no proven direct path to
// them, such as the routers of a Site it routes through.
const (
	// maxRelayLivenessPeers bounds the peers pinged through the relay.
	maxRelayLivenessPeers = 64
	// relayLivenessTick is how often due peers are pinged; each peer at most
	// every relayLivenessSpacing.
	relayLivenessTick    = time.Second
	relayLivenessSpacing = 2 * time.Second
	// relayPongWithin is how long a relayed PING waits for its PONG.
	relayPongWithin = 5 * time.Second
	// relayPingAnswerSpacing paces the PONGs this node sends one peer.
	relayPingAnswerSpacing = time.Second
)

// RelayLivenessObserver learns that a peer answered a PING through the
// relay. It must return immediately.
type RelayLivenessObserver interface {
	ObserveRelayPong(peerID uint64, at time.Time)
}

type relayPing struct {
	peerID   uint64
	deadline time.Time
}

// relayLiveness is the state of the relay pings; guarded by its mutex.
type relayLiveness struct {
	targets []uint64
	sent    map[uint64]time.Time
	pending map[disco.TxID]relayPing
}

// SetRelayLiveness replaces the peers to ping through the relay while no
// direct path to them is proven; at most maxRelayLivenessPeers are kept.
func (r *Runtime) SetRelayLiveness(peerIDs []uint64) {
	if r == nil {
		return
	}
	targets := slices.Clone(peerIDs)
	slices.Sort(targets)
	targets = slices.Compact(targets)
	targets = slices.DeleteFunc(targets, func(id uint64) bool { return id == 0 })
	targets = targets[:min(len(targets), maxRelayLivenessPeers)]
	r.relayMu.Lock()
	defer r.relayMu.Unlock()
	r.relay.targets = targets
	for peerID := range r.relay.sent {
		if !slices.Contains(targets, peerID) {
			delete(r.relay.sent, peerID)
		}
	}
}

func (r *Runtime) runRelayLiveness(ctx context.Context) {
	relayed, ok := r.transport.(pathdiscovery.RelayDatagramTransport)
	if !ok {
		return
	}
	ticker := time.NewTicker(relayLivenessTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.sendRelayPings(relayed)
		}
	}
}

// sendRelayPings pings through the relay each target that is due and has no
// recently proven direct path.
func (r *Runtime) sendRelayPings(relayed pathdiscovery.RelayDatagramTransport) {
	r.lifecycleMu.RLock()
	defer r.lifecycleMu.RUnlock()
	if !r.activeGeneration().IsValid() {
		return
	}
	now := r.clock()
	r.relayMu.Lock()
	for id, ping := range r.relay.pending {
		if !now.Before(ping.deadline) {
			delete(r.relay.pending, id)
		}
	}
	var due []uint64
	for _, peerID := range r.relay.targets {
		if last, sent := r.relay.sent[peerID]; sent && now.Sub(last) < relayLivenessSpacing {
			continue
		}
		if r.registry.RecentPong(peerID, now, directTrust) {
			continue
		}
		due = append(due, peerID)
	}
	r.relayMu.Unlock()
	for _, peerID := range due {
		var id disco.TxID
		if _, err := rand.Read(id[:]); err != nil || id.IsZero() {
			continue
		}
		packet, node, err := r.registry.SealRelayPing(peerID, id, now)
		if err != nil {
			continue
		}
		r.relayMu.Lock()
		r.relay.sent[peerID] = now
		if len(r.relay.pending) < 4*maxRelayLivenessPeers {
			r.relay.pending[id] = relayPing{peerID: peerID, deadline: now.Add(relayPongWithin)}
		}
		r.relayMu.Unlock()
		_ = relayed.SendRelayDatagram(packet, node)
	}
}

// answerRelayPing sends a PONG through the relay, at most one per peer per
// relayPingAnswerSpacing.
func (r *Runtime) answerRelayPing(ping IncomingRelayPing, now time.Time) {
	relayed, ok := r.transport.(pathdiscovery.RelayDatagramTransport)
	if !ok || !r.registry.AllowAnswer(ping.PeerID(), answerRelayPing, relayPingAnswerSpacing, now) {
		return
	}
	packet, node, err := r.registry.SealRelayPong(ping)
	if err != nil {
		return
	}
	_ = relayed.SendRelayDatagram(packet, node)
}

// acceptRelayPong reports a PONG that answers an outstanding relayed PING
// to the same peer.
func (r *Runtime) acceptRelayPong(pong IncomingRelayPong, now time.Time) {
	r.relayMu.Lock()
	ping, outstanding := r.relay.pending[pong.ID()]
	matched := outstanding && ping.peerID == pong.PeerID() && now.Before(ping.deadline)
	if matched {
		delete(r.relay.pending, pong.ID())
	}
	r.relayMu.Unlock()
	if !matched {
		return
	}
	if observer, ok := r.observer.(RelayLivenessObserver); ok {
		observer.ObserveRelayPong(pong.PeerID(), now)
	}
}
