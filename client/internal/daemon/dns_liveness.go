package daemon

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/client/internal/dnsconfig"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/overlayframe"
	"meshtransit.net/client/internal/peerprobe"
)

// Liveness of the resolver Devices of DNS zones (DNS design D1b §5.6): a
// resolver Device in use is pinged through the relay like the routers, after
// them, and one that answered before and stopped is asked after the zone's
// other resolvers. Only zones with another resolver gain from it, and only a
// resolver asked lately is pinged, so an idle node, a phone above all, sends
// nothing for DNS.
const (
	// resolverInUseFor is how long after its last question a resolver
	// Device is pinged.
	resolverInUseFor = time.Minute
	// livenessTick is how often the peers pinged are brought up to date
	// with the resolvers in use.
	livenessTick = time.Second
)

// dnsLivenessController is a DNS controller whose resolver orders resolver
// Devices by their liveness.
type dnsLivenessController interface {
	SetResolverLiveness(dnsconfig.ResolverLiveness)
}

// failoverLiveness is the failover's view of resolver Devices for DNS.
type failoverLiveness struct{ failover *routeFailover }

func (liveness failoverLiveness) Stopped(address netip.Addr) bool {
	return liveness.failover.resolverStopped(address)
}

func (liveness failoverLiveness) Asked(address netip.Addr) {
	liveness.failover.resolverAsked(address)
}

// livenessPeers returns the peers to ping through the relay, in order of
// need: the routers of Sites with several and the candidates of the exit
// pool used, then the resolver Devices asked lately; at most as many as the
// relay pings. It records since when each is pinged, and whether the list
// differs from the last one.
func (failover *routeFailover) livenessPeers() ([]uint64, bool) {
	if failover == nil {
		return nil, false
	}
	routers := failover.routerPeers()
	failover.mu.Lock()
	defer failover.mu.Unlock()
	now := failover.clock()
	ids := slices.DeleteFunc(routers, func(id uint64) bool { return id == 0 })
	for _, id := range failover.resolverOrder {
		asked, found := failover.askedAt[id]
		if found && now.Sub(asked) <= resolverInUseFor && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	ids = ids[:min(len(ids), peerprobe.MaxRelayLivenessPeers)]
	pinged := make(map[uint64]time.Time, len(ids))
	for _, id := range ids {
		since, found := failover.pinged[id]
		if !found {
			since = now
		}
		pinged[id] = since
	}
	changed := !slices.Equal(ids, failover.livenessList)
	failover.pinged, failover.livenessList = pinged, slices.Clone(ids)
	return ids, changed
}

// resolverAsked notes a question to the resolver Device at address, and
// wakes watchResolverLiveness when it is not pinged yet.
func (failover *routeFailover) resolverAsked(address netip.Addr) {
	if failover == nil {
		return
	}
	failover.mu.Lock()
	id, found := failover.resolverPeers[address.Unmap()]
	if !found || failover.livenessClosed {
		failover.mu.Unlock()
		return
	}
	failover.askedAt[id] = failover.clock()
	_, pinged := failover.pinged[id]
	failover.mu.Unlock()
	if !pinged {
		select {
		case failover.livenessWake <- struct{}{}:
		default:
		}
	}
}

// resolverStopped reports the resolver Device at address that answered the
// node's pings before and has not for failoverAliveWithin, while pinged
// longer than that. Once the session ends it reports none: its pings ended.
func (failover *routeFailover) resolverStopped(address netip.Addr) bool {
	if failover == nil {
		return false
	}
	failover.mu.Lock()
	defer failover.mu.Unlock()
	id, found := failover.resolverPeers[address.Unmap()]
	if !found || failover.livenessClosed {
		return false
	}
	since, pinged := failover.pinged[id]
	now := failover.clock()
	if !pinged || now.Sub(since) <= failoverAliveWithin {
		return false
	}
	at, answered := failover.pongs[id]
	return answered && now.Sub(at) > failoverAliveWithin
}

// closeLiveness ends the liveness of resolver Devices with the session.
func (failover *routeFailover) closeLiveness() {
	if failover == nil {
		return
	}
	failover.mu.Lock()
	defer failover.mu.Unlock()
	failover.livenessClosed = true
}

// syncRelayLiveness hands set the peers to ping through the relay, computed
// under the same lock, so a map apply and the watcher never set an older list
// over a newer one; unchanged, the list is set only when force says so.
func (failover *routeFailover) syncRelayLiveness(set func([]uint64), force bool) {
	failover.livenessSetMu.Lock()
	defer failover.livenessSetMu.Unlock()
	if peers, changed := failover.livenessPeers(); changed || force {
		set(peers)
	}
}

// watchResolverLiveness keeps the peers pinged through the relay up to date
// with the resolver Devices in use, until ctx ends.
func watchResolverLiveness(ctx context.Context, failover *routeFailover, set func([]uint64)) {
	ticker := time.NewTicker(livenessTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-failover.livenessWake:
		}
		failover.syncRelayLiveness(set, false)
	}
}

// resolverPeersOf returns the peer of each resolver Device of snapshot's
// DNS zones that has another resolver to answer first, by mesh address, and
// those peers in the zones' order.
func resolverPeersOf(snapshot networkmap.Snapshot) (map[netip.Addr]uint64, []uint64) {
	if snapshot.DNS == nil {
		return nil, nil
	}
	var wanted []netip.Addr
	seen := map[netip.Addr]struct{}{}
	for _, route := range snapshot.DNS.Routes {
		if len(route.Resolvers) < 2 {
			continue // with one resolver there is nothing to ask first
		}
		for _, resolver := range route.Resolvers {
			address := resolver.Address.Addr().Unmap()
			if _, dup := seen[address]; !dup && overlayframe.Contains(netip.PrefixFrom(address, address.BitLen())) {
				seen[address] = struct{}{}
				wanted = append(wanted, address)
			}
		}
	}
	if len(wanted) == 0 {
		return nil, nil
	}
	peers := make(map[netip.Addr]uint64, len(wanted))
	for _, peer := range snapshot.Peers {
		for _, prefix := range peer.Addresses {
			address := prefix.Addr().Unmap()
			if _, found := seen[address]; found && peer.ID != 0 {
				peers[address] = peer.ID
			}
		}
	}
	order := make([]uint64, 0, len(peers))
	for _, address := range wanted {
		if id, found := peers[address]; found && !slices.Contains(order, id) {
			order = append(order, id)
		}
	}
	return peers, order
}
