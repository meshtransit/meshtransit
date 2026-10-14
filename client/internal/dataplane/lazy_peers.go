package dataplane

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/device"

	"meshtransit.net/client/internal/relay"
	"meshtransit.net/client/internal/wghandshake"
)

// Lazy peers: with more than lazyPeerThreshold map peers, wireguard-go holds
// only the peers that carry traffic. An outbound packet to a peer that is not
// installed, or a handshake initiation from one, installs it before
// wireguard-go handles the packet; peers idle for lazyIdleTimeout are removed.
const (
	lazyPeerThreshold = 1_000
	// lazyActivationWait bounds how long the packets to one peer wait for its
	// installation, together: they share one deadline. After a wait runs
	// out, packets do not wait for lazyStallBackoff, so a stalled engine
	// delays traffic by at most one wait per backoff.
	lazyActivationWait   = 250 * time.Millisecond
	lazyStallBackoff     = time.Second
	lazyIdleTimeout      = 10 * time.Minute
	lazyEvictionInterval = time.Minute
	lazyRequestQueue     = 1_024
	// lazyInitiationRate bounds the initiations read per second (one X25519
	// each, about 49 us); lazyInitiationBurst is the bucket size.
	lazyInitiationRate  = 1_000
	lazyInitiationBurst = 200
	// One source address may spend lazySourceRate checks per second, so a
	// sender that knows this node's key cannot spend the shared budget
	// alone; lazySourceLimit bounds the addresses remembered.
	lazySourceRate  = 20
	lazySourceBurst = 20
	lazySourceLimit = 4_096
)

// lazyPeer is one map peer's activity and installation state, read and
// written by the packet paths without locks. installed changes only under the
// engine's mutex and always together with the engine's installed peers.
type lazyPeer struct {
	id        uint64
	key       [32]byte
	installed atomic.Bool
	// lastActive is the unix time in nanoseconds of the last packet to or
	// from the peer through the TUN, or of its installation.
	lastActive atomic.Int64
	// activation is the installation request in flight, which every packet
	// to the peer waits on.
	activation atomic.Pointer[lazyActivation]
}

type lazyActivation struct {
	done     chan struct{}
	deadline time.Time
}

// lazyIndex maps packet addresses and keys to the peers of one applied map.
// It is immutable once published.
type lazyIndex struct {
	byID      map[uint64]*lazyPeer
	byAddr    map[netip.Addr]*lazyPeer
	byKey     map[[32]byte]*lazyPeer
	responder *wghandshake.Responder
}

// lazySession links one open device's packet paths to its activation worker.
type lazySession struct {
	requests chan lazyRequest
	closing  chan struct{}
}

type lazyRequest struct {
	peer       *lazyPeer
	activation *lazyActivation
}

// tokenBucket refills rate tokens per second up to burst.
type tokenBucket struct {
	tokens     float64
	refilledAt time.Time
}

func (b *tokenBucket) take(now time.Time, rate, burst float64) bool {
	if b.refilledAt.IsZero() {
		b.tokens = burst
	} else {
		b.tokens = min(burst, b.tokens+now.Sub(b.refilledAt).Seconds()*rate)
	}
	b.refilledAt = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// lazyPeers carries activation requests from the packet paths to the engine.
// index is nil while the engine installs every peer.
type lazyPeers struct {
	index   atomic.Pointer[lazyIndex]
	session atomic.Pointer[lazySession]
	install func(*lazyPeer)
	evict   func(time.Time)
	now     func() time.Time

	limiterMu sync.Mutex
	global    tokenBucket
	sources   map[netip.Addr]*tokenBucket
	// stalledUntil is the unix time in nanoseconds until which packets do
	// not wait for activations.
	stalledUntil atomic.Int64

	activations atomic.Uint64
	evictions   atomic.Uint64
	dropped     atomic.Uint64
}

func newLazyPeers(install func(*lazyPeer), evict func(time.Time), now func() time.Time) *lazyPeers {
	return &lazyPeers{install: install, evict: evict, now: now, sources: make(map[netip.Addr]*tokenBucket)}
}

// attach starts the activation worker for a newly opened device.
func (l *lazyPeers) attach() {
	if l == nil {
		return
	}
	session := &lazySession{requests: make(chan lazyRequest, lazyRequestQueue), closing: make(chan struct{})}
	if previous := l.session.Swap(session); previous != nil {
		close(previous.closing)
	}
	go l.run(session)
}

// detach releases every packet path waiting on the device about to close; it
// must run before the device is closed, since closing waits for those paths.
func (l *lazyPeers) detach() {
	if l == nil {
		return
	}
	if session := l.session.Swap(nil); session != nil {
		close(session.closing)
	}
}

// reset detaches the device and forgets the map's index.
func (l *lazyPeers) reset() {
	if l == nil {
		return
	}
	l.detach()
	l.index.Store(nil)
}

// counts returns the installations, evictions and dropped activations.
func (l *lazyPeers) counts() (activations, evictions, dropped uint64) {
	if l == nil {
		return 0, 0, 0
	}
	return l.activations.Load(), l.evictions.Load(), l.dropped.Load()
}

func (l *lazyPeers) run(session *lazySession) {
	ticker := time.NewTicker(lazyEvictionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-session.closing:
			return
		case request := <-session.requests:
			if !request.peer.installed.Load() {
				l.install(request.peer)
			}
			request.peer.activation.CompareAndSwap(request.activation, nil)
			close(request.activation.done)
		case <-ticker.C:
			l.evict(l.now())
		}
	}
}

// outbound runs for each outbound packet the policy allowed.
func (l *lazyPeers) outbound(packet []byte) {
	index := l.loadIndex()
	if index == nil {
		return
	}
	destination, ok := packetDestination(packet)
	if !ok {
		return
	}
	if peer := index.byAddr[destination]; peer != nil {
		l.use(peer)
	}
}

// inbound runs for each decrypted inbound packet, before the policy can
// rewrite its addresses; wireguard-go already checked its source against the
// sending peer's allowed IPs.
func (l *lazyPeers) inbound(packet []byte) {
	index := l.loadIndex()
	if index == nil {
		return
	}
	source, ok := packetSource(packet)
	if !ok {
		return
	}
	if peer := index.byAddr[source]; peer != nil {
		peer.lastActive.Store(l.now().UnixNano())
	}
}

// initiation runs for each WireGuard datagram the bind passes to
// wireguard-go. relayKey is the sender's node key when a relay authenticated
// it; source is the sender's address otherwise.
func (l *lazyPeers) initiation(packet []byte, relayKey *relay.Key, source netip.Addr) {
	index := l.loadIndex()
	if index == nil || !isInitiation(packet) {
		return
	}
	var sender [32]byte
	if relayKey != nil {
		// The relay authenticated the sender's node key; wireguard-go still
		// checks the initiation itself.
		sender = [32]byte(*relayKey)
	} else {
		// MAC1 first: only senders that know this node's public key spend
		// the rate-limited key agreement.
		if !index.responder.Addressed(packet) {
			return
		}
		if !l.allowInitiation(source) {
			l.dropped.Add(1)
			return
		}
		key, ok := index.responder.Initiator(packet)
		if !ok {
			return
		}
		sender = key
	}
	if peer := index.byKey[sender]; peer != nil {
		l.use(peer)
	}
}

// use marks peer active and, when wireguard-go does not hold it, has the
// worker install it, waiting until the request's deadline. Storing lastActive
// before loading installed pairs with eviction, which clears installed before
// it reads lastActive again: either this sees the peer uninstalled, or the
// eviction sees the activity and keeps it.
func (l *lazyPeers) use(peer *lazyPeer) {
	peer.lastActive.Store(l.now().UnixNano())
	if peer.installed.Load() {
		return
	}
	session := l.session.Load()
	if session == nil {
		return
	}
	activation := peer.activation.Load()
	if activation == nil {
		fresh := &lazyActivation{done: make(chan struct{}), deadline: time.Now().Add(lazyActivationWait)}
		if peer.activation.CompareAndSwap(nil, fresh) {
			select {
			case session.requests <- lazyRequest{peer: peer, activation: fresh}:
			default:
				peer.activation.CompareAndSwap(fresh, nil)
				l.dropped.Add(1)
				return
			}
		}
		if activation = peer.activation.Load(); activation == nil {
			return // installed meanwhile
		}
	}
	if time.Now().UnixNano() < l.stalledUntil.Load() {
		return
	}
	wait := time.Until(activation.deadline)
	if wait <= 0 {
		return
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-activation.done:
	case <-session.closing:
	case <-timer.C:
		l.stalledUntil.Store(time.Now().Add(lazyStallBackoff).UnixNano())
	}
}

// isInitiation reports whether packet has the size and type of a WireGuard
// handshake initiation.
func isInitiation(packet []byte) bool {
	return len(packet) == device.MessageInitiationSize &&
		binary.LittleEndian.Uint32(packet) == device.MessageInitiationType
}

func (l *lazyPeers) loadIndex() *lazyIndex {
	if l == nil {
		return nil
	}
	return l.index.Load()
}

// allowInitiation spends one initiation check from source's budget and the
// shared one.
func (l *lazyPeers) allowInitiation(source netip.Addr) bool {
	l.limiterMu.Lock()
	defer l.limiterMu.Unlock()
	now := l.now()
	bucket := l.sources[source]
	if bucket == nil {
		if len(l.sources) >= lazySourceLimit {
			clear(l.sources)
		}
		bucket = &tokenBucket{}
		l.sources[source] = bucket
	}
	return bucket.take(now, lazySourceRate, lazySourceBurst) &&
		l.global.take(now, lazyInitiationRate, lazyInitiationBurst)
}

// packetDestination and packetSource read the addresses of an IP packet.
func packetDestination(packet []byte) (netip.Addr, bool) {
	switch {
	case len(packet) >= 20 && packet[0]>>4 == 4:
		return netip.AddrFrom4([4]byte(packet[16:20])), true
	case len(packet) >= 40 && packet[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(packet[24:40])), true
	default:
		return netip.Addr{}, false
	}
}

func packetSource(packet []byte) (netip.Addr, bool) {
	switch {
	case len(packet) >= 20 && packet[0]>>4 == 4:
		return netip.AddrFrom4([4]byte(packet[12:16])), true
	case len(packet) >= 40 && packet[0]>>4 == 6:
		return netip.AddrFrom16([16]byte(packet[8:24])), true
	default:
		return netip.Addr{}, false
	}
}
