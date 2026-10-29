package kubeproxy

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limits bound what the replica and each Device may hold (K1b design §8).
type Limits struct {
	// Per Device: connections; requests at once, not counting watches,
	// followed logs and upgrades; watches and followed logs; upgrades; and
	// requests a second with their burst.
	DeviceConnections, DeviceRequests, DeviceWatches, DeviceUpgrades int
	DeviceRate, DeviceBurst                                          float64
	// SourceHandshakes bounds new connections a second from one address.
	SourceHandshakes float64
	// Connections and Streams bound the replica: connections, and sessions
	// to the API server at once. Past half the streams, each Device keeps
	// to an even share of what is left, at least FairShareFloor.
	Connections, Streams int
}

// DefaultLimits are the design's.
func DefaultLimits() Limits {
	return Limits{DeviceConnections: 16, DeviceRequests: 64, DeviceWatches: 200, DeviceUpgrades: 8,
		DeviceRate: 50, DeviceBurst: 100, SourceHandshakes: 10, Connections: 1024, Streams: 2048}
}

func (limits Limits) valid() bool {
	return limits.DeviceConnections >= 1 && limits.DeviceRequests >= 1 && limits.DeviceWatches >= 1 &&
		limits.DeviceUpgrades >= 1 && limits.DeviceRate > 0 && limits.DeviceBurst >= 1 &&
		limits.SourceHandshakes > 0 && limits.Connections >= 1 && limits.Streams >= 1
}

const (
	// fairShareFloor is the least share of streams a Device keeps under
	// load.
	fairShareFloor = 16
	// sourceUnidentified bounds one address's connections not yet through
	// their handshake: a Device's take milliseconds, so a few never bind
	// (re-review b6b R1).
	sourceUnidentified = 4
	// maximumLimiters bounds the per-address and per-Device rate limiters
	// kept; past it they start over, which only forgives.
	maximumLimiters = 16384
)

// Reasons a request is limited, as the 429's and the metric name them.
const (
	limitConnections       = "connections"
	limitDeviceConnections = "device_connections"
	limitSourceConnections = "source_connections"
	limitUnidentified      = "unidentified"
	limitSourceUnnamed     = "source_unidentified"
	limitHandshakes        = "handshakes"
	limitRate              = "rate"
	limitRequests          = "requests"
	limitWatches           = "watches"
	limitUpgrades          = "upgrades"
	limitStreams           = "streams"
	limitFairShare         = "fair_share"
	limitMemory            = "memory"
)

// gate holds the connection and rate counts behind the limits.
type gate struct {
	limits Limits

	mu sync.Mutex
	// open counts the replica's connections; unidentified those not yet
	// named for a Device; sources each address's (review b6b N1).
	open         int
	unidentified int
	sources      map[netip.Addr]int
	pending      map[netip.Addr]int // unidentified, by address
	devices      map[string]int     // connections by Device
	handshakes   map[netip.Addr]*rate.Limiter
	rates        map[string]*rate.Limiter

	limitedMu sync.Mutex
	limited   map[string]uint64
	// unrecorded counts type A operations Core did not record, by reason.
	unrecorded map[string]uint64
}

// countUnrecorded records a type A operation Core did not record.
func (g *gate) countUnrecorded(reason string) {
	g.limitedMu.Lock()
	g.unrecorded[reason]++
	g.limitedMu.Unlock()
}

// Unrecorded counts type A operations Core did not record, by reason.
func (server *Server) Unrecorded() map[string]uint64 {
	server.gate.limitedMu.Lock()
	defer server.gate.limitedMu.Unlock()
	counted := make(map[string]uint64, len(server.gate.unrecorded))
	for reason, count := range server.gate.unrecorded {
		counted[reason] = count
	}
	return counted
}

func newGate(limits Limits) *gate {
	return &gate{limits: limits, devices: map[string]int{}, sources: map[netip.Addr]int{},
		pending:    map[netip.Addr]int{},
		handshakes: map[netip.Addr]*rate.Limiter{},
		rates:      map[string]*rate.Limiter{}, limited: map[string]uint64{}, unrecorded: map[string]uint64{}}
}

// count records a request limited.
func (g *gate) count(limit string) {
	g.limitedMu.Lock()
	g.limited[limit]++
	g.limitedMu.Unlock()
}

// Limited counts what was refused, by limit.
func (g *gate) Limited() map[string]uint64 {
	g.limitedMu.Lock()
	defer g.limitedMu.Unlock()
	counted := make(map[string]uint64, len(g.limited))
	for limit, count := range g.limited {
		counted[limit] = count
	}
	return counted
}

// accept takes a new connection from source, or names the limit it is past:
// its source's handshakes a second and open connections, the replica's
// connections, and those not yet named for a Device, a quarter of them, so
// connections that never finish a handshake cannot crowd out the Devices
// (review b6b N1). A taken one is let go with release, and identified once
// named.
func (g *gate) accept(source netip.Addr) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	limiter, ok := g.handshakes[source]
	if !ok {
		prune(g.handshakes, time.Now())
		limiter = rate.NewLimiter(rate.Limit(g.limits.SourceHandshakes), max(1, int(g.limits.SourceHandshakes)))
		g.handshakes[source] = limiter
	}
	switch {
	case !limiter.Allow():
		return limitHandshakes
	case g.sources[source] >= g.limits.DeviceConnections:
		return limitSourceConnections
	case g.pending[source] >= sourceUnidentified:
		return limitSourceUnnamed
	case g.open >= g.limits.Connections:
		return limitConnections
	case g.unidentified >= max(1, g.limits.Connections/4):
		return limitUnidentified
	}
	g.open++
	g.unidentified++
	g.sources[source]++
	g.pending[source]++
	return ""
}

// ConnectionStats are the replica's connections: open, not yet named for
// a Device, and the most one Device holds.
type ConnectionStats struct {
	Open, Unidentified, MostByDevice, Devices int
}

// Connections reports the replica's connections.
func (server *Server) Connections() ConnectionStats {
	g := server.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	stats := ConnectionStats{Open: g.open, Unidentified: g.unidentified, Devices: len(g.devices)}
	for _, count := range g.devices {
		stats.MostByDevice = max(stats.MostByDevice, count)
	}
	return stats
}

// named moves a connection from source out of those not yet named.
// The caller holds the lock.
func (g *gate) named(source netip.Addr) {
	g.unidentified--
	decrement(g.pending, source)
}

// release lets a connection from source go; unidentified: it was never
// named for a Device.
func (g *gate) release(source netip.Addr, unidentified bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.open--
	if unidentified {
		g.named(source)
	}
	decrement(g.sources, source)
}

// decrement lowers a count, dropping it at zero.
func decrement[K comparable](counts map[K]int, key K) {
	if counts[key] <= 1 {
		delete(counts, key)
		return
	}
	counts[key]--
}

// joinDevice names a connection from source for device, in one step, or
// refuses one past the Device's limit.
func (g *gate) joinDevice(device string, source netip.Addr) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.devices[device] >= g.limits.DeviceConnections {
		return false
	}
	g.devices[device]++
	g.named(source)
	return true
}

func (g *gate) leaveDevice(device string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.devices[device] <= 1 {
		delete(g.devices, device)
		return
	}
	g.devices[device]--
}

// allow takes one of a Device's requests a second.
func (g *gate) allow(device string, now time.Time) bool {
	g.mu.Lock()
	limiter, ok := g.rates[device]
	if !ok {
		prune(g.rates, now)
		limiter = rate.NewLimiter(rate.Limit(g.limits.DeviceRate), int(g.limits.DeviceBurst))
		g.rates[device] = limiter
	}
	g.mu.Unlock()
	return limiter.AllowN(now, 1)
}

// prune, at the bound, drops the limiters whose bucket is full again: their
// holders lose nothing. Only if none is does it start over (review b6b M4).
func prune[K comparable](limiters map[K]*rate.Limiter, now time.Time) {
	if len(limiters) < maximumLimiters {
		return
	}
	for held, limiter := range limiters {
		if limiter.TokensAt(now) >= float64(limiter.Burst()) {
			delete(limiters, held)
		}
	}
	if len(limiters) >= maximumLimiters {
		clear(limiters)
	}
}

// admit names the limit a new session of its Device is past, or "" when
// it may open: the Device's count of its kind, the replica's streams, and
// past half of them the Device's even share (K1b design §8). The caller
// holds the lock.
func (sessions *registry) admit(held *session, limits Limits) string {
	kinds := sessions.devices[held.device]
	switch held.kind {
	case kindRequest:
		if kinds[kindRequest] >= limits.DeviceRequests {
			return limitRequests
		}
	case kindWatch, kindStream:
		if kinds[kindWatch]+kinds[kindStream] >= limits.DeviceWatches {
			return limitWatches
		}
	case kindUpgrade:
		if kinds[kindUpgrade] >= limits.DeviceUpgrades {
			return limitUpgrades
		}
	}
	total := len(sessions.live)
	if total >= limits.Streams {
		return limitStreams
	}
	if total >= limits.Streams/2 {
		owned := 0
		for _, count := range kinds {
			owned += count
		}
		users := len(sessions.devices)
		if owned == 0 {
			users++
		}
		if owned >= max(fairShareFloor, (limits.Streams-total)/users) {
			return limitFairShare
		}
	}
	return ""
}
