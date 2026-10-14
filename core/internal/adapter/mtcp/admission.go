package mtcp

import (
	"net/netip"
	"sync"
	"time"
)

// Admission defaults (mtcp-v1 §14).
const (
	defaultHandshakeRate  = 10 // per second per source address
	defaultHandshakeBurst = 50
	maxTrackedSources     = 1 << 16
	// snapshotAllowanceSeconds is how long first maps may take while Core is
	// slow but healthy: the default map request timeout. The default
	// unauthenticated limit admits a full burst plus this long at the
	// handshake rate, so a reconnect storm from one NAT is paced by the rate
	// limit and not refused by the unauthenticated limit (150 by default).
	snapshotAllowanceSeconds = 10
	maxUnauthPerSource       = 10000
)

// defaultUnauthenticated is the unauthenticated limit for a handshake rate
// and burst (mtcp-v1 §14).
func defaultUnauthenticated(rate, burst float64) int {
	return int(min(burst+rate*snapshotAllowanceSeconds, maxUnauthPerSource))
}

// admission limits new handshakes and unauthenticated connections per
// source before any cryptography. IPv6 sources are grouped by /64.
type admission struct {
	rate, burst float64
	maxPending  int
	now         func() time.Time

	mu      sync.Mutex
	sources map[netip.Addr]*sourceState
}

type sourceState struct {
	tokens  float64
	updated time.Time
	pending int
}

func newAdmission(rate, burst float64, maxPending int, now func() time.Time) *admission {
	return &admission{rate: rate, burst: burst, maxPending: maxPending, now: now,
		sources: make(map[netip.Addr]*sourceState)}
}

func sourceKey(address netip.Addr) netip.Addr {
	address = address.Unmap()
	if address.Is6() {
		prefix, _ := address.Prefix(64)
		return prefix.Addr()
	}
	return address
}

// begin admits one handshake from address and counts it as pending until
// the returned release runs. It reports false when the source is over its
// rate or holds too many unauthenticated connections.
func (a *admission) begin(address netip.Addr) (func(), bool) {
	source := sourceKey(address)
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	state, found := a.sources[source]
	if !found {
		if len(a.sources) >= maxTrackedSources {
			a.evictLocked(now)
			if len(a.sources) >= maxTrackedSources {
				return nil, false
			}
		}
		state = &sourceState{tokens: a.burst, updated: now}
		a.sources[source] = state
	}
	state.tokens = min(a.burst, state.tokens+now.Sub(state.updated).Seconds()*a.rate)
	state.updated = now
	if state.tokens < 1 || state.pending >= a.maxPending {
		return nil, false
	}
	state.tokens--
	state.pending++
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			state.pending--
			a.mu.Unlock()
		})
	}, true
}

// evictLocked drops idle sources whose bucket has refilled.
func (a *admission) evictLocked(now time.Time) {
	for source, state := range a.sources {
		if state.pending == 0 && state.tokens+now.Sub(state.updated).Seconds()*a.rate >= a.burst {
			delete(a.sources, source)
		}
	}
}
