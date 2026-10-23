package dnsconfig

import (
	"net/netip"
	"sync"
	"time"
)

// Circuit breaker of a forward zone's resolvers (DNS design D1 §5.3): after
// breakerFailures failures in a row a resolver is skipped for
// breakerCooldown, so a resolver that is down does not cost every lookup
// its attempt timeout. Once the cooldown ends, one question tries it again
// (half open) while the others still skip it; a success closes it, a
// failure opens it for another cooldown.
const (
	breakerFailures = 3
	breakerCooldown = 30 * time.Second
	// breakerProbeLimit frees a half-open resolver whose trial never
	// reported, so it cannot stay skipped for good.
	breakerProbeLimit = 2 * resolverAttemptTimeout
	// maxBreakerEntries bounds the resolvers remembered; past it the
	// oldest failures are forgotten first.
	maxBreakerEntries = 1024
)

type breakerState struct {
	failures  int
	openUntil time.Time // zero: closed
	probeAt   time.Time // zero: no trial running
	touched   time.Time
}

// resolverBreaker is safe for concurrent use. Its zero value is not usable:
// use newResolverBreaker.
type resolverBreaker struct {
	mu     sync.Mutex
	now    func() time.Time
	states map[netip.AddrPort]*breakerState
}

func newResolverBreaker(now func() time.Time) *resolverBreaker {
	return &resolverBreaker{now: now, states: make(map[netip.AddrPort]*breakerState)}
}

// allow reports whether to ask resolver now. Each true is a trial the
// caller must end with record.
func (b *resolverBreaker) allow(resolver netip.AddrPort) bool {
	allowed, _ := b.allowTrial(resolver)
	return allowed
}

// allowTrial is allow, and reports whether the resolver is open and this is
// the one trial after its cooldown.
func (b *resolverBreaker) allowTrial(resolver netip.AddrPort) (allowed, trial bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, found := b.states[resolver]
	if !found || state.openUntil.IsZero() {
		return true, false
	}
	now := b.now()
	if now.Before(state.openUntil) {
		return false, false
	}
	if !state.probeAt.IsZero() && now.Sub(state.probeAt) < breakerProbeLimit {
		return false, false
	}
	state.probeAt, state.touched = now, now
	return true, true
}

// reset forgets every failure: what was learned no longer holds (a captive
// portal window closed).
func (b *resolverBreaker) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	clear(b.states)
}

// record ends one trial of resolver: nil closes its breaker, an error counts
// a failure.
func (b *resolverBreaker) record(resolver netip.AddrPort, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		delete(b.states, resolver)
		return
	}
	now := b.now()
	state, found := b.states[resolver]
	if !found {
		if len(b.states) >= maxBreakerEntries {
			b.forgetOldest()
		}
		state = &breakerState{}
		b.states[resolver] = state
	}
	trial := !state.probeAt.IsZero()
	state.failures++
	state.probeAt, state.touched = time.Time{}, now
	// It opens when the third failure arrives or a trial fails; failures of
	// questions still on their way while it is open do not extend it.
	if state.failures >= breakerFailures && (state.openUntil.IsZero() || trial || !now.Before(state.openUntil)) {
		state.openUntil = now.Add(breakerCooldown)
	}
}

// release ends a trial that never asked the resolver (the question was
// given up), without counting it.
func (b *resolverBreaker) release(resolver netip.AddrPort) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if state, found := b.states[resolver]; found {
		state.probeAt = time.Time{}
	}
}

// open reports whether resolver is being skipped now (for tests and
// diagnostics).
func (b *resolverBreaker) open(resolver netip.AddrPort) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	state, found := b.states[resolver]
	return found && !state.openUntil.IsZero() && b.now().Before(state.openUntil)
}

func (b *resolverBreaker) forgetOldest() {
	var oldest netip.AddrPort
	var oldestAt time.Time
	for resolver, state := range b.states {
		if oldestAt.IsZero() || state.touched.Before(oldestAt) {
			oldest, oldestAt = resolver, state.touched
		}
	}
	delete(b.states, oldest)
}
