// Package ratelimit provides the relay's token buckets.
package ratelimit

import (
	"net/netip"
	"sync"
	"time"
)

// Bucket is a classic token bucket. It is not safe for concurrent use; its
// owner serialises access. The zero rate disables the limit.
type Bucket struct {
	rate   float64 // tokens per second; 0 disables the limit
	burst  float64
	tokens float64
	last   time.Time
}

// NewBucket returns a full bucket.
func NewBucket(rate, burst float64) Bucket {
	return Bucket{rate: rate, burst: burst, tokens: burst}
}

// SetRate changes the refill rate and burst.
func (b *Bucket) SetRate(rate, burst float64) { b.rate, b.burst = rate, burst }

// Allow takes n tokens if available.
func (b *Bucket) Allow(now time.Time, n float64) bool {
	if b.rate <= 0 {
		return true
	}
	if !b.last.IsZero() {
		if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
			b.tokens = min(b.burst, b.tokens+elapsed*b.rate)
		}
	}
	b.last = now
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

// Shared is a Bucket safe for concurrent use.
type Shared struct {
	mu     sync.Mutex
	bucket Bucket
}

// NewShared returns a full shared bucket.
func NewShared(rate, burst float64) *Shared {
	return &Shared{bucket: NewBucket(rate, burst)}
}

// Allow takes one token if available.
func (b *Shared) Allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.bucket.Allow(now, 1)
}

// SourceLimiter rate-limits by source address with bounded memory. IPv6
// sources are grouped by /64, the smallest block a host usually controls.
// When the table is full, idle entries are pruned; if none are idle, new
// sources are refused (fail closed) rather than resetting everyone's
// allowance.
type SourceLimiter struct {
	rate, burst float64
	maxSources  int
	now         func() time.Time

	mu        sync.Mutex
	sources   map[netip.Addr]*Bucket
	lastPrune time.Time
}

// NewSourceLimiter returns a limiter allowing rate events per second per
// source with the given burst, tracking at most maxSources sources.
func NewSourceLimiter(rate, burst float64, maxSources int, now func() time.Time) *SourceLimiter {
	if now == nil {
		now = time.Now
	}
	return &SourceLimiter{rate: rate, burst: burst, maxSources: maxSources, now: now, sources: make(map[netip.Addr]*Bucket)}
}

// Allow reports whether an event from src is within its rate.
func (l *SourceLimiter) Allow(src netip.Addr) bool {
	keyAddr := sourceKey(src)
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.sources[keyAddr]
	if !ok {
		if len(l.sources) >= l.maxSources && !l.pruneLocked(now) {
			return false
		}
		nb := NewBucket(l.rate, l.burst)
		b = &nb
		l.sources[keyAddr] = b
	}
	return b.Allow(now, 1)
}

// pruneLocked drops sources whose bucket has refilled (idle long enough to
// be indistinguishable from new ones). It reports whether space was freed.
func (l *SourceLimiter) pruneLocked(now time.Time) bool {
	// At most one full scan per second, so a flood of new sources cannot
	// turn every packet into an O(n) walk.
	if now.Sub(l.lastPrune) < time.Second {
		return false
	}
	l.lastPrune = now
	idle := time.Duration(l.burst / l.rate * float64(time.Second))
	for k, b := range l.sources {
		if now.Sub(b.last) > idle {
			delete(l.sources, k)
		}
	}
	return len(l.sources) < l.maxSources
}

func sourceKey(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return a
}
