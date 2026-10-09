package disco

import (
	"errors"
	"sync"
	"time"

	"meshtransit.net/shared/key"
)

// CallMeMaybe acceptance rules (disco-v2 §3.3, §4.4).
const (
	// MaxClockSkew bounds |now - SentAt| for an accepted CALL_ME_MAYBE.
	MaxClockSkew = 60 * time.Second
	// MinCallMeMaybeInterval bounds accepted CALL_ME_MAYBE per sender.
	MinCallMeMaybeInterval = time.Second
)

var (
	// ErrReplay reports a CALL_ME_MAYBE whose sequence is not newer than the last accepted one.
	ErrReplay = errors.New("disco: replayed call-me-maybe")
	// ErrStale reports a CALL_ME_MAYBE outside the allowed clock skew.
	ErrStale = errors.New("disco: stale call-me-maybe")
	// ErrRateLimited reports a CALL_ME_MAYBE arriving faster than allowed.
	ErrRateLimited = errors.New("disco: call-me-maybe rate limited")
)

type guardEntry struct {
	seq      uint64
	accepted time.Time
}

// ReplayGuard enforces the CALL_ME_MAYBE sequence, freshness and rate rules.
// Memory is bounded by the peers the caller admits: call Forget when a peer
// leaves the map or changes its disco key. The zero value is ready to use and
// reads the wall clock; it is safe for concurrent use.
type ReplayGuard struct {
	// Now returns the current time; nil means time.Now.
	Now func() time.Time

	mu    sync.Mutex
	peers map[key.DiscoPublic]guardEntry
}

// Accept checks m from sender and records it when it is acceptable.
func (g *ReplayGuard) Accept(sender key.DiscoPublic, m CallMeMaybe) error {
	now := time.Now()
	if g.Now != nil {
		now = g.Now()
	}
	sent := time.UnixMilli(m.SentAt)
	if skew := now.Sub(sent); skew > MaxClockSkew || skew < -MaxClockSkew {
		return ErrStale
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	last, seen := g.peers[sender]
	if seen {
		if m.Seq <= last.seq {
			return ErrReplay
		}
		if now.Sub(last.accepted) < MinCallMeMaybeInterval {
			return ErrRateLimited
		}
	}
	if g.peers == nil {
		g.peers = make(map[key.DiscoPublic]guardEntry)
	}
	g.peers[sender] = guardEntry{seq: m.Seq, accepted: now}
	return nil
}

// Forget erases the state kept for sender.
func (g *ReplayGuard) Forget(sender key.DiscoPublic) {
	g.mu.Lock()
	delete(g.peers, sender)
	g.mu.Unlock()
}

// Len returns the number of senders tracked, for tests and metrics.
func (g *ReplayGuard) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.peers)
}
