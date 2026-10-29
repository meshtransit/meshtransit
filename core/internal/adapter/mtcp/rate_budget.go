package mtcp

import (
	"math"
	"time"
)

// Per-session limits on what a node sends (mtcp-v1 §14). Each is a token
// bucket, full when the session starts; a node that follows the protocol
// stays well inside every one of them.
const (
	// RegisterRequest and RotateNodeKey take database locks of the whole
	// Network even when they change nothing; nodes send one per session.
	identityBurst = 4
	identityRate  = 1.0
	// A browser approval URL is a database write, and a node asks for one
	// per sign-in (mtcp-v1 §6.2).
	browserBurst = 2
	browserRate  = 0.1
	// MapResync makes Core encode and send the whole map; a node sends at
	// most one per 10 s (mtcp-v1 §7.1), so half that leaves room for jitter.
	resyncBurst = 2
	resyncRate  = 0.2
	// EnforcementReport is a Redis write; a node sends at most one per
	// second (mtcp-v1 §8.4).
	enforcementBurst = 4
	enforcementRate  = 1.0
	// Every message, and every byte of the records that carry them, also
	// counts against the session's inbound budget.
	inboundMessageBurst = 200
	inboundMessageRate  = 50.0
	inboundByteBurst    = 1 << 20
	inboundByteRate     = 256 << 10
	// gateway.audit1 messages have their own byte budget instead of the
	// inbound one, whose overrun ends the session and its map stream (K1b0
	// §3.5): over it intents are refused limited and outcomes dropped. Four
	// times it is the ceiling, past which the session ends after all, so a
	// gateway cannot make Core decode without bound.
	auditByteBurst    = 512 << 10
	auditByteRate     = 256 << 10
	auditCeilingBurst = 4 * auditByteBurst
	auditCeilingRate  = 4 * auditByteRate
	// auditMessageFloor is the least an audit message costs, so tiny ones
	// cannot make Core decode and answer without bound (review b0b1 H2).
	auditMessageFloor = 4 << 10
)

// rateBudget is a token bucket holding burst tokens, recovered at rate per
// second.
type rateBudget struct {
	burst, rate float64
	spent       float64 // tokens used, recovered at rate
	updated     time.Time
}

func newRateBudget(burst, rate float64) rateBudget { return rateBudget{burst: burst, rate: rate} }

// spend takes cost tokens at now, or reports how long until they are free.
// A refused spend costs nothing.
func (budget *rateBudget) spend(now time.Time, cost float64) (time.Duration, bool) {
	if !budget.updated.IsZero() {
		// A clock stepping back recovers nothing rather than costing tokens.
		elapsed := max(0, now.Sub(budget.updated).Seconds())
		budget.spent = max(0, budget.spent-elapsed*budget.rate)
	}
	budget.updated = now
	if budget.spent+cost > budget.burst {
		return time.Duration((budget.spent + cost - budget.burst) / budget.rate * float64(time.Second)), false
	}
	budget.spent += cost
	return 0, true
}

// refund returns cost tokens spent on something that was not admitted.
func (budget *rateBudget) refund(cost float64) { budget.spent = max(0, budget.spent-cost) }

// retryAfterMS converts a wait to retry_after_ms, rounded up to a whole
// second and bounded to the field.
func retryAfterMS(wait time.Duration) uint32 {
	seconds := math.Ceil(max(wait, 0).Seconds())
	return uint32(min(seconds*1000, math.MaxUint32))
}
