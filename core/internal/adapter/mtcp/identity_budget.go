package mtcp

import (
	"math"
	"time"
)

// A session may send RegisterRequest and RotateNodeKey identityBurst times
// at once and identityRate per second after that (mtcp-v1 §14). Each one
// takes database locks of its whole Network even when it changes nothing,
// and nodes send one per session, so only a loop reaches the limit.
const (
	identityBurst = 4
	identityRate  = 1.0
)

// identityBudget is a token bucket, full when the session starts.
type identityBudget struct {
	spent   float64 // tokens used, recovered at identityRate
	updated time.Time
}

// spend takes one token at now, or reports how long until one is free.
func (budget *identityBudget) spend(now time.Time) (time.Duration, bool) {
	if !budget.updated.IsZero() {
		// A clock stepping back recovers nothing rather than costing tokens.
		elapsed := max(0, now.Sub(budget.updated).Seconds())
		budget.spent = max(0, budget.spent-elapsed*identityRate)
	}
	budget.updated = now
	if budget.spent+1 > identityBurst {
		return time.Duration((budget.spent + 1 - identityBurst) / identityRate * float64(time.Second)), false
	}
	budget.spent++
	return 0, true
}

// retryAfterMS converts a wait to retry_after_ms, rounded up to a whole
// second and bounded to the field.
func retryAfterMS(wait time.Duration) uint32 {
	seconds := math.Ceil(max(wait, 0).Seconds())
	return uint32(min(seconds*1000, math.MaxUint32))
}
