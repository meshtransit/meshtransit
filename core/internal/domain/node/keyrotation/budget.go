package keyrotation

import (
	"errors"
	"time"
)

// A Device changes its Node key at most RotationLimit times within
// RotationWindow (mtcp-v1 §6.3, §14). Every change advances the Network
// revision and resets the WireGuard sessions of every peer, so an
// unbounded loop on one Device would churn its whole Network. Rotation is
// operator-initiated, so a legitimate Device never comes near the limit.
const (
	RotationLimit  = 4
	RotationWindow = time.Hour
	// GatewayRotationLimit is a Kubernetes gateway's budget: it rotates its
	// keys at every start (mtcp-v1 §6.7).
	GatewayRotationLimit = 30
)

// ErrRateLimited classifies a rotation refused by the per-Device budget; the
// error also is a *RateLimitedError carrying when to retry.
var ErrRateLimited = errors.New("node key rotation: rotation budget exhausted")

// RateLimitedError reports a rotation refused by the per-Device budget.
type RateLimitedError struct {
	RetryAfter time.Duration
}

func (err *RateLimitedError) Error() string { return ErrRateLimited.Error() }

// Is matches ErrRateLimited.
func (err *RateLimitedError) Is(target error) bool { return target == ErrRateLimited }

// BudgetEpoch returns the Node-key epoch whose start the budget compares
// against for a Device at current: the oldest of the last RotationLimit
// epochs a key change created. It reports false while the Device changed its
// key fewer than RotationLimit times (epoch 1 is the registration's key).
func BudgetEpoch(current int64, gateway bool) (int64, bool) {
	limit := int64(RotationLimit)
	if gateway {
		limit = GatewayRotationLimit
	}
	epoch := current - limit + 1
	return epoch, epoch >= 2
}

// rotationWait is how long the Device must wait before another rotation at
// now, zero when the budget allows one.
func (resolution Resolution) rotationWait(now time.Time) time.Duration {
	if resolution.budgetWindowStart.IsZero() {
		return 0
	}
	return max(0, resolution.budgetWindowStart.Add(RotationWindow).Sub(now))
}

// budgetEvidenceValid reports whether the budget start is present exactly
// when an epoch is old enough to count. Its order against the current
// epoch's start is not checked: replicas' clocks may differ slightly.
func (resolution Resolution) budgetEvidenceValid() bool {
	_, counts := BudgetEpoch(resolution.nodeKeyEpoch, resolution.gateway)
	return counts != resolution.budgetWindowStart.IsZero()
}
