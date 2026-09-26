package oidcauth

import "time"

// authorityClockSkewAllowance bounds acceptable positive skew for timestamps
// produced by the authoritative database. It never extends an expiry deadline;
// SQL still performs the final lifecycle and authority checks on its own clock.
const authorityClockSkewAllowance = 30 * time.Second

// authorityTimeReached accepts a recent database timestamp even when the local
// process clock is behind. Zero values and timestamps beyond the fixed skew
// window remain invalid.
func authorityTimeReached(now, authorityTime time.Time) bool {
	if now.IsZero() || authorityTime.IsZero() {
		return false
	}
	return !now.Before(authorityTime) || authorityTime.Sub(now) <= authorityClockSkewAllowance
}
