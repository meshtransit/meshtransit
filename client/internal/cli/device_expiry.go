package cli

import (
	"fmt"
	"time"
)

// renewHint tells a person how to keep the Device: signing in again renews
// one that signed in through the browser, keeping its identity and
// addresses; one enrolled with a key needs a new key.
const renewHint = "sign in again with meshctl login, or enroll with a new key, to keep this Device"

// formatDeviceExpiry describes the Device's expiry for meshctl status:
// plainly while it is far off, with a reminder once 14 days or less remain,
// and urgently on the last day.
func formatDeviceExpiry(state, expiresAt string, now time.Time) string {
	switch state {
	case "never":
		return "never"
	case "", "unknown":
		return "unknown"
	}
	at, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return state
	}
	when := at.UTC().Format("2006-01-02 15:04 UTC")
	switch state {
	case "expired":
		return fmt.Sprintf("expired %s; sign in again with meshctl login, or enroll with a new key", when)
	case "imminent":
		return fmt.Sprintf("in %s (%s); %s, now", remainingText(at.Sub(now)), when, renewHint)
	case "soon":
		return fmt.Sprintf("in %s (%s); %s", remainingText(at.Sub(now)), when, renewHint)
	default:
		return fmt.Sprintf("in %s (%s)", remainingText(at.Sub(now)), when)
	}
}

// remainingText rounds a duration down to whole days, or hours on the last
// day, or "less than an hour".
func remainingText(remaining time.Duration) string {
	switch {
	case remaining >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(remaining/(24*time.Hour)))
	case remaining >= 24*time.Hour:
		return "1 day"
	case remaining >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(remaining/time.Hour))
	case remaining >= time.Hour:
		return "1 hour"
	default:
		return "less than an hour"
	}
}
