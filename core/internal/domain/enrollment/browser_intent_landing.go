package enrollment

import "time"

// BrowserIntentLanding is the non-authoritative request shown after SSO.
// It contains no URL token, machine key, Node key, or Network authority.
type BrowserIntentLanding struct {
	IntentID  BrowserIntentID
	State     string
	Hostname  string
	ExpiresAt time.Time
}

// IsValid checks the intent identity, state, hostname, and expiry projection.
func (landing BrowserIntentLanding) IsValid() bool {
	return landing.IntentID.IsValid() &&
		(landing.State == "pending" || landing.State == "approved") &&
		landing.Hostname != "" && !landing.ExpiresAt.IsZero()
}
