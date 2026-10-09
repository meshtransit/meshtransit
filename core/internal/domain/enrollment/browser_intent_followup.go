package enrollment

import "time"

// BrowserIntentFollowup is current machine-bound intent state. It carries no
// URL bearer and does not grant Device registration by itself.
type BrowserIntentFollowup struct {
	IntentID              BrowserIntentID
	State                 string
	PendingRegistrationID RegistrationID
	ExpiresAt             time.Time
}

// IsValid checks the two allowed pre-completion states and their durable link.
func (followup BrowserIntentFollowup) IsValid() bool {
	if !followup.IntentID.IsValid() || followup.ExpiresAt.IsZero() {
		return false
	}
	switch followup.State {
	case "pending":
		return !followup.PendingRegistrationID.IsValid()
	case "approved":
		return followup.PendingRegistrationID.IsValid()
	default:
		return false
	}
}
