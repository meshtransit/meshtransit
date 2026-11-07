package main

import (
	"testing"
	"time"

	"meshtransit.net/core/internal/platform/ratelimit"
)

// Console pages make several management reads each. One Session switching
// tabs quickly must not run out, while sign-in admission stays tight.
func TestPrivateIdentityManagementBudgetsExceedLoginBudgets(t *testing.T) {
	t.Parallel()
	session, err := ratelimit.NewPolicy(managementSessionBurst, managementSessionRefill)
	if err != nil {
		t.Fatal(err)
	}
	source, err := ratelimit.NewPolicy(managementSourceBurst, managementSourceRefill)
	if err != nil {
		t.Fatal(err)
	}
	// TD-CORE-138: QE and a fast person load pages of about ten reads each.
	if session.Capacity() < 120 || session.RefillInterval() > 200*time.Millisecond {
		t.Fatalf("management Session budget = %d per %s, want at least 120 and 5 per second",
			session.Capacity(), session.RefillInterval())
	}
	// The source budget is refunded to a valid Session, so it only has to
	// hold the valid requests in flight from one address: at most
	// managementMaxConcurrent on each of two replicas. Beyond that it bounds
	// failed authentications, so it stays near that floor.
	if source.Capacity() < 2*managementMaxConcurrent || source.Capacity() > 4*managementMaxConcurrent ||
		source.RefillInterval() < 250*time.Millisecond {
		t.Fatalf("management source budget %d per %s must hold the requests in flight and stay tight",
			source.Capacity(), source.RefillInterval())
	}
	if loginSourceBurst >= managementSourceBurst || loginStateBurst >= managementSessionBurst {
		t.Fatal("sign-in admission must stay tighter than management reads")
	}
}
