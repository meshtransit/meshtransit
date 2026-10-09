package main

import (
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/platform/ratelimit"
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
	if session.Capacity() < 60 || session.RefillInterval() > 200*time.Millisecond {
		t.Fatalf("management Session budget = %d per %s, want at least 60 and 5 per second",
			session.Capacity(), session.RefillInterval())
	}
	if source.Capacity() < 4*session.Capacity() || source.RefillInterval() > session.RefillInterval() {
		t.Fatalf("management source budget %d per %s must cover several Sessions behind one address",
			source.Capacity(), source.RefillInterval())
	}
	if loginSourceBurst >= managementSourceBurst || loginStateBurst >= managementSessionBurst {
		t.Fatal("sign-in admission must stay tighter than management reads")
	}
}
