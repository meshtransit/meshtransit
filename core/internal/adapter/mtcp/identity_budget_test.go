package mtcp

import (
	"testing"
	"time"
)

func TestIdentityBudget(t *testing.T) {
	t.Parallel()
	var budget identityBudget
	start := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	for attempt := range identityBurst {
		if _, ok := budget.spend(start); !ok {
			t.Fatalf("request %d of a fresh session refused", attempt+1)
		}
	}
	wait, ok := budget.spend(start)
	if ok || wait != time.Second {
		t.Fatalf("request over the burst: %s, %t; want refused for 1s", wait, ok)
	}
	// A refused request costs nothing; a token comes back each second.
	if _, ok := budget.spend(start.Add(time.Second)); !ok {
		t.Fatal("request after one second refused")
	}
	if _, ok := budget.spend(start.Add(time.Second)); ok {
		t.Fatal("two requests within one recovered token admitted")
	}
	if _, ok := budget.spend(start.Add(time.Hour)); !ok {
		t.Fatal("request after a quiet hour refused")
	}
	// A clock stepping back costs nothing.
	spent := budget.spent
	if _, ok := budget.spend(start); !ok || budget.spent != spent+1 {
		t.Fatalf("spend after the clock stepped back: spent %v, want %v", budget.spent, spent+1)
	}
}

func TestRetryAfterMS(t *testing.T) {
	t.Parallel()
	for wait, want := range map[time.Duration]uint32{
		0: 0, time.Millisecond: 1000, 40 * time.Minute: 2_400_000, -time.Second: 0,
		1 << 62: 4_294_967_295,
	} {
		if got := retryAfterMS(wait); got != want {
			t.Errorf("retryAfterMS(%s) = %d, want %d", wait, got, want)
		}
	}
}
