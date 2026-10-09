//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/platform/ratelimit"
)

func assertRedisRateLimit(ctx context.Context, t *testing.T, client *redisadapter.Client) {
	t.Helper()

	keyID, err := ratelimit.NewDigestKeyID("integration-v1")
	if err != nil {
		t.Fatalf("construct rate-limit key ID: %v", err)
	}
	material := make([]byte, 32)
	material[31] = 1
	digester, err := ratelimit.NewDigester(keyID, material)
	if err != nil {
		t.Fatalf("construct rate-limit digester: %v", err)
	}
	subject, err := digester.Subject(ratelimit.SubjectSource, "192.0.2.254")
	if err != nil {
		t.Fatalf("construct rate-limit subject: %v", err)
	}
	policy, err := ratelimit.NewPolicy(2, 5*time.Second)
	if err != nil {
		t.Fatalf("construct rate-limit policy: %v", err)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		decision, limitErr := client.Allow(ctx, subject, policy)
		if limitErr != nil {
			t.Fatalf("Redis Allow(attempt %d) error = %v", attempt, limitErr)
		}
		wantAllowed := attempt <= 2
		if decision.Allowed() != wantAllowed {
			t.Fatalf(
				"Redis Allow(attempt %d) allowed = %t, want %t",
				attempt,
				decision.Allowed(),
				wantAllowed,
			)
		}
		if !wantAllowed && decision.RetryAfter() <= 0 {
			t.Fatalf("Redis denied decision retry-after = %s", decision.RetryAfter())
		}
	}
	// A new pre-auth state kind must neither reuse the exhausted source bucket nor
	// evade its own shared counter through another digester instance/operation.
	otherDigester, err := ratelimit.NewDigester(keyID, material)
	if err != nil {
		t.Fatal(err)
	}
	state, err := digester.Subject(ratelimit.SubjectAuthTransaction, "192.0.2.254")
	if err != nil {
		t.Fatal(err)
	}
	sameState, err := otherDigester.Subject(ratelimit.SubjectAuthTransaction, "192.0.2.254")
	if err != nil || state != sameState {
		t.Fatal("same state failed cross-instance counter identity")
	}
	for attempt, candidate := range []ratelimit.Subject{state, sameState, state} {
		decision, err := client.Allow(ctx, candidate, policy)
		if err != nil || decision.Allowed() != (attempt < 2) {
			t.Fatal("exact-state shared Redis budget widened or lost isolation", err)
		}
	}
}
