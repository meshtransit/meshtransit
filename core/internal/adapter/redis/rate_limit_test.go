package redis

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/platform/ratelimit"
)

func TestClientValidateRateLimiterIsStructuralAndEffectFree(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		valid bool
	}{
		{name: "missing command"}, {name: "constructed command", valid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &Client{}
			calls := 0
			if test.valid {
				client.applyRateLimit = func(context.Context, string, int64, time.Duration) ([]int64, error) {
					calls++
					return nil, ErrRateLimit
				}
			}
			err := client.ValidateRateLimiter()
			if test.valid && err != nil {
				t.Fatal("constructed limiter rejected", err)
			}
			if !test.valid && !errors.Is(err, ErrInvalidOptions) {
				t.Fatal("unconstructed limiter admitted")
			}
			if calls != 0 {
				t.Fatal("structural validation performed a command")
			}
		})
	}
	var absent *Client
	if !errors.Is(absent.ValidateRateLimiter(), ErrInvalidOptions) {
		t.Fatal("nil limiter admitted")
	}
}

func TestClientAppliesSecretSafeRateLimit(t *testing.T) {
	t.Parallel()

	rawSubject := "192.0.2.10"
	subject := testRateLimitSubject(t, ratelimit.SubjectSource, rawSubject)
	policy, _ := ratelimit.NewPolicy(30, time.Second)
	ctx := t.Context()
	var gotKey string
	var gotCapacity int64
	var gotInterval time.Duration
	client := &Client{applyRateLimit: func(
		gotContext context.Context,
		key string,
		capacity int64,
		interval time.Duration,
	) ([]int64, error) {
		if gotContext != ctx {
			t.Fatal("Allow() did not propagate context")
		}
		gotKey, gotCapacity, gotInterval = key, capacity, interval
		return []int64{1, 29, 0}, nil
	}}

	decision, err := client.Allow(ctx, subject, policy)
	if err != nil || !decision.Allowed() || decision.Remaining() != 29 {
		t.Fatalf("Allow() = (%+v, %v)", decision, err)
	}
	if gotCapacity != 30 || gotInterval != time.Second ||
		!strings.HasPrefix(gotKey, managementRateLimitKeyPrefix+"source:management-v1:") ||
		strings.Contains(gotKey, rawSubject) {
		t.Fatalf("Redis arguments = (%q, %d, %s)", gotKey, gotCapacity, gotInterval)
	}
}

func TestClientReturnsDeniedRateLimitDecision(t *testing.T) {
	t.Parallel()

	client := &Client{applyRateLimit: func(
		context.Context,
		string,
		int64,
		time.Duration,
	) ([]int64, error) {
		return []int64{0, 0, 1250}, nil
	}}
	policy, _ := ratelimit.NewPolicy(5, 250*time.Millisecond)
	decision, err := client.Allow(
		t.Context(),
		testRateLimitSubject(t, ratelimit.SubjectAccountSession, "session-id"),
		policy,
	)
	if err != nil || decision.Allowed() || decision.Limit() != 5 ||
		decision.RetryAfter() != 1250*time.Millisecond {
		t.Fatalf("Allow() = (%+v, %v)", decision, err)
	}
}

func TestClientRejectsMalformedRateLimitResultsAndTransportErrors(t *testing.T) {
	t.Parallel()

	transportErr := errors.New("redis unavailable")
	tests := []struct {
		name   string
		result []int64
		err    error
		want   error
	}{
		{name: "malformed length", result: []int64{1, 1}, want: ErrRateLimit},
		{name: "malformed decision", result: []int64{0, 1, 1000}, want: ErrRateLimit},
		{name: "transport", err: transportErr, want: transportErr},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &Client{applyRateLimit: func(
				context.Context,
				string,
				int64,
				time.Duration,
			) ([]int64, error) {
				return test.result, test.err
			}}
			policy, _ := ratelimit.NewPolicy(5, time.Second)
			if _, err := client.Allow(
				t.Context(),
				testRateLimitSubject(t, ratelimit.SubjectSource, "192.0.2.10"),
				policy,
			); !errors.Is(err, test.want) {
				t.Fatalf("Allow() error = %v, want %v", err, test.want)
			}
		})
	}
}

func testRateLimitSubject(t *testing.T, kind ratelimit.SubjectKind, raw string) ratelimit.Subject {
	t.Helper()
	keyID, _ := ratelimit.NewDigestKeyID("management-v1")
	material := make([]byte, 32)
	material[31] = 1
	digester, _ := ratelimit.NewDigester(keyID, material)
	subject, err := digester.Subject(kind, raw)
	if err != nil {
		t.Fatalf("Digester.Subject() error = %v", err)
	}
	return subject
}
