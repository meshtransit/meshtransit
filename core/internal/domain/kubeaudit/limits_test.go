package kubeaudit

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Each bucket bounds alone; a refusal takes from none; buckets refill.
func TestLocalLimiter(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	limits := Limits{Gateway: Rate{PerSecond: 10, Burst: 20}, Workspace: Rate{PerSecond: 20, Burst: 30},
		Replica: Rate{PerSecond: 100, Burst: 100}}
	limiter, err := NewLocalLimiter(limits, 1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := limiter.Take(t.Context(), "w", "g1", 20); !ok {
		t.Fatal("a gateway's burst was refused")
	}
	wait, ok := limiter.Take(t.Context(), "w", "g1", 1)
	if ok || wait != 100*time.Millisecond {
		t.Fatalf("over the gateway's burst: %v, %v", wait, ok)
	}
	// g2 has its own bucket, but the Workspace holds 10 more only; the
	// refusal takes nothing.
	if _, ok := limiter.Take(t.Context(), "w", "g2", 11); ok {
		t.Fatal("over the Workspace's bucket was taken")
	}
	if _, ok := limiter.Take(t.Context(), "w", "g2", 10); !ok {
		t.Fatal("the Workspace's last tokens were refused")
	}
	if _, ok := limiter.Take(t.Context(), "other", "g3", 31); ok {
		t.Fatal("more than a burst was taken")
	}
	now = now.Add(time.Second)
	if _, ok := limiter.Take(t.Context(), "w", "g1", 10); !ok {
		t.Fatal("a second's refill was refused")
	}
}

// Shared limits are divided among the replicas; the replica's own is not.
func TestLocalLimiterDividesSharedLimits(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	limiter, err := NewLocalLimiter(DefaultLimits, 4, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := limiter.Take(t.Context(), "w", "g", 500); !ok {
		t.Fatal("a quarter of the gateway's burst was refused")
	}
	if _, ok := limiter.Take(t.Context(), "w", "g", 1); ok {
		t.Fatal("past a quarter of the gateway's burst was taken")
	}
	if _, err := NewLocalLimiter(DefaultLimits, 0, time.Now); err == nil {
		t.Fatal("no replicas was taken")
	}
}

type fakeSharedBuckets struct {
	err   error
	wait  time.Duration
	taken []int
}

func (shared *fakeSharedBuckets) TakeKubernetesOperations(_ context.Context, _, _ string, n int, _ Limits) (
	time.Duration, bool, error,
) {
	if shared.err != nil {
		return 0, false, shared.err
	}
	if shared.wait > 0 {
		return shared.wait, false, nil
	}
	shared.taken = append(shared.taken, n)
	return 0, true, nil
}

// The replica's bucket is taken first and refunded when the shared ones
// refuse; while they cannot be reached, local buckets hold their share.
func TestSharedLimiter(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	limits := Limits{Gateway: Rate{PerSecond: 1000, Burst: 1000}, Workspace: Rate{PerSecond: 1000, Burst: 1000},
		Replica: Rate{PerSecond: 10, Burst: 100}}
	shared := &fakeSharedBuckets{}
	var fellBack int
	limiter, err := NewSharedLimiter(shared, limits, 4, func() time.Time { return now }, func() { fellBack++ })
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := limiter.Take(t.Context(), "w", "g", 60); !ok || len(shared.taken) != 1 {
		t.Fatal("a take within every bucket was refused")
	}
	shared.wait = 2 * time.Second
	if wait, ok := limiter.Take(t.Context(), "w", "g", 40); ok || wait != 2*time.Second {
		t.Fatalf("the shared buckets' refusal: %v, %v", wait, ok)
	}
	// The refusal gave the replica's 40 back.
	shared.wait = 0
	if _, ok := limiter.Take(t.Context(), "w", "g", 40); !ok {
		t.Fatal("the replica kept tokens the shared buckets refused")
	}
	if _, ok := limiter.Take(t.Context(), "w", "g", 1); ok {
		t.Fatal("past the replica's burst was taken")
	}
	// Redis down: a quarter of the shared limits, locally, and Redis is
	// left alone for a while.
	now = now.Add(time.Hour)
	shared.err = errors.New("redis: down")
	if _, ok := limiter.Take(t.Context(), "w", "g", 100); !ok || fellBack != 1 {
		t.Fatalf("the fallback refused within its share (fell back %d)", fellBack)
	}
	shared.err = nil
	now = now.Add(time.Second)
	limiter.replica.refundReplica(100)
	if _, ok := limiter.Take(t.Context(), "w", "g", 50); !ok || fellBack != 2 || len(shared.taken) != 2 {
		t.Fatalf("Redis was asked while left alone (fell back %d, %d shared)", fellBack, len(shared.taken))
	}
	now = now.Add(time.Hour)
	if _, ok := limiter.Take(t.Context(), "w", "g", 100); !ok || len(shared.taken) != 3 {
		t.Fatal("Redis was not asked again")
	}
	if _, ok := limiter.Take(t.Context(), "w", "g", 1); ok {
		t.Fatal("past the replica's burst was taken")
	}
	// More than a burst is refused before any bucket is touched; a
	// cancelled batch takes nothing.
	if wait, ok := limiter.Take(t.Context(), "w", "g", 1001); ok || wait != 1001*time.Millisecond {
		t.Fatalf("over a burst: %v, %v", wait, ok)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	shared.err = context.Canceled
	now = now.Add(time.Hour)
	if _, ok := limiter.Take(cancelled, "w", "g", 1); ok || fellBack != 2 {
		t.Fatalf("a cancelled batch fell back (%d)", fellBack)
	}
}
