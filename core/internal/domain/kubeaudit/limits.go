package kubeaudit

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// Rate is a token bucket: PerSecond tokens a second, at most Burst.
type Rate struct {
	PerSecond float64
	Burst     float64
}

func (rate Rate) valid() bool {
	return rate.PerSecond > 0 && rate.Burst >= 1 && !math.IsInf(rate.PerSecond, 0) && !math.IsInf(rate.Burst, 0)
}

// Limits are the operation limits (design §6): each gateway's, each
// Workspace's and this replica's own.
type Limits struct {
	Gateway, Workspace, Replica Rate
}

// DefaultLimits are the design's starting limits; a gateway's is the
// design's cluster limit (each gateway replica keeps its own).
var DefaultLimits = Limits{
	Gateway:   Rate{PerSecond: 200, Burst: 2000},
	Workspace: Rate{PerSecond: 1000, Burst: 10000},
	Replica:   Rate{PerSecond: 2000, Burst: 4000},
}

// maximumBuckets bounds the buckets a limiter keeps; past it, full ones are
// forgotten (a full bucket is the same as none).
const maximumBuckets = 10000

// LocalLimiter keeps the limits in this replica's memory: alone, or while
// the shared limiter cannot be reached, with the shared limits divided
// among the replicas.
type LocalLimiter struct {
	limits Limits
	now    func() time.Time

	mu         sync.Mutex
	replica    bucket
	gateways   map[string]*bucket
	workspaces map[string]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

// NewLocalLimiter keeps limits; the gateway and Workspace ones divided by
// replicas, a burst never below a full batch (review b0b3 L5).
func NewLocalLimiter(limits Limits, replicas int, now func() time.Time) (*LocalLimiter, error) {
	if !limits.Gateway.valid() || !limits.Workspace.valid() || !limits.Replica.valid() || replicas < 1 || now == nil {
		return nil, errors.New("kubeaudit: invalid limits")
	}
	share := func(rate Rate) Rate {
		return Rate{PerSecond: rate.PerSecond / float64(replicas),
			Burst: max(rate.Burst/float64(replicas), min(rate.Burst, MaximumIntents))}
	}
	limits.Gateway, limits.Workspace = share(limits.Gateway), share(limits.Workspace)
	return &LocalLimiter{limits: limits, now: now, replica: bucket{tokens: limits.Replica.Burst, at: now()},
		gateways: map[string]*bucket{}, workspaces: map[string]*bucket{}}, nil
}

// Take takes n tokens from the replica's, the Workspace's and the
// gateway's buckets, or from none; false returns how long until all three
// hold n.
func (limiter *LocalLimiter) Take(_ context.Context, workspace, gateway string, n int) (time.Duration, bool) {
	if n < 1 {
		return 0, true
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now()
	return limiter.takeLocked([]*bucket{&limiter.replica,
		limiter.bucketOf(limiter.workspaces, workspace, limiter.limits.Workspace, now),
		limiter.bucketOf(limiter.gateways, gateway, limiter.limits.Gateway, now),
	}, []Rate{limiter.limits.Replica, limiter.limits.Workspace, limiter.limits.Gateway}, n)
}

// takeLocked takes n from every bucket, each refilled at its rate, or from
// none, returning how long until all hold n.
func (limiter *LocalLimiter) takeLocked(held []*bucket, rates []Rate, n int) (time.Duration, bool) {
	now := limiter.now()
	cost := float64(n)
	var wait time.Duration
	for index, current := range held {
		current.refill(rates[index], now)
		if cost > rates[index].Burst {
			return time.Duration(float64(time.Second) * cost / rates[index].PerSecond), false
		}
		if current.tokens < cost {
			wait = max(wait, time.Duration(float64(time.Second)*(cost-current.tokens)/rates[index].PerSecond))
		}
	}
	if wait > 0 {
		return wait, false
	}
	for _, current := range held {
		current.tokens -= cost
	}
	return 0, true
}

func (current *bucket) refill(rate Rate, now time.Time) {
	if elapsed := now.Sub(current.at); elapsed > 0 {
		current.tokens = min(rate.Burst, current.tokens+elapsed.Seconds()*rate.PerSecond)
		current.at = now
	}
}

// bucketOf returns key's bucket, a full one when new; past maximumBuckets
// the full ones are forgotten first.
func (limiter *LocalLimiter) bucketOf(buckets map[string]*bucket, key string, rate Rate, now time.Time) *bucket {
	if found, ok := buckets[key]; ok {
		return found
	}
	if len(buckets) >= maximumBuckets {
		for other, kept := range buckets {
			if kept.refill(rate, now); kept.tokens >= rate.Burst {
				delete(buckets, other)
			}
		}
		// None full: forget any, the bound holds (a forgotten bucket comes
		// back full).
		for other := range buckets {
			if len(buckets) < maximumBuckets {
				break
			}
			delete(buckets, other)
		}
	}
	created := &bucket{tokens: rate.Burst, at: now}
	buckets[key] = created
	return created
}

// SharedBuckets takes operations from the Workspace's and gateway's buckets
// all replicas share, or from neither.
type SharedBuckets interface {
	TakeKubernetesOperations(ctx context.Context, workspace, gateway string, n int, limits Limits) (
		time.Duration, bool, error)
}

// SharedLimiter takes from this replica's own bucket, then from the shared
// ones (design §6). While those cannot be reached it falls back to local
// buckets holding their share, never refusing everything.
type SharedLimiter struct {
	shared   SharedBuckets
	limits   Limits
	replica  *LocalLimiter // its replica bucket only
	fallback *LocalLimiter
	// fellBack, when set, hears of each take the shared buckets missed.
	fellBack func()
	now      func() time.Time
	// skipUntil: after a failure the shared buckets are not asked for
	// sharedRetry, so a Redis that hangs does not add its timeout to every
	// batch (review b0b3b L).
	skipUntil atomic.Int64 // Unix ns
}

// sharedRetry is how long the shared buckets are left alone after they
// failed.
const sharedRetry = 5 * time.Second

// NewSharedLimiter shares limits among replicas through shared.
func NewSharedLimiter(shared SharedBuckets, limits Limits, replicas int, now func() time.Time,
	fellBack func(),
) (*SharedLimiter, error) {
	replica, err := NewLocalLimiter(limits, 1, now)
	if err != nil || shared == nil {
		return nil, errors.New("kubeaudit: invalid shared limits")
	}
	fallback, err := NewLocalLimiter(limits, replicas, now)
	if err != nil {
		return nil, err
	}
	return &SharedLimiter{shared: shared, limits: limits, replica: replica, fallback: fallback, fellBack: fellBack,
		now: now}, nil
}

// Take takes n operations from all the buckets, or from none.
func (limiter *SharedLimiter) Take(ctx context.Context, workspace, gateway string, n int) (time.Duration, bool) {
	if n < 1 {
		return 0, true
	}
	// More than a burst would never be taken: refused with the time a burst
	// takes to refill, as the local buckets do.
	for _, rate := range []Rate{limiter.limits.Workspace, limiter.limits.Gateway} {
		if float64(n) > rate.Burst {
			return time.Duration(float64(time.Second) * float64(n) / rate.PerSecond), false
		}
	}
	if wait, taken := limiter.replica.takeReplica(n); !taken {
		return wait, false
	}
	var wait time.Duration
	var taken bool
	err := errSharedSkipped
	if limiter.now().UnixNano() >= limiter.skipUntil.Load() {
		wait, taken, err = limiter.shared.TakeKubernetesOperations(ctx, workspace, gateway, n, limiter.limits)
	}
	switch {
	case err != nil && ctx.Err() != nil:
		// The batch's session ended: nothing to take.
		taken = false
	case err != nil:
		if err != errSharedSkipped {
			limiter.skipUntil.Store(limiter.now().Add(sharedRetry).UnixNano())
		}
		if limiter.fellBack != nil {
			limiter.fellBack()
		}
		wait, taken = limiter.fallback.takeShared(workspace, gateway, n)
	}
	if !taken {
		limiter.replica.refundReplica(n)
	}
	return wait, taken
}

var errSharedSkipped = errors.New("kubeaudit: shared limits skipped")

// takeReplica takes n from the replica's bucket alone.
func (limiter *LocalLimiter) takeReplica(n int) (time.Duration, bool) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	return limiter.takeLocked([]*bucket{&limiter.replica}, []Rate{limiter.limits.Replica}, n)
}

// refundReplica gives back n the shared buckets refused.
func (limiter *LocalLimiter) refundReplica(n int) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.replica.tokens = min(limiter.limits.Replica.Burst, limiter.replica.tokens+float64(n))
}

// takeShared takes n from the Workspace's and gateway's local buckets.
func (limiter *LocalLimiter) takeShared(workspace, gateway string, n int) (time.Duration, bool) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := limiter.now()
	return limiter.takeLocked([]*bucket{
		limiter.bucketOf(limiter.workspaces, workspace, limiter.limits.Workspace, now),
		limiter.bucketOf(limiter.gateways, gateway, limiter.limits.Gateway, now),
	}, []Rate{limiter.limits.Workspace, limiter.limits.Gateway}, n)
}
