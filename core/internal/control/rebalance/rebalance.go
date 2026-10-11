// Package rebalance spreads control sessions evenly across replicas: each
// replica publishes its session count to a shared registry and, when it
// holds clearly more than its fair share, asks a bounded number of sessions
// to reconnect (the load balancer then places them anywhere). One replica
// alone, such as a single-server install, never sheds.
package rebalance

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"math/rand/v2"
	"sync"
	"time"
)

// ErrInvalidBalancer reports a missing dependency or unsafe option.
var ErrInvalidBalancer = errors.New("rebalance: invalid balancer")

// ReplicaLoad is one replica's published session count.
type ReplicaLoad struct {
	ReplicaID string
	Sessions  int
}

// Registry stores each replica's load for a bounded time.
type Registry interface {
	// PublishLoad records replicaID's sessions until ttl passes and returns
	// every live replica's load, its own included.
	PublishLoad(ctx context.Context, replicaID string, sessions int, ttl time.Duration) ([]ReplicaLoad, error)
	// WithdrawLoad removes replicaID (it is shutting down).
	WithdrawLoad(ctx context.Context, replicaID string) error
}

// SessionPool is this replica's control sessions.
type SessionPool interface {
	Sessions() int
	// Shed asks up to count sessions to reconnect within window and returns
	// how many it asked.
	Shed(ctx context.Context, count int, window time.Duration) int
}

// Options bounds rebalancing.
type Options struct {
	ReplicaID string
	// Interval between two publications; each waits a random 0-20% longer
	// so replicas do not act in lockstep.
	Interval time.Duration
	// Shed turns shedding on; publication (for autoscaling) always runs.
	Shed bool
	// Tolerance is how far above its fair share a replica may stay, as a
	// fraction of that share; MinExcess is a floor in sessions.
	Tolerance float64
	MinExcess int
	// MaxShedFraction bounds one step's shedding as a fraction of the
	// replica's sessions (at least one session).
	MaxShedFraction float64
	// ReconnectWindow spreads the shed sessions' returns.
	ReconnectWindow time.Duration
	Logger          *slog.Logger
}

func (options Options) isValid() bool {
	return options.ReplicaID != "" && options.Interval >= time.Second && options.Interval <= 5*time.Minute &&
		options.Tolerance >= 0 && options.Tolerance <= 1 && options.MinExcess >= 0 &&
		options.MaxShedFraction > 0 && options.MaxShedFraction <= 0.5 &&
		options.ReconnectWindow >= 0 && options.ReconnectWindow <= 5*time.Minute && options.Logger != nil
}

// Plan returns how many sessions a replica holding own sessions should shed
// given every live replica's load (its own included): none unless it is
// above its fair share by more than the tolerance, then the excess over the
// fair share, bounded per step.
func Plan(own int, loads []ReplicaLoad, options Options) int {
	if len(loads) < 2 || own <= 0 {
		return 0
	}
	total := 0
	for _, load := range loads {
		total += max(load.Sessions, 0)
	}
	fair := int(math.Ceil(float64(total) / float64(len(loads))))
	allowed := fair + max(options.MinExcess, int(math.Ceil(float64(fair)*options.Tolerance)))
	if own <= allowed {
		return 0
	}
	limit := max(1, int(float64(own)*options.MaxShedFraction))
	return min(own-fair, limit)
}

// Balancer publishes this replica's load and sheds its excess. It is an
// app.Service.
type Balancer struct {
	registry Registry
	pool     SessionPool
	options  Options

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan error

	// The previous step's cluster total and whether it was over its share
	// (used by the run goroutine only).
	lastTotal int
	lastOver  bool
}

// stableTotal reports whether the cluster's session total moved by at most
// 5% (or 32 sessions) since the previous step. While it grows or shrinks
// fast (a ramp, a replica's sessions reconnecting after it stopped), other
// replicas' published loads lag by up to one interval, so a replica would
// see an imbalance that is not there.
func stableTotal(previous, current int) bool {
	if previous <= 0 {
		return false
	}
	change := current - previous
	if change < 0 {
		change = -change
	}
	return change <= max(32, current/20)
}

// New constructs a stopped balancer.
func New(registry Registry, pool SessionPool, options Options) (*Balancer, error) {
	if registry == nil || pool == nil || !options.isValid() {
		return nil, ErrInvalidBalancer
	}
	return &Balancer{registry: registry, pool: pool, options: options}, nil
}

// ttl keeps a published load past one missed publication.
func (balancer *Balancer) ttl() time.Duration { return 3 * balancer.options.Interval }

// Start publishes once synchronously, then runs the loop.
func (balancer *Balancer) Start(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidBalancer
	}
	balancer.mu.Lock()
	defer balancer.mu.Unlock()
	if balancer.done != nil {
		return ErrInvalidBalancer
	}
	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	balancer.cancel, balancer.done = cancel, make(chan error, 1)
	go func() {
		balancer.run(runCtx)
		balancer.done <- nil
		close(balancer.done)
	}()
	return nil
}

// Done returns the join channel after Start.
func (balancer *Balancer) Done() <-chan error {
	balancer.mu.Lock()
	defer balancer.mu.Unlock()
	return balancer.done
}

// Shutdown stops the loop and withdraws this replica from the registry, so
// the autoscaler and the other replicas stop counting it at once.
func (balancer *Balancer) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidBalancer
	}
	balancer.mu.Lock()
	cancel, done := balancer.cancel, balancer.done
	balancer.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return balancer.registry.WithdrawLoad(ctx, balancer.options.ReplicaID)
}

func (balancer *Balancer) run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			balancer.step(ctx)
			interval := balancer.options.Interval
			timer.Reset(interval + rand.N(interval/5+1)) //nolint:gosec // spreading needs no secrecy
		}
	}
}

// step publishes the load and sheds the excess once.
func (balancer *Balancer) step(ctx context.Context) {
	own := balancer.pool.Sessions()
	stepCtx, cancel := context.WithTimeout(ctx, balancer.options.Interval)
	defer cancel()
	loads, err := balancer.registry.PublishLoad(stepCtx, balancer.options.ReplicaID, own, balancer.ttl())
	if err != nil {
		balancer.options.Logger.WarnContext(ctx, "control load not published", "error_code", "rebalance_publish_failed",
			"error", err)
		return
	}
	if !balancer.options.Shed {
		return
	}
	total := Total(loads)
	count := Plan(own, loads, balancer.options)
	// Shed only an imbalance seen twice in a row with a steady total.
	if count > 0 && balancer.lastOver && stableTotal(balancer.lastTotal, total) {
		shed := balancer.pool.Shed(stepCtx, count, balancer.options.ReconnectWindow)
		balancer.options.Logger.InfoContext(ctx, "control sessions shed to rebalance",
			"sessions", own, "replicas", len(loads), "shed", shed)
	}
	balancer.lastTotal, balancer.lastOver = total, count > 0
}

// Total sums the loads.
func Total(loads []ReplicaLoad) int {
	total := 0
	for _, load := range loads {
		total += max(load.Sessions, 0)
	}
	return total
}
