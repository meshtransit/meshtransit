package certqueue

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
)

const (
	// DefaultWait is how long a session waits for the worker (§3 step 7).
	DefaultWait = 5 * time.Second
	// DefaultBackstop is how often a waiting session reads its request
	// back when no hint arrives (§14 R-H3).
	DefaultBackstop = time.Second
	// stateLifetime is how long control trusts what it read of the
	// signers; stateErrorLifetime how long a failed read is kept;
	// stateStaleLifetime how long, after a failed read, the last good one
	// still answers (review a3b Go M2).
	stateLifetime      = 10 * time.Second
	stateErrorLifetime = 2 * time.Second
	stateStaleLifetime = time.Minute
	// unavailableBase and unavailableSpread make a gateway wait 60 to 300 s
	// when no worker signs, so a long outage is not a retry storm (R-H3).
	unavailableBase   = time.Minute
	unavailableSpread = 4 * time.Minute
	// timeoutRetry and internalRetry are the waits, jittered by ±50 %
	// (R-L3), after a request still queued and after control's own trouble.
	timeoutRetry  = 2 * time.Second
	internalRetry = 5 * time.Second
	// settleTimeout bounds abandoning a request once its session ended.
	settleTimeout = 2 * time.Second
)

// Options bound the service.
type Options struct {
	Wait     time.Duration
	Backstop time.Duration
	// Queued, optional, hints the signing workers that a request waits
	// (Redis). Best effort.
	Queued func(ctx context.Context)
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Measurements are identifier-free counts for metrics.
type Measurements struct {
	Issued, Refused, Retried, Waits, Notified uint64
	Ready                                     bool
}

// Service queues gateways' requests and waits for their results. It is
// safe for concurrent use; each request runs on its caller's goroutine.
type Service struct {
	store   Store
	options Options

	stateMu         sync.Mutex
	state           SigningState // the last state read
	stateErr        error        // the last read's error, kept until stateExpires
	stateExpires    time.Time
	stateGoodAt     time.Time // when state was read; zero: never
	stateRefreshing bool

	waitersMu sync.Mutex
	waiters   map[publicid.ID]map[chan struct{}]struct{}

	issued, refused, retried, waits, notified atomic.Uint64
	ready                                     atomic.Bool
}

// New builds a service.
func New(store Store, options Options) (*Service, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	if options.Wait == 0 {
		options.Wait = DefaultWait
	}
	if options.Backstop == 0 {
		options.Backstop = DefaultBackstop
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Wait < time.Second || options.Wait > 30*time.Second || options.Backstop < 100*time.Millisecond ||
		options.Backstop > options.Wait {
		return nil, ErrInvalid
	}
	return &Service{store: store, options: options, waiters: map[publicid.ID]map[chan struct{}]struct{}{}}, nil
}

// Snapshot returns the service's counts.
func (service *Service) Snapshot() Measurements {
	return Measurements{
		Issued: service.issued.Load(), Refused: service.refused.Load(), Retried: service.retried.Load(),
		Waits: service.waits.Load(), Notified: service.notified.Load(), Ready: service.ready.Load(),
	}
}

// Available answers a retry at once when no worker can sign, from what
// was read of the signers, before a session spends anything on a request
// (review a3b Go L4). ok is true when a worker signs.
func (service *Service) Available(ctx context.Context) (Result, bool) {
	state, err := service.signingState(ctx)
	switch {
	case err != nil:
		return retry(ReasonInternal, jitter(internalRetry)), false
	case !state.Ready():
		// Nothing is queued while no worker signs (§14 R-H3).
		return retry(ReasonUnavailable, unavailableBase+random(unavailableSpread)), false
	}
	return Result{}, true
}

// Request queues a gateway's request and waits, at most the service's
// wait, for the worker to settle it. When ctx ends first (the session
// ended) the request is abandoned and the zero Result returned.
func (service *Service) Request(ctx context.Context, request Request) Result {
	result := service.request(ctx, request)
	switch result.Outcome {
	case OutcomeIssued:
		service.issued.Add(1)
	case OutcomeRefused:
		service.refused.Add(1)
	case OutcomeRetry:
		service.retried.Add(1)
	}
	return result
}

func (service *Service) request(ctx context.Context, request Request) Result {
	if result, ok := service.Available(ctx); !ok {
		return result
	}
	stored, err := service.store.Enqueue(ctx, request)
	switch {
	case errors.Is(err, ErrNotProven):
		return refuse(ReasonNotProven, 0)
	case err != nil:
		return retry(ReasonInternal, jitter(internalRetry))
	}
	if result, settled := answer(stored); settled {
		return result
	}
	return service.wait(ctx, stored)
}

// answer turns a stored request into a gateway's answer, unless it still
// waits for a worker.
func answer(stored Stored) (Result, bool) {
	switch stored.State {
	case StateIssued:
		return Result{Outcome: OutcomeIssued, Issued: stored}, true
	case StateRefused:
		return refuse(stored.Reason, 0), true
	case StateConflict:
		return refuse(ReasonConflict, 0), true
	case StateLimited:
		reason := stored.Reason
		if reason != ReasonOverloaded {
			reason = ReasonLimited
		}
		// Never sooner than the limit says (review a3b Go L2).
		return retry(reason, later(stored.RetryAfter)), true
	case StatePending, StateClaimed, StateAbandoned:
		return Result{}, false
	}
	return retry(ReasonInternal, jitter(internalRetry)), true
}

// wait waits for a hint that the request settled, or reads it back every
// backstop, until the wait ends: then the request stays queued (a worker
// may sign it meanwhile) and the gateway sends it again, finding it. Only a
// session that ended abandons its request: abandoning at the deadline would
// take a request back from the worker under a backlog, and from a newer
// session of the gateway that waits for it too (review a3b Go M3).
func (service *Service) wait(ctx context.Context, stored Stored) Result {
	if !stored.Request.IsValid() || !stored.Device.IsValid() {
		return retry(ReasonInternal, jitter(internalRetry))
	}
	service.waits.Add(1)
	notify := service.register(stored.Request)
	defer service.unregister(stored.Request, notify)
	deadline := time.NewTimer(service.options.Wait)
	defer deadline.Stop()
	backstop := time.NewTicker(service.options.Backstop)
	defer backstop.Stop()
	if service.options.Queued != nil {
		service.options.Queued(ctx)
	}
	for {
		select {
		case <-ctx.Done():
			// Nobody is left to answer: the request makes room.
			abandonCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), settleTimeout)
			_, _, _ = service.store.Abandon(abandonCtx, stored.Device, stored.Request)
			cancel()
			return Result{}
		case <-deadline.C:
			return retry(ReasonTimeout, jitter(timeoutRetry))
		case <-notify:
		case <-backstop.C:
		}
		current, found, err := service.store.Read(ctx, stored.Device, stored.Request)
		if err != nil && ctx.Err() == nil {
			continue
		}
		if err == nil && !found {
			return retry(ReasonInternal, jitter(internalRetry))
		}
		if err == nil {
			if result, settled := answer(current); settled {
				return result
			}
			if current.State == StateAbandoned {
				// An earlier session of the gateway ended: sending the
				// request again makes it wait again.
				return retry(ReasonTimeout, jitter(timeoutRetry))
			}
		}
	}
}

// Settled wakes the sessions waiting for request: a worker settled it.
func (service *Service) Settled(request publicid.ID) {
	service.waitersMu.Lock()
	defer service.waitersMu.Unlock()
	for notify := range service.waiters[request] {
		select {
		case notify <- struct{}{}:
		default:
		}
	}
	service.notified.Add(1)
}

func (service *Service) register(request publicid.ID) chan struct{} {
	notify := make(chan struct{}, 1)
	service.waitersMu.Lock()
	defer service.waitersMu.Unlock()
	if service.waiters[request] == nil {
		service.waiters[request] = map[chan struct{}]struct{}{}
	}
	service.waiters[request][notify] = struct{}{}
	return notify
}

func (service *Service) unregister(request publicid.ID, notify chan struct{}) {
	service.waitersMu.Lock()
	defer service.waitersMu.Unlock()
	delete(service.waiters[request], notify)
	if len(service.waiters[request]) == 0 {
		delete(service.waiters, request)
	}
}

// signingState reads whether a worker signs at most every 10 s, one read
// at a time: requests arriving meanwhile use the last state read. The read
// does not end with the session that triggered it, and a failed read keeps
// answering with the last good state for a minute (review a3b Go M2).
func (service *Service) signingState(ctx context.Context) (SigningState, error) {
	service.stateMu.Lock()
	now := service.options.Now()
	if now.Before(service.stateExpires) || service.stateRefreshing {
		state, err := service.state, service.stateErr
		if service.stateRefreshing && service.stateGoodAt.IsZero() {
			err = errStateUnknown
		}
		service.stateMu.Unlock()
		return state, err
	}
	service.stateRefreshing = true
	service.stateMu.Unlock()

	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stateErrorLifetime)
	state, err := service.store.SigningState(readCtx)
	cancel()

	service.stateMu.Lock()
	defer service.stateMu.Unlock()
	service.stateRefreshing = false
	now = service.options.Now()
	if err != nil {
		service.stateExpires = now.Add(stateErrorLifetime)
		if !service.stateGoodAt.IsZero() && now.Sub(service.stateGoodAt) < stateStaleLifetime {
			service.stateErr = nil
			return service.state, nil
		}
		service.stateErr = err
		service.ready.Store(false)
		return SigningState{}, err
	}
	service.state, service.stateErr, service.stateGoodAt = state, nil, now
	service.stateExpires = now.Add(stateLifetime)
	service.ready.Store(state.Ready())
	return state, nil
}

// errStateUnknown: the first read of the signers is still running.
var errStateUnknown = errors.New("kubernetes certificate queue: signing state not read yet")

func retry(reason string, after time.Duration) Result {
	return Result{Outcome: OutcomeRetry, Reason: reason, RetryAfter: after}
}

func refuse(reason string, after time.Duration) Result {
	if reason == "" {
		reason = ReasonInternal
	}
	return Result{Outcome: OutcomeRefused, Reason: reason, RetryAfter: after}
}

// jitter spreads a wait over half to one and a half of it (§14 R-L3).
func jitter(wait time.Duration) time.Duration {
	if wait <= 0 {
		wait = timeoutRetry
	}
	return wait/2 + random(wait)
}

// later spreads a wait over one to one and a half of it: never sooner.
func later(wait time.Duration) time.Duration {
	if wait <= 0 {
		wait = timeoutRetry
	}
	return wait + random(wait/2)
}

// Jittered spreads a wait over half to one and a half of it, for callers
// outside the package (review a3b Go L1).
func Jittered(wait time.Duration) time.Duration { return jitter(wait) }

// random is uniform in [0, spread).
func random(spread time.Duration) time.Duration {
	if spread <= 0 {
		return 0
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(spread)))
	if err != nil {
		return spread / 2
	}
	return time.Duration(value.Int64())
}
