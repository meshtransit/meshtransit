package dataplane

import (
	"cmp"
	"context"
	"time"
)

const (
	// helperRefreshInterval is how often meshd asks the helper again for
	// what it last requested: the helper may have restarted, or changed what
	// it installs after a network or settings change.
	helperRefreshInterval = 10 * time.Second
	helperRequestTimeout  = 5 * time.Second
	// maximumWithdrawFailures bounds the retries of an empty request: a
	// helper that keeps refusing it (an older one, or one with the feature
	// off) most likely never installed anything.
	maximumWithdrawFailures = 3
)

// helperSync keeps one kind of host configuration the helper owns, such as
// subnet routes or router forwarding, in step with what the map asks for.
// One worker goroutine sends every request, outside the engine's lock, so
// requests reach the helper in order and the last answer recorded is always
// that of the last request sent: the packet filter never admits what the
// kernel does not carry. All fields are guarded by the engine's lock.
type helperSync[T, R any] struct {
	// desired is what the current map asks for; generation advances with
	// every change of desired or of the device, so an answer to an older
	// request is never recorded.
	desired    T
	generation uint64
	// mayHold means the helper may hold something on the current device: a
	// request was sent since it opened and no empty request succeeded.
	mayHold bool
	// withdrawFailures counts empty requests failed in a row.
	withdrawFailures int
	// wake starts or prods the worker; running is true while it runs.
	wake    chan struct{}
	running bool
	// recheck asks the worker to send the unchanged request again at once:
	// the helper's answer depends on the host's networks, which changed.
	recheck bool
	// refresh overrides helperRefreshInterval in tests.
	refresh time.Duration
}

// helperExchange is how one kind of request is sent and its answer kept.
type helperExchange[T, R any] struct {
	empty func(T) bool
	equal func(T, T) bool
	clone func(T) T
	// send asks the helper, without the engine's lock.
	send func(context.Context, T) (R, error)
	// record keeps an answer and giveUp gives up withdrawing, both with the
	// engine's lock held.
	record func(T, R, error)
	giveUp func(error)
}

// setLocked records what the map asks for and has the worker send it when it
// changed.
func (h *helperSync[T, R]) setLocked(e *WireGuardEngine, desired T, exchange helperExchange[T, R]) {
	if exchange.equal(h.desired, desired) && (!exchange.empty(desired) || !h.mayHold) {
		return
	}
	h.desired = exchange.clone(desired)
	h.generation++
	if h.wake == nil {
		h.wake = make(chan struct{}, 1)
	}
	if !h.running {
		h.running = true
		go h.run(e, exchange, h.wake)
	}
	h.prodLocked()
}

// recheckLocked has the worker send the current request again now, when it
// runs: the host's networks changed.
func (h *helperSync[T, R]) recheckLocked() {
	if !h.running {
		return
	}
	h.recheck = true
	h.prodLocked()
}

func (h *helperSync[T, R]) prodLocked() {
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

// resetLocked forgets what a closed device held: the helper drops it with
// the TUN, and the next device asks again. A request in flight is answered
// for a device that is gone, so its answer is never recorded.
func (h *helperSync[T, R]) resetLocked() {
	var none T
	h.generation++
	h.desired = none
	h.withdrawFailures = 0
	if h.running {
		h.prodLocked()
	}
}

// run sends the desired state whenever it changes, and again every refresh
// while the helper may hold some. It ends once the helper holds nothing and
// nothing is desired, or the device is gone.
func (h *helperSync[T, R]) run(e *WireGuardEngine, exchange helperExchange[T, R], wake <-chan struct{}) {
	e.mu.Lock()
	interval := cmp.Or(h.refresh, helperRefreshInterval)
	e.mu.Unlock()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		e.mu.Lock()
		if e.device == nil {
			h.mayHold = false
		}
		if e.device == nil || (exchange.empty(h.desired) && !h.mayHold) {
			h.running = false
			e.mu.Unlock()
			return
		}
		requested, generation := exchange.clone(h.desired), h.generation
		h.mayHold, h.recheck = true, false
		e.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), helperRequestTimeout)
		result, err := exchange.send(ctx, requested)
		cancel()

		e.mu.Lock()
		current := h.generation == generation
		if current {
			exchange.record(requested, result, err)
			h.settleWithdrawalLocked(exchange, requested, err)
		}
		e.mu.Unlock()
		if !current {
			continue // a newer request is due at once
		}
		select {
		case <-wake:
			e.mu.Lock()
			unchanged := h.generation == generation && !h.recheck
			e.mu.Unlock()
			if unchanged {
				// Prodded without a change: wait for the refresh.
				select {
				case <-wake:
				case <-ticker.C:
				}
			}
		case <-ticker.C:
		}
	}
}

// settleWithdrawalLocked notes whether the helper still holds anything after
// an empty request, giving up after maximumWithdrawFailures failures.
func (h *helperSync[T, R]) settleWithdrawalLocked(exchange helperExchange[T, R], requested T, err error) {
	if !exchange.empty(requested) {
		h.withdrawFailures = 0
		return
	}
	if err == nil {
		h.mayHold, h.withdrawFailures = false, 0
		return
	}
	h.withdrawFailures++
	if h.withdrawFailures < maximumWithdrawFailures {
		return
	}
	h.mayHold, h.withdrawFailures = false, 0
	exchange.giveUp(err)
}
