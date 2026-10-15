package daemon

import (
	"sync"
	"time"
)

// dnsRetry re-applies the latest map's DNS after a failure, with backoff, so
// a host resolver that was briefly unavailable recovers without waiting for
// Core to send another map. Every apply, by the map callback or by a retry,
// runs under mu; a retry runs only if no newer map has been applied since it
// was scheduled and the session has not ended.
type dnsRetry struct {
	mu         sync.Mutex
	generation uint64
	timer      *time.Timer
	stopped    bool
	delay      time.Duration
}

// apply runs a map's DNS apply, cancelling any pending retry of an older map.
func (r *dnsRetry) apply(apply func() bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cancelLocked()
	// A new map starts its retries from the shortest delay.
	r.delay = 0
	apply()
}

// schedule retries attempt after a growing delay until it succeeds, a newer
// map is applied or the session stops.
func (r *dnsRetry) schedule(attempt func() bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	r.scheduleLocked(attempt)
}

func (r *dnsRetry) scheduleLocked(attempt func() bool) {
	r.delay = min(max(2*r.delay, minRuntimeRetry), maxRuntimeRetry)
	generation := r.generation
	r.timer = time.AfterFunc(r.delay, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.stopped || r.generation != generation {
			return
		}
		if attempt() {
			r.delay = 0
			return
		}
		r.scheduleLocked(attempt)
	})
}

// stop ends retries for good; it returns once no retry is running.
func (r *dnsRetry) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = true
	r.cancelLocked()
}

func (r *dnsRetry) cancelLocked() {
	r.generation++
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
}
