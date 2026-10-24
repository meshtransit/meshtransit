package daemon

import (
	"reflect"
	"slices"
	"sync"
	"time"

	"meshtransit.net/client/internal/dnsconfig"
	"meshtransit.net/client/internal/networkmap"
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
	// pending is a retry scheduled and not yet succeeded.
	pending bool
}

// apply runs a map's DNS apply, cancelling any pending retry of an older map.
// A map whose DNS is the same as the one a pending retry applies (same) keeps
// that retry and its backoff instead (same is asked only then): applying it at once would ask a host
// that keeps failing every map, not every 1–30 s (TD-CLI-33). The retry
// applies the newest map. It reports whether it applied.
func (r *dnsRetry) apply(same func() bool, apply func() bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending && !r.stopped && same() {
		return false
	}
	r.cancelLocked()
	// A new map starts its retries from the shortest delay.
	r.delay = 0
	apply()
	return true
}

// schedule retries attempt after a growing delay until it succeeds, a newer
// map is applied or the session stops.
func (r *dnsRetry) schedule(attempt func() bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	// One chain at most: a retry waiting for mu starts no second one.
	delay := r.delay
	r.cancelLocked()
	r.delay = delay
	r.scheduleLocked(attempt)
}

func (r *dnsRetry) scheduleLocked(attempt func() bool) {
	if r.timer != nil {
		r.timer.Stop()
	}
	r.pending = true
	r.delay = min(max(2*r.delay, minRuntimeRetry), maxRuntimeRetry)
	generation := r.generation
	r.timer = time.AfterFunc(r.delay, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.stopped || r.generation != generation {
			return
		}
		if attempt() {
			r.delay, r.pending, r.timer = 0, false, nil
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
	r.pending = false
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
}

// sameDNS reports two maps whose DNS the node applies the same way: the
// plan they compile to and MeshTransit's infrastructure names. Only asked
// while a retry is pending, when the host keeps refusing.
func sameDNS(first, second networkmap.Snapshot, controlURL string) bool {
	firstPlan, firstErr := dnsconfig.Compile(first)
	secondPlan, secondErr := dnsconfig.Compile(second)
	if firstErr != nil || secondErr != nil {
		return false
	}
	// Every map has a new revision; what the host gets is the rest.
	firstPlan.Revision, secondPlan.Revision = 0, 0
	return reflect.DeepEqual(firstPlan, secondPlan) &&
		slices.Equal(infrastructureNames(controlURL, first), infrastructureNames(controlURL, second))
}
