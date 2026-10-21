package mtcp

import (
	"errors"
	"sync"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
)

// A store or flush that failed because Redis could not take it is retried
// with a backoff from endpointReportInterval up to endpointRetryLimit, at
// most endpointRetryAttempts times; after that the node's next report (at
// the latest its 5-minute resend) or the connectivity resync takes over.
// Any other failure is final for that work.
const (
	endpointRetryLimit    = 30 * time.Second
	endpointRetryAttempts = 8
)

var (
	// errNoSnapshot reports a flush on a session that has no map anymore.
	errNoSnapshot = errors.New("mtcp: no map to flush endpoints for")
	// errStaleReport reports a kept report whose map stream was replaced.
	errStaleReport = errors.New("mtcp: endpoint report of a replaced map stream")
)

// endpointTimer is the part of *time.Timer the pacing uses; tests replace
// it to fire the timer when they choose.
type endpointTimer interface {
	Reset(time.Duration) bool
	Stop() bool
}

func realEndpointTimer(delay time.Duration, fire func()) endpointTimer {
	return time.AfterFunc(delay, fire)
}

// endpointReport is one validated EndpointReport, ready to store.
type endpointReport struct {
	snapshot mapsession.Snapshot
	set      node.EndpointSet
	relay    int
	report   *mtcpv1.EndpointReport // for the connectivity it carries
	attempts int                    // failed stores of this report
}

// endpointPacing paces one session's endpoint reports (mtcp-v1 §8.1) and
// keeps the latest one until it is stored and announced:
//   - a report sooner than endpointReportInterval after the last store is
//     kept and stored when the interval ends, replacing any kept before;
//   - a change Core stored but deferred is flushed when Core says it can be
//     announced;
//   - a store or flush that Redis could not take is retried with a backoff.
//
// One timer serves all three. Only one store or flush runs at a time
// (busy); mu guards the state but is never held across Redis I/O, so a
// slow Redis never blocks the session's other messages behind the lock.
// running counts claimed work, so the end of the session waits for it.
type endpointPacing struct {
	mu      sync.Mutex
	running sync.WaitGroup
	stopped bool
	busy    bool
	timer   endpointTimer
	stored  time.Time       // when the last store began
	waiting *endpointReport // the latest report not stored yet
	retryAt time.Time       // after a failed store: no store before it
	flushAt time.Time       // when a deferred change can be announced; zero for none
	// storeFailures and flushFailures count consecutive retryable
	// failures; they set the backoff and clear on success.
	storeFailures int
	flushFailures int
	flushAttempts int // failed flushes of the current deferred change
}

// endpointWork is one store or flush to run outside the lock.
type endpointWork struct {
	store *endpointReport
	flush bool
}

// report stores a report now, or keeps it until the interval since the last
// store, and any backoff after a failed one, ends.
func (conversation *conversation) report(report endpointReport) {
	pacing := &conversation.endpointPacing
	pacing.mu.Lock()
	if pacing.stopped {
		pacing.mu.Unlock()
		return
	}
	pacing.waiting = &report // a newer report replaces a kept or failed one
	work, ok := conversation.nextWorkLocked(conversation.application.now())
	pacing.mu.Unlock()
	if ok {
		conversation.runEndpointWork(work)
	}
}

// fire is the timer: it runs the work that became due.
func (conversation *conversation) fire() {
	pacing := &conversation.endpointPacing
	pacing.mu.Lock()
	work, ok := conversation.nextWorkLocked(conversation.application.now())
	pacing.mu.Unlock()
	if ok {
		conversation.runEndpointWork(work)
	}
}

// nextWorkLocked claims the work due at now, or arms the timer for the
// earliest work left. A running store or flush claims or arms when it ends.
func (conversation *conversation) nextWorkLocked(now time.Time) (endpointWork, bool) {
	pacing := &conversation.endpointPacing
	if pacing.stopped || pacing.busy {
		return endpointWork{}, false
	}
	if pacing.waiting != nil && !now.Before(conversation.storeDueLocked()) {
		report := pacing.waiting
		pacing.waiting, pacing.stored, pacing.busy = nil, now, true
		pacing.running.Add(1)
		return endpointWork{store: report}, true
	}
	if !pacing.flushAt.IsZero() && !now.Before(pacing.flushAt) {
		pacing.busy = true
		pacing.running.Add(1)
		return endpointWork{flush: true}, true
	}
	conversation.armLocked(now)
	return endpointWork{}, false
}

// storeDueLocked is when the waiting report may be stored: an interval
// after the last store, and not before the backoff of a failed one ends.
func (conversation *conversation) storeDueLocked() time.Time {
	pacing := &conversation.endpointPacing
	due := pacing.retryAt
	if !pacing.stored.IsZero() {
		if next := pacing.stored.Add(endpointReportInterval); next.After(due) {
			due = next
		}
	}
	return due
}

// runEndpointWork does a store or flush without the lock, then records the
// result and runs what is due next.
func (conversation *conversation) runEndpointWork(work endpointWork) {
	for {
		announcement, err := conversation.doEndpointWork(work)
		next, ok := conversation.finishEndpointWork(work, announcement, err)
		if !ok {
			return
		}
		work = next
	}
}

func (conversation *conversation) doEndpointWork(work endpointWork) (mapsession.EndpointAnnouncement, error) {
	ctx := conversation.session.ctx
	options := conversation.application.options
	current, ok := conversation.sink.snapshot()
	var announcement mapsession.EndpointAnnouncement
	var err error
	switch {
	case !ok && work.flush:
		err = errNoSnapshot
	case work.flush:
		announcement, err = options.Endpoints.FlushSessionEndpoints(ctx, current)
	case !ok || !sameStream(current, work.store.snapshot):
		// A rotation or a new authorization replaced the stream the report
		// was made for; the node reports again for the new one.
		err = errStaleReport
	default:
		announcement, err = options.Endpoints.ObserveSessionEndpoints(ctx, work.store.snapshot, work.store.set,
			work.store.relay, true)
		if err == nil {
			conversation.connectivity(ctx, work.store.snapshot, work.store.report, work.store.set,
				conversation.application.now())
		}
	}
	if err != nil && ctx.Err() == nil {
		options.Logger.DebugContext(ctx, "mtcp endpoint report not stored or announced", "error", err)
	}
	return announcement, err
}

func sameStream(current, reported mapsession.Snapshot) bool {
	return current.NodeID() == reported.NodeID() && current.NodeKey() == reported.NodeKey() &&
		current.SessionGeneration() == reported.SessionGeneration()
}

// finishEndpointWork records the result of a store or flush and claims the
// next work if it is already due.
func (conversation *conversation) finishEndpointWork(work endpointWork,
	announcement mapsession.EndpointAnnouncement, err error) (endpointWork, bool) {
	pacing := &conversation.endpointPacing
	pacing.mu.Lock()
	defer pacing.mu.Unlock()
	pacing.busy = false
	pacing.running.Done()
	if pacing.stopped {
		return endpointWork{}, false
	}
	now := conversation.application.now()
	if work.store != nil {
		conversation.finishStoreLocked(now, work.store, announcement, err)
	} else {
		conversation.finishFlushLocked(now, announcement, err)
	}
	return conversation.nextWorkLocked(now)
}

func (conversation *conversation) finishStoreLocked(now time.Time, report *endpointReport,
	announcement mapsession.EndpointAnnouncement, err error) {
	pacing := &conversation.endpointPacing
	switch {
	case err == nil:
		pacing.storeFailures, pacing.retryAt = 0, time.Time{}
		if announcement.Deferred {
			pacing.flushAt, pacing.flushAttempts = now.Add(announcement.RetryAfter), 0
		} else {
			pacing.flushAt = time.Time{}
		}
	case errors.Is(err, mapsession.ErrEndpointStore):
		pacing.storeFailures++
		pacing.retryAt = now.Add(endpointBackoff(pacing.storeFailures))
		report.attempts++
		if pacing.waiting == nil && report.attempts < endpointRetryAttempts {
			pacing.waiting = report // keep it until it is stored
		}
	}
	// Any other error is final: the report is dropped.
}

func (conversation *conversation) finishFlushLocked(now time.Time, announcement mapsession.EndpointAnnouncement,
	err error) {
	pacing := &conversation.endpointPacing
	switch {
	case err == nil:
		pacing.flushFailures, pacing.flushAttempts = 0, 0
		pacing.flushAt = time.Time{}
		if announcement.Deferred {
			pacing.flushAt = now.Add(announcement.RetryAfter)
		}
	case errors.Is(err, mapsession.ErrEndpointFlush) && pacing.flushAttempts+1 < endpointRetryAttempts:
		pacing.flushFailures++
		pacing.flushAttempts++
		pacing.flushAt = now.Add(endpointBackoff(pacing.flushFailures))
	default:
		// Final, or retried enough: the connectivity resync announces it.
		pacing.flushAt, pacing.flushAttempts = time.Time{}, 0
	}
}

// endpointBackoff is the delay after the given number of consecutive
// failures: endpointReportInterval, doubling up to endpointRetryLimit.
func endpointBackoff(failures int) time.Duration {
	delay := endpointReportInterval
	for range failures - 1 {
		if delay >= endpointRetryLimit {
			break
		}
		delay *= 2
	}
	return min(delay, endpointRetryLimit)
}

// armLocked sets the timer for the earliest work left, if any.
func (conversation *conversation) armLocked(now time.Time) {
	pacing := &conversation.endpointPacing
	var next time.Time
	if pacing.waiting != nil {
		next = conversation.storeDueLocked()
	}
	if !pacing.flushAt.IsZero() && (pacing.waiting == nil || pacing.flushAt.Before(next)) {
		next = pacing.flushAt
	}
	if pacing.waiting == nil && pacing.flushAt.IsZero() {
		if pacing.timer != nil {
			pacing.timer.Stop()
		}
		return
	}
	delay := max(next.Sub(now), time.Millisecond)
	if pacing.timer == nil {
		pacing.timer = conversation.application.endpointTimer(delay, conversation.fire)
		return
	}
	pacing.timer.Reset(delay)
}

// stopEndpointPacing ends the pacing when the session ends and waits for a
// store or flush already running; their endpoint timeout bounds that wait.
func (conversation *conversation) stopEndpointPacing() {
	pacing := &conversation.endpointPacing
	pacing.mu.Lock()
	pacing.stopped = true
	pacing.waiting, pacing.flushAt = nil, time.Time{}
	if pacing.timer != nil {
		pacing.timer.Stop()
	}
	pacing.mu.Unlock()
	pacing.running.Wait()
}
