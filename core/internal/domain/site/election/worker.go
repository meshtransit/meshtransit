package election

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/site"
)

const (
	// PageSize is how many Sites one read returns.
	PageSize = 64
	// massSilenceTransitions and massSilenceShare: this many routers
	// turning silent within massSilenceWindow, and at least this share of
	// those known, look like Core or Redis trouble, not routers dying: their
	// silence proves nothing for up to massSilenceFreeze (design §6.2).
	massSilenceTransitions = 20
	massSilenceShare       = 0.3
	massSilenceWindow      = time.Minute
	massSilenceFreeze      = 10 * time.Minute
	// silenceConfirm is how long silence past its grace must last before it
	// counts: one regular pass, whatever wakeups ran passes in between.
	silenceConfirm = 10 * time.Second
	// wakeInterval bounds the passes wakeups run.
	wakeInterval = time.Second
	// resubscribeAfter and resubscribeMax pace a lost wakeup subscription.
	resubscribeAfter = time.Second
	resubscribeMax   = 30 * time.Second
)

var (
	// ErrInvalidWorker rejects unsafe dependencies or timing bounds.
	ErrInvalidWorker = errors.New("site election worker: invalid configuration")
	// ErrWorkerStarted rejects duplicate lifecycle ownership.
	ErrWorkerStarted = errors.New("site election worker: already started")
	// ErrWorkerNotStarted rejects shutdown before startup.
	ErrWorkerNotStarted = errors.New("site election worker: not started")
)

// RouterFacts is what the database holds about one router of a Site.
type RouterFacts struct {
	Device   node.ID
	Priority int
	Draining bool
	// Live, WorkspaceOwned and Covers decide whether the Device may serve
	// the Site at all: active and unexpired, owned by the Workspace, and
	// offering every prefix of the Site.
	Live, WorkspaceOwned, Covers bool
}

// SiteFacts is one active Site with routers.
type SiteFacts struct {
	Site     site.ID
	Failback bool
	// Primary is the elected primary (zero: none, or not elected yet) and
	// Generation its election's generation (0 before the first).
	Primary    node.ID
	Generation int64
	// Routers in priority order.
	Routers []RouterFacts
}

// Page is one page of Sites in Site order.
type Page struct {
	Sites []SiteFacts
	Done  bool
}

// Facts reads the Sites to elect for, page by page after a Site.
type Facts interface {
	List(ctx context.Context, installation deployment.ID, after site.ID, limit int) (Page, error)
}

// Decision is a primary to record, made on Generation.
type Decision struct {
	Site               site.ID
	ExpectedGeneration int64
	Primary            node.ID // zero: none
	Reason             string
}

// Recorder records a decision; false when it was made on an older state.
type Recorder interface {
	Record(ctx context.Context, installation deployment.ID, decision Decision) (bool, error)
}

// Clock is this host's time.
type Clock interface{ Now() time.Time }

// Options binds one process to an installation and its pacing.
type Options struct {
	DeploymentID                   deployment.ID
	PollInterval, OperationTimeout time.Duration
	// Wakeups, when set, subscribes to hints that a router newly reports a
	// failed Site: a pass then runs at once instead of at the next poll.
	Wakeups func(context.Context) (WakeupSubscription, error)
}

// WakeupSubscription receives wakeup hints; Receive blocks until one comes.
type WakeupSubscription interface {
	Receive(ctx context.Context) error
	Close() error
}

func (options Options) valid() bool {
	return options.DeploymentID.IsValid() && options.PollInterval >= time.Second &&
		options.PollInterval <= time.Minute && options.OperationTimeout >= 100*time.Millisecond &&
		options.OperationTimeout <= 15*time.Second
}

// trackKey names one router of one Site.
type trackKey struct {
	site   site.ID
	device node.ID
}

// track is what the worker remembers about one router of one Site across
// sweeps; it is lost when the process restarts, which only restarts the
// hold-down, silence and failback clocks. Each worker replica keeps its own:
// the hold-down and failback bounds hold per replica, and the generation
// check keeps replicas from writing over each other's decisions.
type track struct {
	failedAt     time.Time // the last failure seen; zero once recovered
	healthySince time.Time // healthy since, after failedAt
	usableSince  time.Time
	silentAt     time.Time // when silence was first seen; zero while reporting
	seen         time.Time
}

// Worker elects primaries every poll. It owns one goroutine.
type Worker struct {
	options      Options
	facts        Facts
	recorder     Recorder
	observations distribution.ObservationLoader
	clock        Clock
	logger       *slog.Logger

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan error

	// Owned by the sweep goroutine.
	tracks      map[trackKey]*track
	silences    map[node.ID]time.Time // routers that turned silent, when
	frozenUntil time.Time

	running                                             atomic.Bool
	passes, readErrors, elections, writeErrors, wakeups atomic.Uint64
}

// Measurements are identifier-free process counters.
type Measurements struct {
	Running                                             bool
	Passes, ReadErrors, Elections, WriteErrors, Wakeups uint64
}

// New constructs a stopped worker without I/O.
func New(options Options, facts Facts, recorder Recorder, observations distribution.ObservationLoader,
	clock Clock, logger *slog.Logger,
) (*Worker, error) {
	if !options.valid() || nilPort(facts) || nilPort(recorder) || nilPort(observations) || nilPort(clock) ||
		logger == nil {
		return nil, ErrInvalidWorker
	}
	return &Worker{options: options, facts: facts, recorder: recorder, observations: observations, clock: clock,
		logger: logger, tracks: map[trackKey]*track{}, silences: map[node.ID]time.Time{}}, nil
}

func nilPort(port any) bool {
	if port == nil {
		return true
	}
	value := reflect.ValueOf(port)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// Start owns cancellation separately from the caller's startup context.
func (worker *Worker) Start(ctx context.Context) error {
	if worker == nil || ctx == nil {
		return ErrInvalidWorker
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if worker.started {
		return ErrWorkerStarted
	}
	owned, cancel := context.WithCancel(context.WithoutCancel(ctx))
	worker.cancel, worker.done, worker.started = cancel, make(chan error, 1), true
	go func() {
		worker.running.Store(true)
		worker.run(owned)
		worker.running.Store(false)
		worker.done <- nil
		close(worker.done)
	}()
	return nil
}

// Done is the process-owned lifecycle join, available after Start.
func (worker *Worker) Done() <-chan error {
	if worker == nil {
		return nil
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	return worker.done
}

// Shutdown cancels the sweeps.
func (worker *Worker) Shutdown(ctx context.Context) error {
	if worker == nil || ctx == nil {
		return ErrInvalidWorker
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if !worker.started {
		return ErrWorkerNotStarted
	}
	worker.cancel()
	return nil
}

// Snapshot returns race-safe measurements.
func (worker *Worker) Snapshot() Measurements {
	if worker == nil {
		return Measurements{}
	}
	return Measurements{Running: worker.running.Load(), Passes: worker.passes.Load(),
		ReadErrors: worker.readErrors.Load(), Elections: worker.elections.Load(),
		WriteErrors: worker.writeErrors.Load(), Wakeups: worker.wakeups.Load()}
}

func (worker *Worker) run(ctx context.Context) {
	wake := make(chan struct{}, 1)
	var listening sync.WaitGroup
	if worker.options.Wakeups != nil {
		listening.Go(func() { worker.listen(ctx, wake) })
	}
	defer listening.Wait()
	timer := time.NewTimer(0)
	defer timer.Stop()
	var last time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-wake:
			worker.wakeups.Add(1)
			if wait := wakeInterval - time.Since(last); wait > 0 {
				// Too soon after a pass: run when the interval ends.
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(wait)
				continue
			}
		case <-timer.C:
		}
		worker.Sweep(ctx)
		last = time.Now()
		if ctx.Err() != nil {
			return
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(worker.options.PollInterval)
	}
}

// listen forwards wakeup hints to wake until ctx ends, subscribing again
// after a failure with a growing pause. A lost hint only delays a pass until
// the next poll.
func (worker *Worker) listen(ctx context.Context, wake chan<- struct{}) {
	pause := resubscribeAfter
	for ctx.Err() == nil {
		subscription, err := worker.options.Wakeups(ctx)
		if err == nil {
			for {
				if err = subscription.Receive(ctx); err != nil {
					break
				}
				// Only a subscription that delivers resets the pause.
				pause = resubscribeAfter
				select {
				case wake <- struct{}{}:
				default:
				}
			}
			_ = subscription.Close()
		}
		if ctx.Err() != nil {
			return
		}
		worker.logger.DebugContext(ctx, "Site election wakeups unavailable", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(pause):
		}
		pause = min(2*pause, resubscribeMax)
	}
}

// Sweep elects for every Site once.
func (worker *Worker) Sweep(ctx context.Context) {
	worker.passes.Add(1)
	now := worker.clock.Now()
	worker.freeze(now)
	seen := map[trackKey]struct{}{}
	var after site.ID
	for ctx.Err() == nil {
		readCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
		page, err := worker.facts.List(readCtx, worker.options.DeploymentID, after, PageSize)
		cancel()
		if err != nil {
			worker.readErrors.Add(1)
			worker.logger.WarnContext(ctx, "Site election deferred", "error_code", "site_election_read_failed")
			return
		}
		observations, known := worker.observe(ctx, page.Sites)
		for _, facts := range page.Sites {
			worker.elect(ctx, facts, observations, known, now, seen)
			after = facts.Site
		}
		if page.Done || len(page.Sites) == 0 {
			break
		}
	}
	// Forget routers no longer listed.
	for key := range worker.tracks {
		if _, kept := seen[key]; !kept && ctx.Err() == nil {
			delete(worker.tracks, key)
		}
	}
}

// observe reads the delivery records of every router of sites; known is
// false when Redis could not be read, so health proves nothing this sweep.
func (worker *Worker) observe(ctx context.Context, sites []SiteFacts) (map[node.ID]distribution.Observation, bool) {
	var ids []node.ID
	unique := map[node.ID]struct{}{}
	for _, facts := range sites {
		for _, router := range facts.Routers {
			if _, listed := unique[router.Device]; !listed {
				unique[router.Device] = struct{}{}
				ids = append(ids, router.Device)
			}
		}
	}
	observations := make(map[node.ID]distribution.Observation, len(ids))
	for start := 0; start < len(ids); start += distribution.MaximumObservationBatch {
		batch := ids[start:min(len(ids), start+distribution.MaximumObservationBatch)]
		readCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
		loaded, err := worker.observations.LoadObservations(readCtx, batch)
		cancel()
		if err != nil || len(loaded) != len(batch) {
			worker.readErrors.Add(1)
			return nil, false
		}
		for index, id := range batch {
			if loaded[index].IsValid() {
				observations[id] = loaded[index]
			}
		}
	}
	return observations, true
}

func (worker *Worker) elect(ctx context.Context, facts SiteFacts,
	observations map[node.ID]distribution.Observation, known bool, now time.Time, seen map[trackKey]struct{},
) {
	candidates := make([]Candidate, 0, len(facts.Routers))
	for _, router := range facts.Routers {
		key := trackKey{site: facts.Site, device: router.Device}
		seen[key] = struct{}{}
		candidates = append(candidates, worker.status(key, router, observations[router.Device], known,
			router.Device == facts.Primary, now))
	}
	primary, reason := Elect(facts.Primary, candidates, facts.Failback)
	// Without the routers' health (health counts every router usable) only
	// authority facts are certain: no failback on it.
	if (facts.Generation > 0 && primary == facts.Primary) || (!known && reason == ReasonFailback) {
		return
	}
	if reason == "" {
		reason = ReasonElected
	}
	writeCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	changed, err := worker.recorder.Record(writeCtx, worker.options.DeploymentID, Decision{
		Site: facts.Site, ExpectedGeneration: facts.Generation, Primary: primary, Reason: reason,
	})
	if err != nil {
		worker.writeErrors.Add(1)
		worker.logger.WarnContext(ctx, "Site primary not recorded", "site", facts.Site.String(),
			"error_code", "site_election_write_failed")
		return
	}
	if changed {
		worker.elections.Add(1)
		worker.logger.InfoContext(ctx, "Site primary elected", "site", facts.Site.String(),
			"primary", primary.String(), "previous", facts.Primary.String(), "reason", reason)
	}
}

// status judges one router of one Site and updates what is remembered of
// it.
func (worker *Worker) status(key trackKey, router RouterFacts, observation distribution.Observation, known,
	current bool, now time.Time,
) Candidate {
	remembered := worker.tracks[key]
	if remembered == nil {
		remembered = &track{}
		worker.tracks[key] = remembered
	}
	remembered.seen = now
	candidate := Candidate{Device: router.Device}
	switch {
	case !router.Live || !router.WorkspaceOwned || !router.Covers:
		candidate.Status = StatusIneligible
	case router.Draining:
		candidate.Status = StatusDraining
	default:
		candidate.Status, candidate.Code = worker.health(remembered, key, observation, known, current, now)
	}
	if candidate.Status == StatusUsable && known {
		if remembered.usableSince.IsZero() {
			remembered.usableSince = now
		}
		candidate.UsableFor = now.Sub(remembered.usableSince)
	} else {
		remembered.usableSince = time.Time{}
	}
	return candidate
}

// health judges what a router reports of a Site: failed, silent past its
// grace, recovering, or usable. A router that never reported health (an
// older client) is usable: missing health is no evidence. Without health
// (Redis unreadable) the current primary stays usable, and a router last
// seen failing is no target to move to.
func (worker *Worker) health(remembered *track, key trackKey, observation distribution.Observation, known,
	current bool, now time.Time,
) (Status, string) {
	if !known {
		if current || remembered.failedAt.IsZero() {
			return StatusUsable, ""
		}
		return StatusHoldDown, ""
	}
	if !observation.RouteHealthAt.IsZero() && now.Sub(observation.RouteHealthAt) > SilenceGrace {
		// Silence counts once it lasted silenceConfirm, so the sweeps in
		// between have seen how many routers turned silent with it.
		if remembered.silentAt.IsZero() {
			remembered.silentAt = now
			if _, counted := worker.silences[key.device]; !counted {
				worker.silences[key.device] = now
			}
		}
		if now.Sub(remembered.silentAt) < silenceConfirm {
			return StatusUsable, ""
		}
		if now.Before(worker.frozenUntil) {
			return StatusUsable, ""
		}
		remembered.failedAt, remembered.healthySince = now, time.Time{}
		return StatusFailed, "silent"
	}
	remembered.silentAt = time.Time{}
	reported, fresh := distribution.CurrentRouteHealth(observation, now)
	state, code := "", ""
	if fresh {
		for _, entry := range reported {
			if entry.Ref == key.site.String() {
				state, code = entry.State, entry.Code
			}
		}
	}
	if state == distribution.SiteHealthFailed {
		remembered.failedAt, remembered.healthySince = now, time.Time{}
		return StatusFailed, code
	}
	if !remembered.failedAt.IsZero() {
		if state == "" {
			return StatusHoldDown, "" // not healthy yet, only not failed
		}
		if remembered.healthySince.IsZero() {
			remembered.healthySince = now
		}
		if now.Sub(remembered.healthySince) < HoldDown {
			return StatusHoldDown, ""
		}
		remembered.failedAt, remembered.healthySince = time.Time{}, time.Time{}
	}
	return StatusUsable, ""
}

// freeze decides, before a sweep judges any router, whether silence proves
// nothing for a while: after many routers turned silent at once (design
// §6.2). It counts routers, not Sites: one router of many Sites going
// silent is one router failing.
func (worker *Worker) freeze(now time.Time) {
	for device, at := range worker.silences {
		if now.Sub(at) > massSilenceWindow {
			delete(worker.silences, device)
		}
	}
	routers := map[node.ID]struct{}{}
	for key := range worker.tracks {
		routers[key.device] = struct{}{}
	}
	if len(worker.silences) >= massSilenceTransitions &&
		float64(len(worker.silences)) >= massSilenceShare*float64(max(len(routers), 1)) &&
		now.After(worker.frozenUntil) {
		worker.frozenUntil = now.Add(massSilenceFreeze)
		worker.logger.Warn("many routers went silent at once; their silence proves nothing for a while",
			"routers", len(worker.silences), "error_code", "site_election_frozen")
	}
}
