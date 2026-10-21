package primaryelection

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
)

const (
	// PageSize is how many groups one read returns.
	PageSize = 64
	// massSilenceTransitions and massSilenceShare: this many members turning
	// silent within massSilenceWindow, and at least this share of those
	// known, look like Core or Redis trouble, not members dying: their
	// silence proves nothing for up to massSilenceFreeze (subnet router
	// design §6.2).
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
	ErrInvalidWorker = errors.New("primary election worker: invalid configuration")
	// ErrWorkerStarted rejects duplicate lifecycle ownership.
	ErrWorkerStarted = errors.New("primary election worker: already started")
	// ErrWorkerNotStarted rejects shutdown before startup.
	ErrWorkerNotStarted = errors.New("primary election worker: not started")
)

// MemberFacts is what the database holds about one member of a group.
type MemberFacts struct {
	Device   node.ID
	Priority int
	Draining bool
	// Eligible decides whether the Device may serve the group at all: for a
	// router, active and unexpired, owned by the Workspace and offering
	// every prefix of the Site; for an exit node, offering to be one.
	Eligible bool
}

// GroupFacts is one active group with members.
type GroupFacts struct {
	// Group is the group's public ID, as its members report health of it.
	Group    string
	Failback bool
	// Primary is the elected primary (zero: none, or not elected yet) and
	// Generation its election's generation (0 before the first).
	Primary    node.ID
	Generation int64
	// Members in priority order.
	Members []MemberFacts
	// Spread groups also have a serving set (exit node design §16): Serving
	// is the set now (empty before its first election), ServingGeneration
	// its election's generation (0 before the first) and ServingChangedAt
	// when it last changed.
	Spread            bool
	Serving           []node.ID
	ServingGeneration int64
	ServingChangedAt  time.Time
	// ServingReason is why the set last changed and ServingPrevious the set
	// before: every replica holds back members that left overloaded.
	ServingReason   string
	ServingPrevious []node.ID
}

// Page is one page of groups in group order.
type Page struct {
	Groups []GroupFacts
	Done   bool
}

// Facts reads the groups to elect for, page by page after a group.
type Facts interface {
	List(ctx context.Context, installation deployment.ID, after string, limit int) (Page, error)
}

// Decision is a primary to record, made on ExpectedGeneration.
type Decision struct {
	Group              string
	ExpectedGeneration int64
	Primary            node.ID // zero: none
	Reason             string
}

// Recorder records a decision; false when it was made on an older state.
type Recorder interface {
	Record(ctx context.Context, installation deployment.ID, decision Decision) (bool, error)
}

// Report is what a member last reported of a group: when it last reported
// health at all (zero: never), and, while its report is fresh, the state
// and code it gave for the group (empty state: nothing for the group).
type Report struct {
	ReportedAt  time.Time
	State, Code string
}

// HealthReader reads a member's report of one group from its delivery
// record.
type HealthReader func(observation distribution.Observation, group string, now time.Time) Report

// Clock is this host's time.
type Clock interface{ Now() time.Time }

// Options binds one process to an installation, what it elects and its
// pacing.
type Options struct {
	DeploymentID                   deployment.ID
	PollInterval, OperationTimeout time.Duration
	// Health reads members' reports; required.
	Health HealthReader
	// Label names the groups in logs ("Site", "Exit Pool"), Key their log
	// attribute ("site", "exit_pool") and Code the prefix of error codes
	// ("site_election").
	Label, Key, Code string
	// Wakeups, when set, subscribes to hints that a member newly reports a
	// failed group: a pass then runs at once instead of at the next poll.
	Wakeups func(context.Context) (WakeupSubscription, error)
	// Overloaded, when set, says which health codes of a degraded member
	// take it out of a spread group's serving set.
	Overloaded func(code string) bool
	// Serving elects spread groups' serving sets
	// (MESHTRANSIT_EXIT_SPREAD_ENABLED); off, they are left as they are.
	Serving bool
}

// WakeupSubscription receives wakeup hints; Receive blocks until one comes.
type WakeupSubscription interface {
	Receive(ctx context.Context) error
	Close() error
}

func (options Options) valid() bool {
	return options.DeploymentID.IsValid() && options.PollInterval >= time.Second &&
		options.PollInterval <= time.Minute && options.OperationTimeout >= 100*time.Millisecond &&
		options.OperationTimeout <= 15*time.Second && options.Health != nil &&
		options.Label != "" && options.Key != "" && options.Code != ""
}

// trackKey names one member of one group.
type trackKey struct {
	group  string
	device node.ID
}

// track is what the worker remembers about one member of one group across
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
	// overloadedSince is when the member began reporting overload; zero
	// while it reports none.
	overloadedSince time.Time
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
	silences    map[node.ID]time.Time // members that turned silent, when
	frozenUntil time.Time

	running                                             atomic.Bool
	passes, readErrors, elections, writeErrors, wakeups atomic.Uint64
	// tally is the group and member health of the last complete sweep that
	// could read the members' health.
	tally atomic.Pointer[Tally]
}

// Measurements are identifier-free process counters and the health counts
// of the last complete sweep.
type Measurements struct {
	Running                                             bool
	Passes, ReadErrors, Elections, WriteErrors, Wakeups uint64
	// Tally is nil until a sweep has completed with health known.
	Tally *Tally
}

// Tally counts groups by how well their members can serve them and members
// by status, over one sweep.
type Tally struct {
	// GroupsServed have a member that can serve them now.
	GroupsServed uint64
	// GroupsDegraded have members, none of which can serve now (failed,
	// recovering or draining).
	GroupsDegraded uint64
	// GroupsUnserved have no member the group can use at all.
	GroupsUnserved uint64
	// Members counts member entries (one member of one group) by status.
	Members map[Status]uint64
}

func (tally *Tally) add(candidates []Candidate) {
	best := StatusIneligible
	for _, candidate := range candidates {
		tally.Members[candidate.Status]++
		best = min(best, candidate.Status)
	}
	switch best {
	case StatusUsable:
		tally.GroupsServed++
	case StatusIneligible:
		tally.GroupsUnserved++
	default:
		tally.GroupsDegraded++
	}
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
		WriteErrors: worker.writeErrors.Load(), Wakeups: worker.wakeups.Load(), Tally: worker.tally.Load()}
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
		worker.logger.DebugContext(ctx, worker.options.Label+" election wakeups unavailable", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(pause):
		}
		pause = min(2*pause, resubscribeMax)
	}
}

// Sweep elects for every group once.
func (worker *Worker) Sweep(ctx context.Context) {
	worker.passes.Add(1)
	now := worker.clock.Now()
	worker.freeze(now)
	seen := map[trackKey]struct{}{}
	tally := &Tally{Members: map[Status]uint64{}}
	healthKnown := true
	after := ""
	for ctx.Err() == nil {
		readCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
		page, err := worker.facts.List(readCtx, worker.options.DeploymentID, after, PageSize)
		cancel()
		if err != nil {
			worker.readErrors.Add(1)
			worker.logger.WarnContext(ctx, worker.options.Label+" election deferred",
				"error_code", worker.options.Code+"_read_failed")
			return
		}
		observations, known := worker.observe(ctx, page.Groups)
		healthKnown = healthKnown && known
		for _, facts := range page.Groups {
			tally.add(worker.elect(ctx, facts, observations, known, now, seen))
			after = facts.Group
		}
		if page.Done || len(page.Groups) == 0 {
			break
		}
	}
	if ctx.Err() == nil && healthKnown {
		worker.tally.Store(tally)
	}
	// Forget members no longer listed.
	for key := range worker.tracks {
		if _, kept := seen[key]; !kept && ctx.Err() == nil {
			delete(worker.tracks, key)
		}
	}
}

// observe reads the delivery records of every member of groups; known is
// false when Redis could not be read, so health proves nothing this sweep.
func (worker *Worker) observe(ctx context.Context, groups []GroupFacts) (map[node.ID]distribution.Observation, bool) {
	var ids []node.ID
	unique := map[node.ID]struct{}{}
	for _, facts := range groups {
		for _, member := range facts.Members {
			if _, listed := unique[member.Device]; !listed {
				unique[member.Device] = struct{}{}
				ids = append(ids, member.Device)
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

func (worker *Worker) elect(ctx context.Context, facts GroupFacts,
	observations map[node.ID]distribution.Observation, known bool, now time.Time, seen map[trackKey]struct{},
) []Candidate {
	candidates := make([]Candidate, 0, len(facts.Members))
	for _, member := range facts.Members {
		key := trackKey{group: facts.Group, device: member.Device}
		seen[key] = struct{}{}
		candidates = append(candidates, worker.status(key, member, observations[member.Device], known,
			member.Device == facts.Primary, now))
	}
	worker.electPrimary(ctx, facts, candidates, known)
	if facts.Spread && known && worker.options.Serving {
		worker.electServing(ctx, facts, candidates, observations, now)
	}
	return candidates
}

// electPrimary records a group's primary when it changed.
func (worker *Worker) electPrimary(ctx context.Context, facts GroupFacts, candidates []Candidate, known bool) {
	primary, reason := Elect(facts.Primary, candidates, facts.Failback)
	// Without the members' health (health counts every member usable) only
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
		Group: facts.Group, ExpectedGeneration: facts.Generation, Primary: primary, Reason: reason,
	})
	if err != nil {
		worker.writeErrors.Add(1)
		worker.logger.WarnContext(ctx, worker.options.Label+" primary not recorded", worker.options.Key,
			facts.Group, "error_code", worker.options.Code+"_write_failed")
		return
	}
	if changed {
		worker.elections.Add(1)
		worker.logger.InfoContext(ctx, worker.options.Label+" primary elected", worker.options.Key, facts.Group,
			"primary", primary.String(), "previous", facts.Primary.String(), "reason", reason)
	}
}

// electServing records a spread group's serving set when it changed, at
// most once every ServingChangeSpacing. It runs only on known health: an
// unreadable Redis changes nothing.
func (worker *Worker) electServing(ctx context.Context, facts GroupFacts, candidates []Candidate,
	observations map[node.ID]distribution.Observation, now time.Time,
) {
	recorder, records := worker.recorder.(ServingRecorder)
	if !records {
		return
	}
	// Members the last change took out overloaded are held back until
	// RecoveredAfter, as every replica reads it from the database.
	var leftOverloaded []node.ID
	if facts.ServingReason == ServingOverloaded {
		for _, device := range facts.ServingPrevious {
			if !slices.Contains(facts.Serving, device) {
				leftOverloaded = append(leftOverloaded, device)
			}
		}
	}
	heldUntil := facts.ServingChangedAt.Add(RecoveredAfter)
	members := make([]ServingCandidate, 0, len(candidates))
	for index, candidate := range candidates {
		member := facts.Members[index]
		remembered := worker.tracks[trackKey{group: facts.Group, device: member.Device}]
		overloaded, reporting := worker.overload(remembered, candidate, observations[member.Device], facts.Group, now)
		left := slices.Contains(leftOverloaded, member.Device)
		members = append(members, ServingCandidate{Device: member.Device, Priority: member.Priority,
			Status: candidate.Status, UsableFor: candidate.UsableFor, Overloaded: overloaded, Reporting: reporting,
			HeldBack: left && now.Before(heldUntil), Recovered: left && !now.Before(heldUntil)})
	}
	serving, reason, changed := ElectServing(facts.Serving, members)
	if !changed || (!facts.ServingChangedAt.IsZero() && now.Sub(facts.ServingChangedAt) < ServingChangeSpacing) {
		return
	}
	writeCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	recorded, err := recorder.RecordServing(writeCtx, worker.options.DeploymentID, ServingDecision{
		Group: facts.Group, ExpectedGeneration: facts.ServingGeneration, Devices: serving, Reason: reason,
	})
	if err != nil {
		worker.writeErrors.Add(1)
		worker.logger.WarnContext(ctx, worker.options.Label+" serving set not recorded", worker.options.Key,
			facts.Group, "error_code", worker.options.Code+"_serving_write_failed")
		return
	}
	if recorded {
		worker.elections.Add(1)
		worker.logger.InfoContext(ctx, worker.options.Label+" serving set elected", worker.options.Key,
			facts.Group, "members", len(serving), "reason", reason)
	}
}

// overload judges whether a member reports overload now (reporting) and
// has for OverloadedAfter (overloaded).
func (worker *Worker) overload(remembered *track, candidate Candidate, observation distribution.Observation,
	group string, now time.Time,
) (overloaded, reporting bool) {
	if remembered == nil || worker.options.Overloaded == nil {
		return false, false
	}
	report := worker.options.Health(observation, group, now)
	reporting = candidate.Status == StatusUsable && report.State == distribution.SiteHealthDegraded &&
		worker.options.Overloaded(report.Code)
	if !reporting {
		remembered.overloadedSince = time.Time{}
		return false, false
	}
	if remembered.overloadedSince.IsZero() {
		remembered.overloadedSince = now
	}
	return now.Sub(remembered.overloadedSince) >= OverloadedAfter, true
}

// status judges one member of one group and updates what is remembered of
// it.
func (worker *Worker) status(key trackKey, member MemberFacts, observation distribution.Observation, known,
	current bool, now time.Time,
) Candidate {
	remembered := worker.tracks[key]
	if remembered == nil {
		remembered = &track{}
		worker.tracks[key] = remembered
	}
	remembered.seen = now
	candidate := Candidate{Device: member.Device}
	switch {
	case !member.Eligible:
		candidate.Status = StatusIneligible
	case member.Draining:
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

// health judges what a member reports of a group: failed, silent past its
// grace, recovering, or usable. A member that never reported health (an
// older client) is usable: missing health is no evidence. Without health
// (Redis unreadable) the current primary stays usable, and a member last
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
	report := worker.options.Health(observation, key.group, now)
	if !report.ReportedAt.IsZero() && now.Sub(report.ReportedAt) > SilenceGrace {
		// Silence counts once it lasted silenceConfirm, so the sweeps in
		// between have seen how many members turned silent with it.
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
	if report.State == distribution.SiteHealthFailed {
		remembered.failedAt, remembered.healthySince = now, time.Time{}
		return StatusFailed, report.Code
	}
	if !remembered.failedAt.IsZero() {
		if report.State == "" {
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

// freeze decides, before a sweep judges any member, whether silence proves
// nothing for a while: after many members turned silent at once. It counts
// members, not groups: one member of many groups going silent is one member
// failing.
func (worker *Worker) freeze(now time.Time) {
	for device, at := range worker.silences {
		if now.Sub(at) > massSilenceWindow {
			delete(worker.silences, device)
		}
	}
	members := map[node.ID]struct{}{}
	for key := range worker.tracks {
		members[key.device] = struct{}{}
	}
	if len(worker.silences) >= massSilenceTransitions &&
		float64(len(worker.silences)) >= massSilenceShare*float64(max(len(members), 1)) &&
		now.After(worker.frozenUntil) {
		worker.frozenUntil = now.Add(massSilenceFreeze)
		worker.logger.Warn("many members went silent at once; their silence proves nothing for a while",
			"members", len(worker.silences), "label", worker.options.Label,
			"error_code", worker.options.Code+"_frozen")
	}
}
