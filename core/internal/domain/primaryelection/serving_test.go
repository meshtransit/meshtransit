package primaryelection

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
)

func TestElectServing(t *testing.T) {
	t.Parallel()
	first, second, third := device(t, 1), device(t, 2), device(t, 3)
	usable := func(id node.ID, priority int) ServingCandidate {
		return ServingCandidate{Device: id, Priority: priority, Status: StatusUsable, UsableFor: time.Hour}
	}
	fresh := func(candidate ServingCandidate) ServingCandidate {
		candidate.UsableFor = time.Second
		return candidate
	}
	overloaded := func(candidate ServingCandidate) ServingCandidate {
		candidate.Overloaded = true
		return candidate
	}
	failed := func(candidate ServingCandidate) ServingCandidate {
		candidate.Status = StatusFailed
		return candidate
	}
	recovered := func(candidate ServingCandidate) ServingCandidate {
		candidate.Recovered = true
		return candidate
	}
	heldBack := func(candidate ServingCandidate) ServingCandidate {
		candidate.HeldBack = true
		return candidate
	}
	reporting := func(candidate ServingCandidate) ServingCandidate {
		candidate.Reporting = true
		return candidate
	}
	for name, test := range map[string]struct {
		current    []node.ID
		candidates []ServingCandidate
		want       []node.ID
		reason     string
	}{
		"the best tier serves": {nil, []ServingCandidate{usable(first, 1), usable(second, 1), usable(third, 2)},
			[]node.ID{first, second}, ServingElected},
		"a lower tier serves when the best cannot": {[]node.ID{first},
			[]ServingCandidate{failed(usable(first, 1)), usable(third, 2)}, []node.ID{third}, ServingFailover},
		"a new member waits for its hold-down": {[]node.ID{first},
			[]ServingCandidate{usable(first, 1), fresh(usable(second, 1))}, []node.ID{first}, ""},
		"a member of the set stays without waiting": {[]node.ID{first, second},
			[]ServingCandidate{fresh(usable(first, 1)), usable(second, 1)}, []node.ID{first, second}, ""},
		"it joins after its hold-down": {[]node.ID{first},
			[]ServingCandidate{usable(first, 1), usable(second, 1)}, []node.ID{first, second}, ServingJoined},
		"an overloaded member leaves": {[]node.ID{first, second},
			[]ServingCandidate{usable(first, 1), overloaded(usable(second, 1))}, []node.ID{first}, ServingOverloaded},
		"a whole overloaded tier still serves": {[]node.ID{first, second},
			[]ServingCandidate{overloaded(usable(first, 1)), overloaded(usable(second, 1)), usable(third, 2)},
			[]node.ID{first, second}, ""},
		"a recovered member comes back": {[]node.ID{first},
			[]ServingCandidate{usable(first, 1), recovered(usable(second, 1))}, []node.ID{first, second},
			ServingRecovered},
		"every member failed keeps the set": {[]node.ID{first, second},
			[]ServingCandidate{failed(usable(first, 1)), failed(usable(second, 1))}, []node.ID{first, second}, ""},
		"none can serve": {[]node.ID{first}, []ServingCandidate{{Device: first, Priority: 1, Status: StatusDraining}},
			nil, ServingNone},
		"a member held back does not join": {[]node.ID{first},
			[]ServingCandidate{usable(first, 1), heldBack(usable(second, 1))}, []node.ID{first}, ""},
		"a member reporting overload does not join": {[]node.ID{first},
			[]ServingCandidate{usable(first, 1), reporting(usable(second, 1))}, []node.ID{first}, ""},
		"overloaded members leave only while half the tier is not": {[]node.ID{first, second, third},
			[]ServingCandidate{usable(first, 1), overloaded(usable(second, 1)), overloaded(usable(third, 1))},
			[]node.ID{first, second, third}, ""},
		"none before and none now": {nil, []ServingCandidate{fresh(usable(first, 1))}, nil, ""},
		"draining leaves": {[]node.ID{first, second}, []ServingCandidate{usable(first, 1),
			{Device: second, Priority: 1, Status: StatusDraining}}, []node.ID{first}, ServingFailover},
	} {
		got, reason, changed := ElectServing(test.current, test.candidates)
		if !slices.Equal(got, test.want) || reason != test.reason || changed != (test.reason != "") {
			t.Errorf("%s: ElectServing = %v %q %v, want %v %q", name, got, reason, changed, test.want, test.reason)
		}
	}
}

// fakeSpread is one spread group's facts; it records decisions as prepare
// would.
type fakeSpread struct {
	facts   GroupFacts
	serving []ServingDecision
	clock   *stepClock
}

func (fake *fakeSpread) List(context.Context, deployment.ID, string, int) (Page, error) {
	return Page{Groups: []GroupFacts{fake.facts}, Done: true}, nil
}

func (fake *fakeSpread) Record(_ context.Context, _ deployment.ID, decision Decision) (bool, error) {
	fake.facts.Primary, fake.facts.Generation = decision.Primary, fake.facts.Generation+1
	return true, nil
}

func (fake *fakeSpread) RecordServing(_ context.Context, _ deployment.ID, decision ServingDecision) (bool, error) {
	if decision.ExpectedGeneration != fake.facts.ServingGeneration {
		return false, nil
	}
	fake.serving = append(fake.serving, decision)
	fake.facts.ServingPrevious, fake.facts.ServingReason = fake.facts.Serving, decision.Reason
	fake.facts.Serving, fake.facts.ServingGeneration = decision.Devices, fake.facts.ServingGeneration+1
	fake.facts.ServingChangedAt = fake.clock.now
	return true, nil
}

type fakeObservations struct {
	byID map[node.ID]distribution.Observation
	err  error
}

func (fake *fakeObservations) LoadObservations(_ context.Context, ids []node.ID) ([]distribution.Observation, error) {
	if fake.err != nil {
		return nil, fake.err
	}
	loaded := make([]distribution.Observation, len(ids))
	for index, id := range ids {
		loaded[index] = fake.byID[id]
	}
	return loaded, nil
}

type stepClock struct{ now time.Time }

func (clock *stepClock) Now() time.Time { return clock.now }

// TestWorkerElectsASpreadGroupsServingSet: the best tier serves once
// usable for the hold-down; overload takes a member out after a minute and
// it comes back after five calm minutes; a failure takes it out at once;
// changes are spaced; an unreadable Redis changes nothing.
func TestWorkerElectsASpreadGroupsServingSet(t *testing.T) {
	t.Parallel()
	installation, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	first, second, third := device(t, 1), device(t, 2), device(t, 3)
	group := "01a159f2-8c40-718b-bea7-ea6c60ff7b0e"
	started := time.Date(2026, time.October, 21, 12, 0, 0, 0, time.UTC)
	clock := &stepClock{now: started}
	fake := &fakeSpread{clock: clock, facts: GroupFacts{Group: group, Spread: true, Members: []MemberFacts{
		{Device: first, Priority: 1, Eligible: true}, {Device: second, Priority: 1, Eligible: true},
		{Device: third, Priority: 2, Eligible: true}}}}
	observations := &fakeObservations{byID: map[node.ID]distribution.Observation{}}
	report := func(id node.ID, state, code string) {
		observations.byID[id] = distribution.Observation{Known: true, SessionGeneration: 1, NetworkRevision: 1,
			DeliveredAt: started, SeenAt: clock.now, RouteHealthAt: clock.now,
			RouteHealth: []distribution.SiteHealth{{Ref: group, State: state, Code: code}}}
	}
	health := func(observation distribution.Observation, group string, now time.Time) Report {
		for _, item := range observation.RouteHealth {
			if item.Ref == group {
				return Report{ReportedAt: observation.RouteHealthAt, State: item.State, Code: item.Code}
			}
		}
		return Report{}
	}
	worker, err := New(Options{DeploymentID: installation, PollInterval: 10 * time.Second,
		OperationTimeout: time.Second, Health: health, Label: "Exit Pool", Key: "exit_pool",
		Code: "exit_pool_election", Overloaded: func(code string) bool { return code == "conntrack_high" },
		Serving: true}, fake, fake, observations, clock, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// A second replica, started later, judges with its own memory.
	replica := func() *Worker {
		other, err := New(Options{DeploymentID: installation, PollInterval: 10 * time.Second,
			OperationTimeout: time.Second, Health: health, Label: "Exit Pool", Key: "exit_pool",
			Code: "exit_pool_election", Overloaded: func(code string) bool { return code == "conntrack_high" },
			Serving: true}, fake, fake, observations, clock, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		return other
	}
	sweep := func(after time.Duration) {
		clock.now = clock.now.Add(after)
		for _, id := range []node.ID{first, second, third} {
			state, code := distribution.SiteHealthOK, "ok"
			if previous, known := observations.byID[id]; known && len(previous.RouteHealth) == 1 {
				state, code = previous.RouteHealth[0].State, previous.RouteHealth[0].Code
			}
			report(id, state, code)
		}
		worker.Sweep(context.Background())
	}
	expect := func(step string, want []node.ID, reason string, decisions int) {
		t.Helper()
		if len(fake.serving) != decisions {
			t.Fatalf("%s: %d decisions, want %d: %+v", step, len(fake.serving), decisions, fake.serving)
		}
		if reason != "" {
			last := fake.serving[decisions-1]
			if !slices.Equal(last.Devices, want) || last.Reason != reason {
				t.Fatalf("%s: last decision %+v, want %v %q", step, last, want, reason)
			}
		}
	}
	sweep(0)
	expect("before the hold-down", nil, "", 0)
	sweep(HoldDown)
	expect("after the hold-down", []node.ID{first, second}, ServingElected, 1)
	changedAt := clock.now

	report(second, distribution.SiteHealthDegraded, "conntrack_high")
	sweep(ServingChangeSpacing)
	expect("overloaded for less than a minute", nil, "", 1)
	sweep(OverloadedAfter)
	expect("overloaded for a minute", []node.ID{first}, ServingOverloaded, 2)
	if !clock.now.After(changedAt.Add(ServingChangeSpacing)) {
		t.Fatal("the test does not space its changes")
	}

	// A replica that never saw the overload holds second back too.
	late := replica()
	late.Sweep(context.Background())
	clock.now = clock.now.Add(HoldDown + time.Second)
	late.Sweep(context.Background())
	expect("a fresh replica while second still reports overload", nil, "", 2)
	report(second, distribution.SiteHealthOK, "ok")
	sweep(time.Minute)
	late.Sweep(context.Background())
	expect("calm, within five minutes of leaving", nil, "", 2)
	sweep(RecoveredAfter)
	expect("five minutes after leaving", []node.ID{first, second}, ServingRecovered, 3)

	report(first, distribution.SiteHealthFailed, "egress_failed")
	sweep(time.Second)
	expect("a failure within the spacing", nil, "", 3)
	sweep(ServingChangeSpacing)
	expect("a failure after the spacing", []node.ID{second}, ServingFailover, 4)
	report(second, distribution.SiteHealthFailed, "egress_failed")
	report(third, distribution.SiteHealthFailed, "egress_failed")
	sweep(ServingChangeSpacing)
	expect("every member failed keeps the set", nil, "", 4)

	observations.err = context.DeadlineExceeded
	report(second, distribution.SiteHealthFailed, "egress_failed")
	sweep(time.Minute)
	expect("without health", nil, "", 4)
}
