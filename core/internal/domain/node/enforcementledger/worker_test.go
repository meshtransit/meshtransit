package enforcementledger

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/shared/policydigest"
)

var (
	digestA = policydigest.Digest{0xa}
	digestB = policydigest.Digest{0xb}
)

type fakeDirectory struct {
	mu      sync.Mutex
	scopes  []network.Scope
	targets map[network.Scope][]Target
	fail    bool
}

func (directory *fakeDirectory) ListNetworks(_ context.Context, _ deployment.ID, after network.ID,
	limit int) ([]network.Scope, error) {
	directory.mu.Lock()
	defer directory.mu.Unlock()
	if directory.fail {
		return nil, errors.New("synthetic directory failure")
	}
	var page []network.Scope
	for _, scope := range directory.scopes {
		if (after == network.ID{} || scope.NetworkID().String() > after.String()) && len(page) < limit {
			page = append(page, scope)
		}
	}
	return page, nil
}

func (directory *fakeDirectory) ListDevices(_ context.Context, _ deployment.ID, scope network.Scope, after node.ID,
	limit int) ([]Target, error) {
	directory.mu.Lock()
	defer directory.mu.Unlock()
	var page []Target
	for _, target := range directory.targets[scope] {
		if (after == node.ID{} || target.DeviceID.String() > after.String()) && len(page) < limit {
			page = append(page, target)
		}
	}
	return page, nil
}

type fakeObservations struct {
	mu    sync.Mutex
	byID  map[node.ID]distribution.Observation
	calls int
}

func (loader *fakeObservations) LoadObservations(_ context.Context, ids []node.ID) ([]distribution.Observation, error) {
	loader.mu.Lock()
	defer loader.mu.Unlock()
	loader.calls++
	if len(ids) > distribution.MaximumPageSize {
		return nil, errors.New("batch too large")
	}
	result := make([]distribution.Observation, len(ids))
	for index, id := range ids {
		result[index] = loader.byID[id]
	}
	return result, nil
}

type fakeRecorder struct {
	mu       sync.Mutex
	recorded []Observation
	outcome  Outcome
	err      error
}

func (recorder *fakeRecorder) Record(_ context.Context, _ deployment.ID, observation Observation) (Outcome, error) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.recorded = append(recorder.recorded, observation)
	return recorder.outcome, recorder.err
}

func (recorder *fakeRecorder) state() []Observation {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]Observation(nil), recorder.recorded...)
}

type fakePruner struct{ calls int }

func (pruner *fakePruner) Prune(context.Context, deployment.ID, int) (int, error) {
	pruner.calls++
	return 0, nil
}

func testScope(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func testDevice(t *testing.T, index int) node.ID {
	t.Helper()
	id, err := node.ParseID(fmt.Sprintf("01890f00-0000-7000-8000-%012d", 300+index))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// observed builds a delivery record delivered and reported at the given times.
func observed(delivered, enforced policydigest.Digest, deliveredAt time.Time, report bool) distribution.Observation {
	observation := distribution.Observation{
		Known: true, SessionGeneration: 1, NetworkRevision: 7, PolicyRevision: 3,
		DeliveredAt: deliveredAt, SeenAt: deliveredAt, Online: true,
		Filter: distribution.FilterSummary{Digest: delivered, Grants: 4},
	}
	if report {
		observation.Enforced = distribution.FilterSummary{Digest: enforced, Grants: 3}
		observation.AppliedAt, observation.ReportedAt = deliveredAt, deliveredAt
	}
	return observation
}

func newTestWorker(t *testing.T, directory Directory, loader distribution.ObservationLoader,
	recorder Recorder) *Worker {
	t.Helper()
	installation, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	worker, err := New(Options{DeploymentID: installation, PollInterval: 15 * time.Second,
		PruneInterval: time.Hour, OperationTimeout: 5 * time.Second},
		directory, loader, recorder, &fakePruner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func TestWorkerRecordsOnlyChangedEvidence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		scope := testScope(t)
		now := time.Now()
		old := now.Add(-2 * distribution.EnforcementGrace)
		devices := make([]node.ID, 6)
		for index := range devices {
			devices[index] = testDevice(t, index)
		}
		directory := &fakeDirectory{scopes: []network.Scope{scope}, targets: map[network.Scope][]Target{scope: {
			{DeviceID: devices[0]}, // enforced, no evidence yet: recorded
			{DeviceID: devices[1], Open: Interval{State: StateEnforced, Delivered: digestA, Enforced: digestA}}, // mismatch now
			{DeviceID: devices[2]}, // applying: nothing
			{DeviceID: devices[3], Open: Interval{State: StateEnforced, Delivered: digestA, Enforced: digestA}}, // unchanged
			{DeviceID: devices[4]}, // never reported past grace: nothing
			{DeviceID: devices[5]}, // never delivered: nothing
		}}}
		loader := &fakeObservations{byID: map[node.ID]distribution.Observation{
			devices[0]: observed(digestA, digestA, old, true),
			devices[1]: observed(digestA, digestB, old, true),
			devices[2]: observed(digestA, digestB, now, true),
			devices[3]: observed(digestA, digestA, old, true),
			devices[4]: observed(digestA, digestA, old, false),
		}}
		recorder := &fakeRecorder{outcome: OutcomeRecorded}
		worker := newTestWorker(t, directory, loader, recorder)
		if err := worker.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		recorded := recorder.state()
		if len(recorded) != 2 || recorded[0].DeviceID != devices[0] || recorded[0].State() != StateEnforced ||
			recorded[1].DeviceID != devices[1] || recorded[1].State() != StateMismatch ||
			recorded[1].Delivered.Grants != 4 || recorded[1].Enforced.Grants != 3 || recorded[1].NetworkRevision != 7 {
			t.Fatalf("recorded = %+v", recorded)
		}
		if snapshot := worker.Snapshot(); snapshot.Passes != 1 || snapshot.Recorded != 2 || !snapshot.Running {
			t.Fatalf("measurements = %+v", snapshot)
		}
		if err := worker.Shutdown(t.Context()); err != nil {
			t.Fatal(err)
		}
		<-worker.Done()
	})
}

func TestWorkerBatchesObservationsAndCountsFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		scope := testScope(t)
		targets := make([]Target, 150)
		for index := range targets {
			targets[index] = Target{DeviceID: testDevice(t, index)}
		}
		directory := &fakeDirectory{scopes: []network.Scope{scope}, targets: map[network.Scope][]Target{scope: targets}}
		loader := &fakeObservations{byID: map[node.ID]distribution.Observation{}}
		recorder := &fakeRecorder{outcome: OutcomeAudited, err: errors.New("synthetic record failure")}
		loader.byID[targets[0].DeviceID] = observed(digestA, digestB, time.Now().Add(-time.Hour), true)
		worker := newTestWorker(t, directory, loader, recorder)
		if err := worker.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if loader.calls != 2 {
			t.Fatalf("observation loads = %d, want 2 batches", loader.calls)
		}
		if snapshot := worker.Snapshot(); snapshot.Deferred != 1 || snapshot.Recorded != 0 {
			t.Fatalf("measurements = %+v", snapshot)
		}
		directory.mu.Lock()
		directory.fail = true
		directory.mu.Unlock()
		time.Sleep(15 * time.Second)
		synctest.Wait()
		if snapshot := worker.Snapshot(); snapshot.Passes != 2 || snapshot.ReadErrors != 1 {
			t.Fatalf("measurements after a failed read = %+v", snapshot)
		}
		if err := worker.Shutdown(t.Context()); err != nil {
			t.Fatal(err)
		}
		<-worker.Done()
	})
}

func TestNewRejectsUnsafeComposition(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	installation, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	valid := Options{DeploymentID: installation, PollInterval: 15 * time.Second, PruneInterval: time.Hour,
		OperationTimeout: 5 * time.Second}
	if _, err := New(valid, nil, &fakeObservations{}, &fakeRecorder{}, &fakePruner{}, logger); !errors.Is(err, ErrInvalidWorker) {
		t.Fatalf("nil directory error = %v", err)
	}
	invalid := valid
	invalid.PollInterval = time.Hour
	if _, err := New(invalid, &fakeDirectory{}, &fakeObservations{}, &fakeRecorder{}, &fakePruner{}, logger); !errors.Is(err, ErrInvalidWorker) {
		t.Fatalf("slow poll error = %v", err)
	}
	var worker *Worker
	if err := worker.Shutdown(t.Context()); !errors.Is(err, ErrInvalidWorker) {
		t.Fatalf("nil Shutdown error = %v", err)
	}
}
