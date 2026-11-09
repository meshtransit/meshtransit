package networksummary

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

type fakeStore struct {
	mu         sync.Mutex
	due        []network.Scope
	computeOK  bool
	computeErr error
	gone       bool
	newer      bool
	saved      []time.Duration
	released   int
	retries    []time.Duration
	claims     int
}

func (store *fakeStore) Fold(context.Context, int) (int, error) { return 0, nil }

func (store *fakeStore) Claim(_ context.Context, _ deployment.ID, _ publicid.ID, limit int,
	_ time.Duration) ([]network.Scope, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.claims++
	count := min(limit, len(store.due))
	claimed := store.due[:count]
	store.due = store.due[count:]
	return claimed, nil
}

func (store *fakeStore) Compute(context.Context, deployment.ID, network.Scope) (Summary, bool, error) {
	if store.computeErr != nil {
		return Summary{}, false, store.computeErr
	}
	if store.gone {
		return Summary{}, false, nil
	}
	return validSummary(), true, nil
}

func (store *fakeStore) Save(_ context.Context, _ deployment.ID, _ publicid.ID, _ Summary, _,
	spacing time.Duration) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.saved = append(store.saved, spacing)
	return store.newer, nil
}

func (store *fakeStore) Release(_ context.Context, _ deployment.ID, _ publicid.ID, _ network.Scope,
	retry time.Duration) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.released++
	store.retries = append(store.retries, retry)
	return nil
}

func (store *fakeStore) Lag(context.Context, deployment.ID) (Lag, error) {
	return Lag{Pending: 3, Marks: 5, Oldest: 4 * time.Second}, nil
}

func testScopes(t *testing.T, count int) []network.Scope {
	t.Helper()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000103")
	scopes := make([]network.Scope, 0, count)
	for index := range count {
		id, err := publicid.New()
		if err != nil {
			t.Fatal(err)
		}
		networkID, err := network.ParseID(id.String())
		if err != nil {
			t.Fatal(err, index)
		}
		scope, err := network.NewScope(workspaceID, networkID)
		if err != nil {
			t.Fatal(err)
		}
		scopes = append(scopes, scope)
	}
	return scopes
}

func testWorker(t *testing.T, store Store, batch int) *Worker {
	t.Helper()
	installation, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	worker, err := New(Options{DeploymentID: installation, BatchSize: batch, PollInterval: time.Second,
		OperationTimeout: time.Second, Lease: time.Minute}, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func TestWorkerStoresEachClaimedNetworkSpacedByItsCost(t *testing.T) {
	t.Parallel()
	store := &fakeStore{due: testScopes(t, 3), newer: true}
	worker := testWorker(t, store, 2)
	if claimed := worker.pass(t.Context()); claimed != 2 {
		t.Fatalf("first pass claimed %d", claimed)
	}
	if claimed := worker.pass(t.Context()); claimed != 1 {
		t.Fatalf("second pass claimed %d", claimed)
	}
	snapshot := worker.Snapshot()
	if snapshot.Claimed != 3 || snapshot.Stored != 3 || snapshot.Failed != 0 || len(store.saved) != 3 {
		t.Fatalf("snapshot %+v, saved %d", snapshot, len(store.saved))
	}
	for _, spacing := range store.saved {
		if spacing < minimumSpacing {
			t.Fatalf("spacing %s below the floor", spacing)
		}
	}
}

func TestWorkerReleasesWhatItCouldNotCount(t *testing.T) {
	t.Parallel()
	failing := &fakeStore{due: testScopes(t, 2), computeErr: errors.New("database gone")}
	worker := testWorker(t, failing, 4)
	worker.pass(t.Context())
	if snapshot := worker.Snapshot(); snapshot.Failed != 2 || failing.released != 2 || len(failing.saved) != 0 {
		t.Fatalf("failed count: %+v released %d", snapshot, failing.released)
	}
	// A failed count waits before the Network is claimed again.
	for _, retry := range failing.retries {
		if retry != failureRetry {
			t.Fatalf("failed count released with retry %s", retry)
		}
	}
	deleted := &fakeStore{due: testScopes(t, 1), gone: true}
	worker = testWorker(t, deleted, 4)
	worker.pass(t.Context())
	if snapshot := worker.Snapshot(); snapshot.Gone != 1 || snapshot.Failed != 0 || deleted.released != 1 ||
		deleted.retries[0] != 0 {
		t.Fatalf("gone Network: %+v", snapshot)
	}
}

func TestWorkerGivesBackTheRestOfABatchWhenStopped(t *testing.T) {
	t.Parallel()
	store := &fakeStore{due: testScopes(t, 3), newer: true}
	worker := testWorker(t, store, 4)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	worker.pass(ctx)
	if store.released != 3 || len(store.saved) != 0 {
		t.Fatalf("stopped pass released %d, saved %d", store.released, len(store.saved))
	}
}

func TestWorkerCountsAnOlderSummaryAsStale(t *testing.T) {
	t.Parallel()
	store := &fakeStore{due: testScopes(t, 1), newer: false}
	worker := testWorker(t, store, 4)
	worker.pass(t.Context())
	if snapshot := worker.Snapshot(); snapshot.Stale != 1 || snapshot.Stored != 0 {
		t.Fatalf("stale summary: %+v", snapshot)
	}
}

func TestSpacingGrowsWithTheCostOfACount(t *testing.T) {
	t.Parallel()
	for took, want := range map[time.Duration]time.Duration{
		0: 2 * time.Second, 50 * time.Millisecond: 2 * time.Second, 500 * time.Millisecond: 10 * time.Second,
		time.Minute: 10 * time.Minute,
	} {
		if got := Spacing(took); got != want {
			t.Errorf("Spacing(%s) = %s, want %s", took, got, want)
		}
	}
}

func TestWorkerRunsUntilShutdownAndReadsLag(t *testing.T) {
	t.Parallel()
	store := &fakeStore{due: testScopes(t, 1), newer: true}
	worker := testWorker(t, store, 4)
	if err := worker.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for worker.Snapshot().Stored == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := worker.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-worker.Done()
	if snapshot := worker.Snapshot(); snapshot.Stored != 1 || snapshot.Pending != 3 || snapshot.Marks != 5 ||
		snapshot.Lag != 4*time.Second ||
		snapshot.Running {
		t.Fatalf("after run: %+v", snapshot)
	}
}

func TestNewRefusesUnsafeOptions(t *testing.T) {
	t.Parallel()
	installation, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	good := Options{DeploymentID: installation, BatchSize: 8, PollInterval: 5 * time.Second,
		OperationTimeout: 10 * time.Second, Lease: 2 * time.Minute}
	if _, err := New(good, &fakeStore{}, logger); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Options){
		"batch":             func(options *Options) { options.BatchSize = 65 },
		"lease under work":  func(options *Options) { options.Lease = 10 * time.Second },
		"lease under batch": func(options *Options) { options.Lease = 80 * time.Second },
		"poll":              func(options *Options) { options.PollInterval = 100 * time.Millisecond },
	} {
		options := good
		change(&options)
		if _, err := New(options, &fakeStore{}, logger); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := New(good, nil, logger); err == nil {
		t.Error("nil store accepted")
	}
}
