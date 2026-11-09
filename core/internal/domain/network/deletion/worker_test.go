package deletion

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
)

type fakeWorkerStore struct {
	mu    sync.Mutex
	steps []Step
	err   error
	calls int
}

func (store *fakeWorkerStore) Step(context.Context, deployment.ID, int) (Step, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.calls++
	if store.err != nil {
		return Step{}, store.err
	}
	if len(store.steps) == 0 {
		return Step{}, nil
	}
	step := store.steps[0]
	store.steps = store.steps[1:]
	return step, nil
}

func (store *fakeWorkerStore) Lag(context.Context, deployment.ID) (Lag, error) {
	return Lag{Pending: 1, Oldest: 3 * time.Second}, nil
}

func testWorker(t *testing.T, store WorkerStore) *Worker {
	t.Helper()
	installation, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	worker, err := NewWorker(WorkerOptions{DeploymentID: installation, BatchSize: 500, PollInterval: time.Second,
		OperationTimeout: time.Second}, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func TestWorkerStepsUntilNothingIsLeft(t *testing.T) {
	t.Parallel()
	store := &fakeWorkerStore{steps: []Step{{Changed: true, Revoked: 500}, {Changed: true, Revoked: 20,
		Completed: true}}}
	worker := testWorker(t, store)
	for worker.pass(t.Context()) {
	}
	snapshot := worker.Snapshot()
	if snapshot.Steps != 2 || snapshot.Revoked != 520 || snapshot.Completed != 1 || snapshot.Failures != 0 ||
		store.calls != 3 {
		t.Fatalf("snapshot %+v after %d calls", snapshot, store.calls)
	}
}

func TestWorkerCountsDeletionsThatFailed(t *testing.T) {
	t.Parallel()
	worker := testWorker(t, &fakeWorkerStore{steps: []Step{{Failed: 2}}})
	if worker.pass(t.Context()) || worker.Snapshot().Failures != 2 {
		t.Fatalf("snapshot %+v", worker.Snapshot())
	}
}

func TestWorkerCountsFailuresAndWaits(t *testing.T) {
	t.Parallel()
	worker := testWorker(t, &fakeWorkerStore{err: errors.New("database gone")})
	if worker.pass(t.Context()) {
		t.Fatal("a failed step asked for another at once")
	}
	if worker.Snapshot().Failures != 1 {
		t.Fatalf("snapshot %+v", worker.Snapshot())
	}
}

func TestWorkerRunsUntilShutdownAndReadsLag(t *testing.T) {
	t.Parallel()
	worker := testWorker(t, &fakeWorkerStore{steps: []Step{{Changed: true, Completed: true}}})
	if err := worker.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for worker.Snapshot().Pending == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := worker.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-worker.Done()
	if snapshot := worker.Snapshot(); snapshot.Completed != 1 || snapshot.Pending != 1 ||
		snapshot.Lag != 3*time.Second || snapshot.Running {
		t.Fatalf("after run: %+v", snapshot)
	}
	if err := worker.Start(t.Context()); err == nil {
		t.Fatal("started twice")
	}
}

func TestNewWorkerRefusesUnsafeOptions(t *testing.T) {
	t.Parallel()
	installation, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	good := WorkerOptions{DeploymentID: installation, BatchSize: 500, PollInterval: 10 * time.Second,
		OperationTimeout: 30 * time.Second}
	if _, err := NewWorker(good, &fakeWorkerStore{}, logger); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*WorkerOptions){
		"batch":      func(options *WorkerOptions) { options.BatchSize = 2001 },
		"poll":       func(options *WorkerOptions) { options.PollInterval = time.Millisecond },
		"timeout":    func(options *WorkerOptions) { options.OperationTimeout = 2 * time.Minute },
		"deployment": func(options *WorkerOptions) { options.DeploymentID = deployment.ID{} },
	} {
		options := good
		change(&options)
		if _, err := NewWorker(options, &fakeWorkerStore{}, logger); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
