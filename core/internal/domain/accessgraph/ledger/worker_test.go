package ledger

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
	"meshtransit.net/core/internal/domain/workspace"
)

type dueFunc func(context.Context, deployment.ID, int) ([]network.Scope, error)

func (due dueFunc) ListDue(ctx context.Context, id deployment.ID, limit int) ([]network.Scope, error) {
	return due(ctx, id, limit)
}

type recordFunc func(context.Context, deployment.ID, network.Scope) (Outcome, error)

func (record recordFunc) Record(ctx context.Context, id deployment.ID, scope network.Scope) (Outcome, error) {
	return record(ctx, id, scope)
}

type pruneFunc func(context.Context, deployment.ID, int) (int, error)

func (prune pruneFunc) Prune(ctx context.Context, id deployment.ID, limit int) (int, error) {
	return prune(ctx, id, limit)
}

var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

func testOptions(t *testing.T) Options {
	t.Helper()
	id, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	return Options{DeploymentID: id, BatchSize: 4, PollInterval: 100 * time.Millisecond,
		PruneInterval: time.Hour, OperationTimeout: time.Second}
}

func testScope(t *testing.T, value string) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatal(err)
	}
	networkID, err := network.ParseID(value)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	due := dueFunc(func(context.Context, deployment.ID, int) ([]network.Scope, error) { return nil, nil })
	record := recordFunc(func(context.Context, deployment.ID, network.Scope) (Outcome, error) { return 0, nil })
	prune := pruneFunc(func(context.Context, deployment.ID, int) (int, error) { return 0, nil })
	var nilDue dueFunc
	tests := []struct {
		name    string
		mutate  func(*Options)
		due     Due
		record  Recorder
		prune   Pruner
		logger  *slog.Logger
		wantErr bool
	}{
		{name: "valid", mutate: func(*Options) {}, due: due, record: record, prune: prune, logger: discardLogger},
		{name: "missing deployment", mutate: func(o *Options) { o.DeploymentID = deployment.ID{} }, due: due,
			record: record, prune: prune, logger: discardLogger, wantErr: true},
		{name: "batch too large", mutate: func(o *Options) { o.BatchSize = 65 }, due: due, record: record,
			prune: prune, logger: discardLogger, wantErr: true},
		{name: "poll too fast", mutate: func(o *Options) { o.PollInterval = time.Millisecond }, due: due,
			record: record, prune: prune, logger: discardLogger, wantErr: true},
		{name: "prune too often", mutate: func(o *Options) { o.PruneInterval = time.Second }, due: due,
			record: record, prune: prune, logger: discardLogger, wantErr: true},
		{name: "operation too long", mutate: func(o *Options) { o.OperationTimeout = time.Minute }, due: due,
			record: record, prune: prune, logger: discardLogger, wantErr: true},
		{name: "typed nil due", mutate: func(*Options) {}, due: nilDue, record: record, prune: prune,
			logger: discardLogger, wantErr: true},
		{name: "missing pruner", mutate: func(*Options) {}, due: due, record: record, logger: discardLogger,
			wantErr: true},
		{name: "missing logger", mutate: func(*Options) {}, due: due, record: record, prune: prune, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := testOptions(t)
			test.mutate(&options)
			_, err := New(options, test.due, test.record, test.prune, test.logger)
			if (err != nil) != test.wantErr || test.wantErr && !errors.Is(err, ErrInvalidWorker) {
				t.Fatalf("New() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestWorkerRecordsDueNetworksAndPrunesUntilShort(t *testing.T) {
	t.Parallel()
	first := testScope(t, "01890f00-0000-7000-8000-000000000201")
	second := testScope(t, "01890f00-0000-7000-8000-000000000202")
	third := testScope(t, "01890f00-0000-7000-8000-000000000203")
	var mu sync.Mutex
	var recorded []network.Scope
	pruneCalls := 0
	passed := make(chan struct{}, 1)
	due := dueFunc(func(_ context.Context, _ deployment.ID, limit int) ([]network.Scope, error) {
		// The batch grows by the one Network backing off after its failure.
		if limit != 4 && limit != 5 {
			t.Errorf("limit = %d", limit)
		}
		return []network.Scope{first, second, third}, nil
	})
	record := recordFunc(func(_ context.Context, _ deployment.ID, scope network.Scope) (Outcome, error) {
		mu.Lock()
		defer mu.Unlock()
		recorded = append(recorded, scope)
		switch scope {
		case first:
			return OutcomeRecorded, nil
		case second:
			return OutcomeUnchanged, nil
		default:
			select {
			case passed <- struct{}{}:
			default:
			}
			return 0, errors.New("serialization failure")
		}
	})
	prune := pruneFunc(func(context.Context, deployment.ID, int) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		pruneCalls++
		if pruneCalls == 1 {
			return PruneBatchSize, nil
		}
		return 3, nil
	})
	worker, err := New(testOptions(t), due, record, prune, discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-passed:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not complete a pass")
	}
	if err := worker.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-worker.Done()
	snapshot := worker.Snapshot()
	mu.Lock()
	defer mu.Unlock()
	if len(recorded) < 3 || recorded[0] != first || recorded[1] != second || recorded[2] != third {
		t.Fatalf("recorded = %v", recorded)
	}
	if pruneCalls != 2 || snapshot.Pruned != PruneBatchSize+3 || snapshot.Recorded < 1 || snapshot.Unchanged < 1 ||
		snapshot.Deferred < 1 || snapshot.Running {
		t.Fatalf("prune calls = %d snapshot = %+v", pruneCalls, snapshot)
	}
}

func TestWorkerCountsDiscoveryFailuresAndRejectsOversizedPages(t *testing.T) {
	t.Parallel()
	scope := testScope(t, "01890f00-0000-7000-8000-000000000201")
	calls := make(chan int, 8)
	attempt := 0
	due := dueFunc(func(context.Context, deployment.ID, int) ([]network.Scope, error) {
		attempt++
		calls <- attempt
		if attempt == 1 {
			return nil, errors.New("unavailable")
		}
		return []network.Scope{scope, scope, scope, scope, scope}, nil
	})
	record := recordFunc(func(context.Context, deployment.ID, network.Scope) (Outcome, error) {
		t.Error("oversized page reached the recorder")
		return 0, nil
	})
	prune := pruneFunc(func(context.Context, deployment.ID, int) (int, error) { return 0, errors.New("down") })
	worker, err := New(testOptions(t), due, record, prune, discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The third discovery starts only after the second pass has finished.
	for range 3 {
		select {
		case <-calls:
		case <-time.After(5 * time.Second):
			t.Fatal("worker stalled")
		}
	}
	if err := worker.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-worker.Done()
	snapshot := worker.Snapshot()
	if snapshot.DiscoveryErrors < 2 || snapshot.PruneErrors != 1 || snapshot.Recorded != 0 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if err := worker.Start(t.Context()); !errors.Is(err, ErrWorkerStarted) {
		t.Fatalf("restart error = %v", err)
	}
}

func TestWorkerBacksOffAFailingNetworkWithoutStarvingOthers(t *testing.T) {
	t.Parallel()
	stuck := testScope(t, "01890f00-0000-7000-8000-000000000201")
	healthy := testScope(t, "01890f00-0000-7000-8000-000000000202")
	options := testOptions(t)
	options.BatchSize = 1
	var mu sync.Mutex
	attempts := map[network.Scope]int{}
	limits := []int{}
	done := make(chan struct{})
	due := dueFunc(func(_ context.Context, _ deployment.ID, limit int) ([]network.Scope, error) {
		mu.Lock()
		defer mu.Unlock()
		limits = append(limits, limit)
		return []network.Scope{stuck, healthy}[:min(limit, 2)], nil
	})
	record := recordFunc(func(_ context.Context, _ deployment.ID, scope network.Scope) (Outcome, error) {
		mu.Lock()
		defer mu.Unlock()
		attempts[scope]++
		if scope == healthy {
			select {
			case <-done:
			default:
				close(done)
			}
			return OutcomeRecorded, nil
		}
		return 0, errors.New("audit stream unavailable")
	})
	prune := pruneFunc(func(context.Context, deployment.ID, int) (int, error) { return 0, nil })
	worker, err := New(options, due, record, prune, discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("healthy Network starved behind a failing one")
	}
	if err := worker.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-worker.Done()
	mu.Lock()
	defer mu.Unlock()
	if attempts[stuck] != 1 || attempts[healthy] < 1 || limits[0] != 1 || limits[1] != 2 {
		t.Fatalf("attempts = %v limits = %v", attempts, limits)
	}
}

func TestRetryDelayDoublesUpToTheCap(t *testing.T) {
	t.Parallel()
	worker := &Worker{options: testOptions(t)}
	if worker.retryDelay(1) != 200*time.Millisecond || worker.retryDelay(3) != 800*time.Millisecond ||
		worker.retryDelay(40) != maximumRetryDelay {
		t.Fatal("unexpected retry delays", worker.retryDelay(1), worker.retryDelay(3), worker.retryDelay(40))
	}
}
