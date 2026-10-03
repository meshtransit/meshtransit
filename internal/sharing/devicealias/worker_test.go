package devicealias

import (
	"context"
	"errors"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/sharing"
	"io"
	"log/slog"
	"testing"
	"time"
)

type workFunc func(context.Context, deployment.ID, Cursor, int) (Page, error)

func (work workFunc) List(ctx context.Context, id deployment.ID, after Cursor, limit int) (Page, error) {
	return work(ctx, id, after, limit)
}

type changeFunc func(context.Context, ChangeIntent) (bool, error)

func (change changeFunc) Change(ctx context.Context, intent ChangeIntent) (bool, error) {
	return change(ctx, intent)
}

func workerFixture(t *testing.T) (Options, ChangeIntent, *slog.Logger) {
	t.Helper()
	id, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := sharing.ParsePrivateEndpointID("01890f00-0000-7000-8000-000000000010")
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := node.ParseID("01890f00-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	return Options{DeploymentID: id, BatchSize: 1, PollInterval: 100 * time.Millisecond, OperationTimeout: time.Second},
		ChangeIntent{DeploymentID: id, EndpointID: endpoint, ConsumerID: consumer, EndpointGeneration: 1, ProviderNodeEpoch: 1, ConsumerNodeEpoch: 1, Mode: Reserve}, slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestWorkerAdvancesAfterFailureAndRestartsAuthoritativeSweep(t *testing.T) {
	t.Parallel()
	options, intent, logger := workerFixture(t)
	next := Cursor{EndpointID: intent.EndpointID, ConsumerID: intent.ConsumerID}
	reads, changes := 0, 0
	work := workFunc(func(_ context.Context, id deployment.ID, after Cursor, limit int) (Page, error) {
		reads++
		if reads == 1 {
			if after != (Cursor{}) {
				t.Fatal("initial cursor")
			}
			return Page{Items: []ChangeIntent{intent}, Next: next}, nil
		}
		if after != next || id != options.DeploymentID || limit != 1 {
			t.Fatal("failed pair blocked later page")
		}
		return Page{Done: true, Next: next}, nil
	})
	change := changeFunc(func(context.Context, ChangeIntent) (bool, error) {
		changes++
		return false, errors.New("synthetic unknown commit")
	})
	worker, err := New(options, work, change, logger)
	if err != nil {
		t.Fatal(err)
	}
	after := worker.reconcile(t.Context(), Cursor{})
	if after != next {
		t.Fatal("failure stalled cursor")
	}
	after = worker.reconcile(t.Context(), after)
	if after != (Cursor{}) || changes != 1 {
		t.Fatal("sweep did not reset")
	}
	metrics := worker.Snapshot()
	if metrics.Passes != 2 || metrics.Deferred != 1 || metrics.Changed != 0 {
		t.Fatal("incorrect worker outcome")
	}
}

func TestWorkerRejectsStalledForeignDuplicateAndFailedDiscovery(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"stalled", "foreign", "duplicate", "failed", "empty progressing"} {
		t.Run(name, func(t *testing.T) {
			options, intent, logger := workerFixture(t)
			options.BatchSize = 2
			next := Cursor{EndpointID: intent.EndpointID, ConsumerID: intent.ConsumerID}
			page := Page{Items: []ChangeIntent{intent}, Next: next}
			var readErr error
			switch name {
			case "stalled":
				page.Next = Cursor{}
			case "foreign":
				page.Items[0].DeploymentID = deployment.ID{}
			case "duplicate":
				page.Items = append(page.Items, intent)
			case "failed":
				readErr = errors.New("synthetic read failure")
			case "empty progressing":
				page.Items = nil
			}
			calls := 0
			worker, err := New(options, workFunc(func(context.Context, deployment.ID, Cursor, int) (Page, error) { return page, readErr }), changeFunc(func(context.Context, ChangeIntent) (bool, error) { calls++; return true, nil }), logger)
			if err != nil {
				t.Fatal(err)
			}
			after := worker.reconcile(t.Context(), Cursor{})
			if calls != 0 {
				t.Fatal("invalid discovery released a change")
			}
			if name == "empty progressing" {
				if after != next {
					t.Fatal("no-action rows stalled pagination")
				}
			} else if after != (Cursor{}) || worker.Snapshot().DiscoveryErrors != 1 {
				t.Fatal("invalid discovery advanced cursor")
			}
		})
	}
}

func TestWorkerShutdownCancelsAndJoinsBlockedRead(t *testing.T) {
	t.Parallel()
	options, _, logger := workerFixture(t)
	entered := make(chan struct{}, 1)
	worker, err := New(options, workFunc(func(ctx context.Context, _ deployment.ID, _ Cursor, _ int) (Page, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return Page{}, ctx.Err()
	}), changeFunc(func(context.Context, ChangeIntent) (bool, error) {
		t.Error("blocked read released a change")
		return false, nil
	}), logger)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(worker.Shutdown(t.Context()), ErrWorkerNotStarted) {
		t.Fatal("unstarted shutdown")
	}
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := worker.Start(parent); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("worker never read")
	}
	cancel()
	if !worker.Snapshot().Running {
		t.Fatal("startup context stole worker ownership")
	}
	if !errors.Is(worker.Start(t.Context()), ErrWorkerStarted) {
		t.Fatal("duplicate start")
	}
	if err := worker.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-worker.Done():
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker leaked blocked read")
	}
	if worker.Snapshot().Running {
		t.Fatal("worker not stopped")
	}
}

func TestWorkerRejectsUnsafeBoundsAndTypedNil(t *testing.T) {
	t.Parallel()
	options, _, logger := workerFixture(t)
	var empty workFunc
	changes := changeFunc(func(context.Context, ChangeIntent) (bool, error) { return false, nil })
	if _, err := New(options, empty, changes, logger); !errors.Is(err, ErrInvalidWorker) {
		t.Fatal("typed nil accepted")
	}
	options.BatchSize = 129
	if _, err := New(options, workFunc(func(context.Context, deployment.ID, Cursor, int) (Page, error) { return Page{}, nil }), changes, logger); !errors.Is(err, ErrInvalidWorker) {
		t.Fatal("unbounded worker")
	}
}
