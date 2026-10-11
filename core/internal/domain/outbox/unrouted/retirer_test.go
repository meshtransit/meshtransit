package unrouted

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

type storeFunc func(context.Context, string, int) (int, error)

func (store storeFunc) RetireUnroutedEvents(ctx context.Context, workerID string, limit int) (int, error) {
	return store(ctx, workerID, limit)
}

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	store := storeFunc(func(context.Context, string, int) (int, error) { return 0, nil })
	var nilStore *struct{ Store }
	valid := DefaultOptions("worker-1")
	for _, test := range []struct {
		name    string
		options Options
		store   Store
		logger  *slog.Logger
	}{
		{name: "no worker", options: DefaultOptions(""), store: store, logger: discard},
		{name: "empty batch", options: Options{WorkerID: "w", BatchSize: 0, Interval: time.Minute, OperationTimeout: time.Second}, store: store, logger: discard},
		{name: "batch too large", options: Options{WorkerID: "w", BatchSize: 257, Interval: time.Minute, OperationTimeout: time.Second}, store: store, logger: discard},
		{name: "interval too short", options: Options{WorkerID: "w", BatchSize: 1, Interval: time.Millisecond, OperationTimeout: time.Second}, store: store, logger: discard},
		{name: "missing store", options: valid, logger: discard},
		{name: "typed nil store", options: valid, store: nilStore, logger: discard},
		{name: "missing logger", options: valid, store: store},
	} {
		if _, err := New(test.options, test.store, test.logger); !errors.Is(err, ErrInvalidRetirer) {
			t.Errorf("%s: error = %v", test.name, err)
		}
	}
	if _, err := New(valid, store, discard); err != nil {
		t.Fatal(err)
	}
}

func TestPassDrainsFullBatchesAndCountsFailures(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	results := []int{4, 4, 1}
	store := storeFunc(func(_ context.Context, workerID string, limit int) (int, error) {
		if workerID != "worker-1" || limit != 4 {
			t.Errorf("call = (%q, %d)", workerID, limit)
		}
		call := int(calls.Add(1))
		if call <= len(results) {
			return results[call-1], nil
		}
		return 0, errors.New("unavailable")
	})
	options := DefaultOptions("worker-1")
	options.BatchSize = 4
	retirer, err := New(options, store, discard)
	if err != nil {
		t.Fatal(err)
	}
	retirer.pass(t.Context())
	if got := retirer.Snapshot(); got.Retired != 9 || got.Failed != 0 || calls.Load() != 3 {
		t.Fatalf("after drain: %+v, calls %d", got, calls.Load())
	}
	retirer.pass(t.Context())
	if got := retirer.Snapshot(); got.Failed != 1 || got.Passes != 2 {
		t.Fatalf("after failure: %+v", got)
	}
}

func TestPassStopsAfterBoundedBatches(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	store := storeFunc(func(_ context.Context, _ string, limit int) (int, error) {
		calls.Add(1)
		return limit, nil
	})
	options := DefaultOptions("worker-1")
	options.BatchSize = 1
	retirer, err := New(options, store, discard)
	if err != nil {
		t.Fatal(err)
	}
	retirer.pass(t.Context())
	if calls.Load() != maxBatchesPerPass {
		t.Fatalf("calls = %d, want %d", calls.Load(), maxBatchesPerPass)
	}
}

func TestLifecycle(t *testing.T) {
	t.Parallel()
	ran := make(chan struct{}, 1)
	store := storeFunc(func(context.Context, string, int) (int, error) {
		select {
		case ran <- struct{}{}:
		default:
		}
		return 0, nil
	})
	retirer, err := New(DefaultOptions("worker-1"), store, discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := retirer.Shutdown(t.Context()); !errors.Is(err, ErrRetirerNotStarted) {
		t.Fatalf("Shutdown before Start = %v", err)
	}
	if err := retirer.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := retirer.Start(t.Context()); !errors.Is(err, ErrRetirerStarted) {
		t.Fatalf("second Start = %v", err)
	}
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("first pass did not run")
	}
	if err := retirer.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-retirer.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("retirer did not stop")
	}
}
