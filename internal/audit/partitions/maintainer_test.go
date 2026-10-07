package partitions

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

type storeFunc func(context.Context, int) (int, error)

func (store storeFunc) EnsurePartitions(ctx context.Context, months int) (int, error) {
	return store(ctx, months)
}

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	store := storeFunc(func(context.Context, int) (int, error) { return 0, nil })
	var nilStore *struct{ Store }
	for _, test := range []struct {
		name    string
		options Options
		store   Store
		logger  *slog.Logger
	}{
		{name: "window too small", options: Options{MonthsAhead: 0, Interval: time.Hour, OperationTimeout: time.Second}, store: store, logger: discard},
		{name: "window too large", options: Options{MonthsAhead: 37, Interval: time.Hour, OperationTimeout: time.Second}, store: store, logger: discard},
		{name: "interval too short", options: Options{MonthsAhead: 3, Interval: time.Second, OperationTimeout: time.Second}, store: store, logger: discard},
		{name: "missing store", options: DefaultOptions(), logger: discard},
		{name: "typed nil store", options: DefaultOptions(), store: nilStore, logger: discard},
		{name: "missing logger", options: DefaultOptions(), store: store},
	} {
		if _, err := New(test.options, test.store, test.logger); !errors.Is(err, ErrInvalidMaintainer) {
			t.Errorf("%s: error = %v", test.name, err)
		}
	}
	if _, err := New(DefaultOptions(), store, discard); err != nil {
		t.Fatal(err)
	}
}

func TestPassCountsCreatedAndFailures(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	store := storeFunc(func(_ context.Context, months int) (int, error) {
		if months != 12 {
			t.Errorf("months = %d", months)
		}
		if calls.Add(1) == 1 {
			return 0, errors.New("unavailable")
		}
		return 2, nil
	})
	maintainer, err := New(DefaultOptions(), store, discard)
	if err != nil {
		t.Fatal(err)
	}
	maintainer.pass(t.Context())
	maintainer.pass(t.Context())
	got := maintainer.Snapshot()
	if got.Passes != 2 || got.Failed != 1 || got.Created != 2 {
		t.Fatalf("Snapshot() = %+v", got)
	}
}

func TestLifecycleRunsAtStartAndStops(t *testing.T) {
	t.Parallel()
	ran := make(chan struct{}, 1)
	store := storeFunc(func(context.Context, int) (int, error) {
		select {
		case ran <- struct{}{}:
		default:
		}
		return 0, nil
	})
	maintainer, err := New(DefaultOptions(), store, discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := maintainer.Shutdown(t.Context()); !errors.Is(err, ErrMaintainerNotStarted) {
		t.Fatalf("Shutdown() before Start = %v", err)
	}
	if err := maintainer.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := maintainer.Start(t.Context()); !errors.Is(err, ErrMaintainerStarted) {
		t.Fatalf("second Start() = %v", err)
	}
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("first pass did not run at start")
	}
	if err := maintainer.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-maintainer.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("maintainer did not stop")
	}
}
