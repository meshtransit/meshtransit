package retention

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

// scriptedStore answers each kind from a queue of batch sizes and records
// the order of calls.
type scriptedStore struct {
	idempotency, outbox, audit []int
	failAudit                  bool
	calls                      []string
	limits                     []int
}

func next(queue *[]int) int {
	if len(*queue) == 0 {
		return 0
	}
	value := (*queue)[0]
	*queue = (*queue)[1:]
	return value
}

func (store *scriptedStore) PruneIdempotency(_ context.Context, grace time.Duration, limit int) (int, error) {
	if grace != 24*time.Hour {
		return 0, errors.New("unexpected grace")
	}
	store.calls, store.limits = append(store.calls, "idempotency"), append(store.limits, limit)
	return next(&store.idempotency), nil
}

func (store *scriptedStore) PruneOutbox(_ context.Context, delivered, terminal, _ int) (OutboxRemoved, error) {
	if delivered != 7 || terminal != 30 {
		return OutboxRemoved{}, errors.New("unexpected outbox policy")
	}
	store.calls = append(store.calls, "outbox")
	events := next(&store.outbox)
	return OutboxRemoved{Events: events, Attempts: 2 * events}, nil
}

func (store *scriptedStore) DropAuditPartitions(_ context.Context, keepMonths int) ([]string, error) {
	if keepMonths != 12 {
		return nil, errors.New("unexpected audit policy")
	}
	store.calls = append(store.calls, "partitions")
	if store.failAudit {
		return nil, ErrBusy
	}
	return []string{"audit_event_2025_10"}, nil
}

func (store *scriptedStore) PruneAudit(_ context.Context, keepMonths, _ int) (AuditRemoved, error) {
	if keepMonths != 12 {
		return AuditRemoved{}, errors.New("unexpected audit policy")
	}
	store.calls = append(store.calls, "audit")
	rows := next(&store.audit)
	return AuditRemoved{Identities: rows, Mutations: rows / 2}, nil
}

func options(batch, batches int) Options {
	return Options{Policy: DefaultPolicy(), BatchSize: batch, MaxBatches: batches, Interval: time.Hour,
		OperationTimeout: time.Second}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestPassRemovesEachKindUntilABatchIsNotFull(t *testing.T) {
	t.Parallel()
	store := &scriptedStore{idempotency: []int{10, 10, 3}, outbox: []int{4}, audit: []int{10, 0}}
	maintainer, err := New(options(10, 20), store, quiet())
	if err != nil {
		t.Fatal(err)
	}
	maintainer.Pass(context.Background())
	want := []string{"idempotency", "idempotency", "idempotency", "outbox", "partitions", "audit", "audit"}
	if len(store.calls) != len(want) {
		t.Fatalf("calls = %v, want %v", store.calls, want)
	}
	for index := range want {
		if store.calls[index] != want[index] {
			t.Fatalf("calls = %v, want %v", store.calls, want)
		}
	}
	got := maintainer.Snapshot()
	if got.IdempotencyRecords != 23 || got.OutboxEvents != 4 || got.OutboxAttempts != 8 ||
		got.AuditRows != 15 || got.AuditPartitions != 1 || got.Failed != 0 || got.LastWholePass.IsZero() {
		t.Fatalf("measurements = %+v", got)
	}
}

func TestPassStopsAKindAtItsBatchBudget(t *testing.T) {
	t.Parallel()
	store := &scriptedStore{idempotency: []int{5, 5, 5, 5, 5}}
	maintainer, err := New(options(5, 3), store, quiet())
	if err != nil {
		t.Fatal(err)
	}
	maintainer.Pass(context.Background())
	if got := maintainer.Snapshot().IdempotencyRecords; got != 15 {
		t.Fatalf("removed %d idempotency records, want 15 (three batches)", got)
	}
}

func TestFailedPassIsCountedAndNotWhole(t *testing.T) {
	t.Parallel()
	store := &scriptedStore{failAudit: true}
	maintainer, err := New(options(10, 2), store, quiet())
	if err != nil {
		t.Fatal(err)
	}
	maintainer.Pass(context.Background())
	got := maintainer.Snapshot()
	if got.Failed != 1 || !got.LastWholePass.IsZero() {
		t.Fatalf("measurements = %+v, want one failure and no whole pass", got)
	}
}

func TestNewRejectsUnsafeBounds(t *testing.T) {
	t.Parallel()
	store := &scriptedStore{}
	for name, mutate := range map[string]func(*Options){
		"no Activity kept":          func(o *Options) { o.Policy.AuditKeepMonths = 0 },
		"terminal before delivered": func(o *Options) { o.Policy.OutboxTerminalDays = 3 },
		"grace under an hour":       func(o *Options) { o.Policy.IdempotencyGrace = time.Minute },
		"batch over the function":   func(o *Options) { o.BatchSize = 5001 },
		"tight loop":                func(o *Options) { o.Interval = time.Second },
	} {
		bad := DefaultOptions()
		mutate(&bad)
		if _, err := New(bad, store, quiet()); !errors.Is(err, ErrInvalidMaintainer) {
			t.Errorf("%s: err = %v, want ErrInvalidMaintainer", name, err)
		}
	}
	var missing *scriptedStore
	if _, err := New(DefaultOptions(), missing, quiet()); !errors.Is(err, ErrInvalidMaintainer) {
		t.Errorf("nil store: err = %v", err)
	}
}

func TestMaintainerStartsOnceAndStops(t *testing.T) {
	t.Parallel()
	maintainer, err := New(DefaultOptions(), &scriptedStore{}, quiet())
	if err != nil {
		t.Fatal(err)
	}
	if err := maintainer.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := maintainer.Start(context.Background()); !errors.Is(err, ErrMaintainerStarted) {
		t.Fatalf("second start: %v", err)
	}
	if err := maintainer.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-maintainer.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("maintainer did not stop")
	}
}
