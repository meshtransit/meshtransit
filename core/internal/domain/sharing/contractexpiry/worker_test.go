package contractexpiry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/sharing"
)

type listFunc func(context.Context, deployment.ID, Cursor, int) (Page, error)

func (list listFunc) List(ctx context.Context, id deployment.ID, after Cursor, limit int) (Page, error) {
	return list(ctx, id, after, limit)
}

type expireFunc func(context.Context, deployment.ID, sharing.ContractID) (bool, error)

func (expire expireFunc) End(ctx context.Context, id deployment.ID, contract sharing.ContractID) (bool, error) {
	return expire(ctx, id, contract)
}

var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

func mustContract(t *testing.T, value string) sharing.ContractID {
	t.Helper()
	id, err := sharing.ParseContractID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testOptions(t *testing.T, batch int) Options {
	t.Helper()
	id, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	return Options{Kind: KindExpiry, DeploymentID: id, BatchSize: batch, PollInterval: 100 * time.Millisecond, OperationTimeout: time.Second}
}

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	list := listFunc(func(context.Context, deployment.ID, Cursor, int) (Page, error) { return Page{Done: true}, nil })
	expire := expireFunc(func(context.Context, deployment.ID, sharing.ContractID) (bool, error) { return false, nil })
	var nilList listFunc
	tests := []struct {
		name    string
		mutate  func(*Options)
		list    Candidates
		expire  Finalizer
		logger  *slog.Logger
		wantErr bool
	}{
		{name: "valid", mutate: func(*Options) {}, list: list, expire: expire, logger: discardLogger},
		{name: "device removal", mutate: func(o *Options) { o.Kind = KindDeviceRemoval }, list: list, expire: expire, logger: discardLogger},
		{name: "unknown kind", mutate: func(o *Options) { o.Kind = "renewal" }, list: list, expire: expire, logger: discardLogger, wantErr: true},
		{name: "missing kind", mutate: func(o *Options) { o.Kind = "" }, list: list, expire: expire, logger: discardLogger, wantErr: true},
		{name: "missing deployment", mutate: func(o *Options) { o.DeploymentID = deployment.ID{} }, list: list, expire: expire, logger: discardLogger, wantErr: true},
		{name: "batch too large", mutate: func(o *Options) { o.BatchSize = 129 }, list: list, expire: expire, logger: discardLogger, wantErr: true},
		{name: "poll too fast", mutate: func(o *Options) { o.PollInterval = time.Millisecond }, list: list, expire: expire, logger: discardLogger, wantErr: true},
		{name: "operation too long", mutate: func(o *Options) { o.OperationTimeout = time.Minute }, list: list, expire: expire, logger: discardLogger, wantErr: true},
		{name: "typed nil candidates", mutate: func(*Options) {}, list: nilList, expire: expire, logger: discardLogger, wantErr: true},
		{name: "missing finalizer", mutate: func(*Options) {}, list: list, logger: discardLogger, wantErr: true},
		{name: "missing logger", mutate: func(*Options) {}, list: list, expire: expire, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := testOptions(t, 2)
			test.mutate(&options)
			_, err := New(options, test.list, test.expire, test.logger)
			if (err != nil) != test.wantErr || test.wantErr && !errors.Is(err, ErrInvalidWorker) {
				t.Fatalf("New() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestPageIsValid(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	first := Candidate{ContractID: mustContract(t, "01890f00-0000-7000-8000-000000000010"), At: base}
	second := Candidate{ContractID: mustContract(t, "01890f00-0000-7000-8000-000000000011"), At: base}
	later := Candidate{ContractID: mustContract(t, "01890f00-0000-7000-8000-000000000001"), At: base.Add(time.Second)}
	at := func(candidate Candidate) Cursor {
		return Cursor{At: candidate.At, ContractID: candidate.ContractID}
	}
	tests := []struct {
		name  string
		page  Page
		after Cursor
		want  bool
	}{
		{name: "empty final page", page: Page{Done: true}, want: true},
		{name: "ordered full page", page: Page{Items: []Candidate{first, second}, Next: at(second)}, want: true},
		{name: "expiry orders before id", page: Page{Items: []Candidate{second, later}, Next: at(later)}, want: true},
		{name: "continues after cursor", page: Page{Items: []Candidate{later}, Done: true}, after: at(second), want: true},
		{name: "repeats cursor", page: Page{Items: []Candidate{second}, Done: true}, after: at(second)},
		{name: "reordered", page: Page{Items: []Candidate{second, first}, Next: at(first)}},
		{name: "duplicate", page: Page{Items: []Candidate{first, first}, Next: at(first)}},
		{name: "short page not done", page: Page{Items: []Candidate{first}, Next: at(first)}},
		{name: "next is not last item", page: Page{Items: []Candidate{first, second}, Next: at(first)}},
		{name: "too many items", page: Page{Items: []Candidate{first, second, later}, Done: true}},
		{name: "invalid contract", page: Page{Items: []Candidate{{At: base}}, Done: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := test.page.IsValid(test.after, 2); got != test.want {
				t.Fatalf("IsValid() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestSweepAdvancesPastFailuresAndRestartsWhenDone(t *testing.T) {
	t.Parallel()
	options := testOptions(t, 2)
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	failing := Candidate{ContractID: mustContract(t, "01890f00-0000-7000-8000-000000000010"), At: base}
	open := Candidate{ContractID: mustContract(t, "01890f00-0000-7000-8000-000000000011"), At: base}
	gone := Candidate{ContractID: mustContract(t, "01890f00-0000-7000-8000-000000000012"), At: base.Add(time.Second)}
	next := Cursor{At: open.At, ContractID: open.ContractID}
	reads := 0
	list := listFunc(func(_ context.Context, id deployment.ID, after Cursor, limit int) (Page, error) {
		reads++
		if id != options.DeploymentID || limit != 2 {
			t.Fatalf("List(%v, %d)", id, limit)
		}
		if reads == 1 {
			if !after.IsZero() {
				t.Fatal("first sweep must start at the zero cursor")
			}
			return Page{Items: []Candidate{failing, open}, Next: next}, nil
		}
		if after != next {
			t.Fatal("a failed contract must not block later contracts")
		}
		return Page{Items: []Candidate{gone}, Done: true}, nil
	})
	expire := expireFunc(func(_ context.Context, _ deployment.ID, contract sharing.ContractID) (bool, error) {
		switch contract {
		case failing.ContractID:
			return false, errors.New("lock timeout")
		case open.ContractID:
			return true, nil
		default:
			return false, nil
		}
	})
	worker, err := New(options, list, expire, discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	cursor := worker.sweep(ctx, Cursor{})
	if cursor != next {
		t.Fatalf("first sweep cursor = %+v", cursor)
	}
	if cursor = worker.sweep(ctx, cursor); !cursor.IsZero() {
		t.Fatalf("a completed sweep must restart, cursor = %+v", cursor)
	}
	got := worker.Snapshot()
	if got.Passes != 2 || got.Ended != 1 || got.Deferred != 1 || got.DiscoveryErrors != 0 {
		t.Fatalf("Snapshot() = %+v", got)
	}
}

func TestSweepRestartsAfterInvalidDiscovery(t *testing.T) {
	t.Parallel()
	options := testOptions(t, 1)
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	candidate := Candidate{ContractID: mustContract(t, "01890f00-0000-7000-8000-000000000010"), At: base}
	after := Cursor{At: candidate.At, ContractID: candidate.ContractID}
	tests := []struct {
		name string
		page Page
		err  error
	}{
		{name: "read failure", err: errors.New("unavailable")},
		{name: "stalled page", page: Page{Items: []Candidate{candidate}, Next: after}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			list := listFunc(func(context.Context, deployment.ID, Cursor, int) (Page, error) { return test.page, test.err })
			expire := expireFunc(func(context.Context, deployment.ID, sharing.ContractID) (bool, error) {
				t.Fatal("no contract may be finalized from an invalid page")
				return false, nil
			})
			worker, err := New(options, list, expire, discardLogger)
			if err != nil {
				t.Fatal(err)
			}
			if cursor := worker.sweep(t.Context(), after); !cursor.IsZero() {
				t.Fatalf("cursor = %+v, want restart", cursor)
			}
			if got := worker.Snapshot(); got.DiscoveryErrors != 1 || got.Ended != 0 {
				t.Fatalf("Snapshot() = %+v", got)
			}
		})
	}
}

func TestWorkerLifecycle(t *testing.T) {
	t.Parallel()
	listed := make(chan struct{}, 1)
	list := listFunc(func(context.Context, deployment.ID, Cursor, int) (Page, error) {
		select {
		case listed <- struct{}{}:
		default:
		}
		return Page{Done: true}, nil
	})
	expire := expireFunc(func(context.Context, deployment.ID, sharing.ContractID) (bool, error) { return false, nil })
	worker, err := New(testOptions(t, 1), list, expire, discardLogger)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Shutdown(t.Context()); !errors.Is(err, ErrWorkerNotStarted) {
		t.Fatalf("Shutdown() before Start error = %v", err)
	}
	if err := worker.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := worker.Start(t.Context()); !errors.Is(err, ErrWorkerStarted) {
		t.Fatalf("second Start() error = %v", err)
	}
	<-listed
	if err := worker.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-worker.Done():
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop")
	}
	if worker.Snapshot().Running {
		t.Fatal("stopped worker reports running")
	}
}
