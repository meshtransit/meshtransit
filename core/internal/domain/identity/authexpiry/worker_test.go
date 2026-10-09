package authexpiry_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/authexpiry"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
	"go.uber.org/goleak"
)

func TestMain(main *testing.M) { goleak.VerifyTestMain(main) }

func TestNewRejectsUnsafeOwnership(t *testing.T) {
	t.Parallel()
	var missing *sweeper
	tests := []struct {
		name string
		edit func(*authexpiry.Options, *authexpiry.Dependencies)
	}{
		{name: "missing assignment", edit: func(o *authexpiry.Options, _ *authexpiry.Dependencies) {
			o.DeploymentID = deployment.ID{}
		}},
		{name: "short poll", edit: func(o *authexpiry.Options, _ *authexpiry.Dependencies) {
			o.PollInterval = 99 * time.Millisecond
		}},
		{name: "long poll", edit: func(o *authexpiry.Options, _ *authexpiry.Dependencies) {
			o.PollInterval = time.Minute + time.Nanosecond
		}},
		{name: "zero pass", edit: func(o *authexpiry.Options, _ *authexpiry.Dependencies) { o.PassTimeout = 0 }},
		{name: "long pass", edit: func(o *authexpiry.Options, _ *authexpiry.Dependencies) {
			o.PassTimeout = 30*time.Second + time.Nanosecond
		}},
		{name: "zero batch", edit: func(o *authexpiry.Options, _ *authexpiry.Dependencies) { o.BatchSize = 0 }},
		{name: "long batch", edit: func(o *authexpiry.Options, _ *authexpiry.Dependencies) { o.BatchSize = 129 }},
		{name: "nil sweeper", edit: func(_ *authexpiry.Options, d *authexpiry.Dependencies) { d.Sweeper = nil }},
		{name: "typed nil sweeper", edit: func(_ *authexpiry.Options, d *authexpiry.Dependencies) {
			d.Sweeper = missing
		}},
		{name: "nil observer", edit: func(_ *authexpiry.Options, d *authexpiry.Dependencies) { d.Observer = nil }},
		{name: "nil logger", edit: func(_ *authexpiry.Options, d *authexpiry.Dependencies) { d.Logger = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options, dependencies := fixture(t)
			test.edit(&options, &dependencies)
			if worker, err := authexpiry.New(options, dependencies); worker != nil ||
				!errors.Is(err, authexpiry.ErrInvalidWorker) {
				t.Fatal("unsafe worker constructed")
			}
		})
	}
}

func TestWorkerOwnsImmediateSequentialPassAndJoinedCleanup(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		options, dependencies := fixture(t)
		observer := dependencies.Observer.(*observations)
		var calls atomic.Int64
		cleanup := make(chan struct{})
		dependencies.Sweeper = &sweeper{run: func(ctx context.Context, dep deployment.ID) (oidcauth.ExpiryPass, error) {
			if dep != options.DeploymentID {
				t.Error("assignment changed")
			}
			calls.Add(1)
			<-ctx.Done()
			<-cleanup // Models joined independent rollback after cancellation.
			return oidcauth.ExpiryPass{Attempted: 1}, ctx.Err()
		}}
		worker := mustWorker(t, options, dependencies)
		if worker.Done() != nil || !errors.Is(worker.Shutdown(t.Context()), authexpiry.ErrWorkerNotStarted) {
			t.Fatal("stopped worker has work")
		}
		if err := worker.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		state := observer.snapshot()
		if calls.Load() != 1 || !state.running || state.active != 1 {
			t.Fatal("first pass not immediate")
		}
		// Time cannot create overlapping passes while one is owned.
		time.Sleep(500 * time.Millisecond)
		synctest.Wait()
		if calls.Load() != 1 || !errors.Is(worker.Start(t.Context()), authexpiry.ErrWorkerStarted) {
			t.Fatal("pass overlapped or worker restarted")
		}
		// No mutex is held across the blocked callback; even canceled shutdown signals it.
		canceled, cancel := context.WithCancel(t.Context())
		cancel()
		if err := worker.Shutdown(canceled); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case <-worker.Done():
			t.Fatal("Done released before cleanup joined")
		default:
		}
		close(cleanup)
		join(t, worker)
		state = observer.snapshot()
		if state.running || state.active != 0 || len(state.closed) != 1 ||
			state.closed[0].Outcome != authexpiry.Canceled {
			t.Fatal("canceled ownership/telemetry did not drain")
		}
		if err := worker.Shutdown(t.Context()); err != nil {
			t.Fatal("repeated shutdown failed", err)
		}
	})
}

func TestWorkerRejectsZeroAndCanceledStartupBeforeEffects(t *testing.T) {
	t.Parallel()
	var zero authexpiry.Worker
	var absent *authexpiry.Worker
	for _, worker := range []*authexpiry.Worker{&zero, absent} {
		if !errors.Is(worker.Start(t.Context()), authexpiry.ErrInvalidWorker) || worker.Done() != nil ||
			!errors.Is(worker.Shutdown(t.Context()), authexpiry.ErrInvalidWorker) {
			t.Fatal("invalid lifecycle accepted")
		}
	}
	options, dependencies := fixture(t)
	worker := mustWorker(t, options, dependencies)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var missingContext context.Context
	if !errors.Is(worker.Start(ctx), context.Canceled) || worker.Done() != nil ||
		!errors.Is(worker.Start(missingContext), authexpiry.ErrInvalidWorker) ||
		!errors.Is(worker.Shutdown(missingContext), authexpiry.ErrInvalidWorker) {
		t.Fatal("invalid context started work")
	}
}

func TestWorkerRejectsMalformedPassCounts(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		pass oidcauth.ExpiryPass
	}{
		{name: "negative", pass: oidcauth.ExpiryPass{Attempted: -1}},
		{name: "overflow", pass: oidcauth.ExpiryPass{Attempted: 9}},
		{name: "confirmation overflow", pass: oidcauth.ExpiryPass{Attempted: 1, Confirmed: 2}},
		{name: "incomplete success", pass: oidcauth.ExpiryPass{Attempted: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				options, dependencies := fixture(t)
				observer := dependencies.Observer.(*observations)
				dependencies.Sweeper = &sweeper{run: func(context.Context, deployment.ID) (oidcauth.ExpiryPass, error) {
					return test.pass, nil
				}}
				worker := mustWorker(t, options, dependencies)
				if err := worker.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				state := observer.snapshot()
				if len(state.closed) != 1 || state.closed[0].Outcome != authexpiry.Invalid ||
					state.closed[0].Pass != (oidcauth.ExpiryPass{}) || state.closed[0].BatchLimitReached {
					t.Fatal("malformed aggregate counts escaped")
				}
				if err := worker.Shutdown(t.Context()); err != nil {
					t.Fatal(err)
				}
				join(t, worker)
			})
		})
	}
}

func TestWorkerUnknownPassWaitsBeforeFreshSelectionAndKeepsLogsPrivate(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		options, dependencies := fixture(t)
		observer := dependencies.Observer.(*observations)
		var output bytes.Buffer
		dependencies.Logger = slog.New(slog.NewJSONHandler(&output, nil))
		var calls atomic.Int64
		dependencies.Sweeper = &sweeper{run: func(context.Context, deployment.ID) (oidcauth.ExpiryPass, error) {
			if calls.Add(1) == 1 {
				return oidcauth.ExpiryPass{Attempted: 2, Confirmed: 1},
					errors.Join(oidcauth.ErrCommitOutcomeUnknown, errors.New("private-provider-secret"))
			}
			return oidcauth.ExpiryPass{}, nil
		}}
		worker := mustWorker(t, options, dependencies)
		if err := worker.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		time.Sleep(options.PollInterval - time.Nanosecond)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("unknown pass retried without interval")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		state := observer.snapshot()
		if calls.Load() != 2 || len(state.closed) != 2 || state.closed[0].Outcome != authexpiry.CommitUnknown ||
			state.closed[1].Outcome != authexpiry.Empty {
			t.Fatal("fresh pass/outcomes invalid")
		}
		if strings.Contains(output.String(), "private-provider-secret") ||
			strings.Contains(output.String(), options.DeploymentID.String()) {
			t.Fatal("private data logged")
		}
		if err := worker.Shutdown(t.Context()); err != nil {
			t.Fatal(err)
		}
		join(t, worker)
	})
}

func TestWorkerBoundsPassAndStopsOnCleanupFailure(t *testing.T) {
	t.Parallel()
	for _, cleanupFailed := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "cleanup fatal"}[cleanupFailed], func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				options, dependencies := fixture(t)
				observer := dependencies.Observer.(*observations)
				dependencies.Sweeper = &sweeper{run: func(ctx context.Context, _ deployment.ID) (oidcauth.ExpiryPass, error) {
					<-ctx.Done()
					if cleanupFailed {
						return oidcauth.ExpiryPass{}, errors.Join(ctx.Err(), oidcauth.ErrExpiryCleanupFailed)
					}
					return oidcauth.ExpiryPass{}, ctx.Err()
				}}
				worker := mustWorker(t, options, dependencies)
				if err := worker.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
				time.Sleep(options.PassTimeout)
				synctest.Wait()
				if cleanupFailed {
					if err := <-worker.Done(); !errors.Is(err, authexpiry.ErrCleanupFailed) || observer.snapshot().running {
						t.Fatal("cleanup failure did not stop owner")
					}
				} else {
					state := observer.snapshot()
					if len(state.closed) != 1 || state.closed[0].Outcome != authexpiry.Deadline {
						t.Fatal("pass not deadline bounded")
					}
					if err := worker.Shutdown(t.Context()); err != nil {
						t.Fatal(err)
					}
					join(t, worker)
				}
			})
		})
	}
}

type sweeper struct {
	run func(context.Context, deployment.ID) (oidcauth.ExpiryPass, error)
}

func (s *sweeper) Sweep(ctx context.Context, dep deployment.ID) (oidcauth.ExpiryPass, error) {
	return s.run(ctx, dep)
}

type observations struct {
	mu sync.Mutex
	observationSnapshot
}

type observationSnapshot struct {
	running bool
	active  int
	closed  []authexpiry.Observation
}

func (o *observations) WorkerRunning(running bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.running = running
}
func (o *observations) PassOpened() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.active++
}
func (o *observations) PassClosed(observation authexpiry.Observation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.active--
	o.closed = append(o.closed, observation)
}

func (o *observations) snapshot() observationSnapshot {
	o.mu.Lock()
	defer o.mu.Unlock()
	return observationSnapshot{running: o.running, active: o.active,
		closed: append([]authexpiry.Observation{}, o.closed...)}
}

func fixture(t *testing.T) (authexpiry.Options, authexpiry.Dependencies) {
	t.Helper()
	dep, err := deployment.ParseID("01958000-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	return authexpiry.Options{
			DeploymentID: dep, BatchSize: 8, PollInterval: 100 * time.Millisecond, PassTimeout: time.Second,
		}, authexpiry.Dependencies{
			Sweeper: &sweeper{run: func(context.Context, deployment.ID) (oidcauth.ExpiryPass, error) {
				return oidcauth.ExpiryPass{}, nil
			}},
			Observer: &observations{observationSnapshot: observationSnapshot{closed: make([]authexpiry.Observation, 0)}},
			Logger:   slog.New(slog.DiscardHandler),
		}
}

func mustWorker(t *testing.T, options authexpiry.Options, dependencies authexpiry.Dependencies) *authexpiry.Worker {
	t.Helper()
	worker, err := authexpiry.New(options, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func join(t *testing.T, worker *authexpiry.Worker) {
	t.Helper()
	if err := <-worker.Done(); err != nil {
		t.Fatal(err)
	}
	if _, open := <-worker.Done(); open {
		t.Fatal("Done not closed")
	}
}
