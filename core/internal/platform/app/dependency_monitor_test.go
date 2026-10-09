package app

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestNewDependencyMonitorRequiresExactCheckerSet(t *testing.T) {
	t.Parallel()

	state := mustRuntimeState(t, RoleAPI)
	postgres := &fakeChecker{component: ComponentPostgreSQL}
	redis := &fakeChecker{component: ComponentRedis}
	var typedNil *fakeChecker
	options := MonitorOptions{CheckTimeout: time.Second, CheckInterval: 5 * time.Second}

	tests := []struct {
		name     string
		state    *RuntimeState
		options  MonitorOptions
		checkers []DependencyChecker
	}{
		{name: "missing state", options: options, checkers: []DependencyChecker{postgres, redis}},
		{name: "missing timeout", state: state, options: MonitorOptions{CheckInterval: time.Second}, checkers: []DependencyChecker{postgres, redis}},
		{name: "missing interval", state: state, options: MonitorOptions{CheckTimeout: time.Second}, checkers: []DependencyChecker{postgres, redis}},
		{name: "timeout at interval", state: state, options: MonitorOptions{CheckTimeout: time.Second, CheckInterval: time.Second}, checkers: []DependencyChecker{postgres, redis}},
		{name: "missing redis", state: state, options: options, checkers: []DependencyChecker{postgres}},
		{name: "duplicate postgres", state: state, options: options, checkers: []DependencyChecker{postgres, postgres, redis}},
		{name: "unknown checker", state: state, options: options, checkers: []DependencyChecker{postgres, redis, &fakeChecker{component: ComponentUnknown}}},
		{name: "typed nil checker", state: state, options: options, checkers: []DependencyChecker{postgres, redis, typedNil}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			monitor, err := NewDependencyMonitor(test.options, test.state, test.checkers...)
			if !errors.Is(err, ErrInvalidDependencyMonitor) {
				t.Fatalf("NewDependencyMonitor() error = %v, want ErrInvalidDependencyMonitor", err)
			}
			if monitor != nil {
				t.Fatalf("NewDependencyMonitor() = %v, want nil", monitor)
			}
		})
	}
}

func TestDependencyMonitorInitialCheckFailsClosed(t *testing.T) {
	t.Parallel()

	state := mustRuntimeState(t, RoleWorker)
	postgres := &fakeChecker{component: ComponentPostgreSQL}
	redis := &fakeChecker{component: ComponentRedis, err: errors.New("connection detail must remain internal")}
	monitor := mustMonitor(t, state, postgres, redis)

	err := monitor.Start(context.Background())
	if !errors.Is(err, ErrDependencyUnavailable) {
		t.Fatalf("Start() error = %v, want ErrDependencyUnavailable", err)
	}
	if got := state.Snapshot().Components["redis"]; got != "unavailable" {
		t.Fatalf("redis status = %q, want unavailable", got)
	}
	if monitor.Done() != nil {
		t.Fatal("Done() != nil after failed initial check")
	}
}

func TestDependencyMonitorStartsWhenIsolatedLoginDependencyIsUnavailable(t *testing.T) {
	t.Parallel()

	state, err := NewRuntimeState(
		[]Role{RoleAPI, RoleControl, RoleWorker, RoleRelay, RoleIdentity},
		ComponentPrivateLogin,
	)
	if err != nil {
		t.Fatal(err)
	}
	monitor := mustMonitor(
		t,
		state,
		&fakeChecker{component: ComponentPostgreSQL},
		&fakeChecker{component: ComponentRedis},
		&fakeChecker{component: ComponentIdentityPostgreSQL, err: errors.New("identity database unavailable")},
		&fakeChecker{component: ComponentIdentityConfiguration, err: errors.New("identity drift")},
		&fakeChecker{component: ComponentIdentitySigner, err: errors.New("identity signer unavailable")},
		&fakeChecker{component: ComponentPrivateLogin, err: errors.New("provider unavailable")},
	)
	if err := monitor.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	state.SetReady(true)
	if !state.Ready() || state.Snapshot().LoginReady {
		t.Fatal("isolated login outage changed Core admission")
	}
	if err := monitor.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-monitor.Done(); err != nil {
		t.Fatal(err)
	}
}

func TestDependencyMonitorTracksLossAndRecovery(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		state := mustRuntimeState(t, RoleControl)
		postgres := &fakeChecker{component: ComponentPostgreSQL}
		redis := &fakeChecker{component: ComponentRedis}
		monitor := mustMonitor(t, state, postgres, redis)
		if err := monitor.Start(t.Context()); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		state.SetReady(true)
		if !state.Ready() {
			t.Fatal("Ready() = false after successful initial check")
		}

		redis.setError(errors.New("temporary outage"))
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if state.Ready() {
			t.Fatal("Ready() = true after dependency loss")
		}

		redis.setError(nil)
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if !state.Ready() {
			t.Fatal("Ready() = false after dependency recovery")
		}

		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := monitor.Shutdown(ctx); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		if err := <-monitor.Done(); err != nil {
			t.Fatalf("Done() error = %v", err)
		}
	})
}

func TestDependencyMonitorBoundsChecks(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		state := mustRuntimeState(t, RoleAPI)
		postgres := &fakeChecker{
			component: ComponentPostgreSQL,
			check: func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			},
		}
		redis := &fakeChecker{component: ComponentRedis}
		monitor := mustMonitor(t, state, postgres, redis)

		start := time.Now()
		err := monitor.Start(t.Context())
		if !errors.Is(err, ErrDependencyUnavailable) {
			t.Fatalf("Start() error = %v, want ErrDependencyUnavailable", err)
		}
		if elapsed := time.Since(start); elapsed != time.Second {
			t.Fatalf("initial check elapsed = %s, want 1s", elapsed)
		}
	})
}

func TestDependencyMonitorShutdownDuringStartPreventsLateWorker(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		state := mustRuntimeState(t, RoleAPI)
		checkStarted := make(chan struct{})
		postgres := &fakeChecker{
			component: ComponentPostgreSQL,
			check: func(ctx context.Context) error {
				close(checkStarted)
				<-ctx.Done()
				return ctx.Err()
			},
		}
		redis := &fakeChecker{component: ComponentRedis}
		monitor := mustMonitor(t, state, postgres, redis)

		startResult := make(chan error, 1)
		go func() {
			startResult <- monitor.Start(t.Context())
		}()
		<-checkStarted

		shutdownResult := make(chan error, 1)
		go func() {
			shutdownResult <- monitor.Shutdown(t.Context())
		}()
		synctest.Wait()

		if err := <-shutdownResult; err != nil {
			t.Fatalf("Shutdown() error = %v, want nil", err)
		}
		if err := <-startResult; !errors.Is(err, context.Canceled) {
			t.Fatalf("Start() error = %v, want context canceled", err)
		}
		if monitor.Done() != nil {
			t.Fatal("Done() != nil after shutdown canceled startup")
		}
	})
}

func TestDependencyMonitorShutdownCancelsInFlightCheckAndJoins(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		state := mustRuntimeState(t, RoleControl)
		periodicCheckStarted := make(chan struct{})
		var calls atomic.Int32
		postgres := &fakeChecker{
			component: ComponentPostgreSQL,
			check: func(ctx context.Context) error {
				if calls.Add(1) == 1 {
					return nil
				}
				close(periodicCheckStarted)
				<-ctx.Done()
				return ctx.Err()
			},
		}
		redis := &fakeChecker{component: ComponentRedis}
		monitor := mustMonitor(t, state, postgres, redis)
		if err := monitor.Start(t.Context()); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		time.Sleep(5 * time.Second)
		synctest.Wait()
		<-periodicCheckStarted
		if err := monitor.Shutdown(t.Context()); err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		synctest.Wait()
		if err := <-monitor.Done(); err != nil {
			t.Fatalf("Done() error = %v", err)
		}
	})
}

func mustRuntimeState(t *testing.T, roles ...Role) *RuntimeState {
	t.Helper()

	state, err := NewRuntimeState(roles)
	if err != nil {
		t.Fatalf("NewRuntimeState() error = %v", err)
	}
	return state
}

func mustMonitor(t *testing.T, state *RuntimeState, checkers ...DependencyChecker) *DependencyMonitor {
	t.Helper()

	monitor, err := NewDependencyMonitor(
		MonitorOptions{CheckTimeout: time.Second, CheckInterval: 5 * time.Second},
		state,
		checkers...,
	)
	if err != nil {
		t.Fatalf("NewDependencyMonitor() error = %v", err)
	}
	return monitor
}

type fakeChecker struct {
	mu        sync.Mutex
	component Component
	err       error
	check     func(context.Context) error
}

func (checker *fakeChecker) Component() Component {
	return checker.component
}

func (checker *fakeChecker) Check(ctx context.Context) error {
	checker.mu.Lock()
	check := checker.check
	err := checker.err
	checker.mu.Unlock()
	if check != nil {
		return check(ctx)
	}
	return err
}

func (checker *fakeChecker) setError(err error) {
	checker.mu.Lock()
	defer checker.mu.Unlock()
	checker.err = err
}
