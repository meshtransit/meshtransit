package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"testing/synctest"
	"time"
)

func TestApplicationRetainsResourcesWithoutJoin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                                 string
		serviceMissing, monitorMissing       bool
		serviceUnjoined, monitorUnjoined     bool
		shutdownSuccess, partialStartFailure bool
		unexpectedExit                       string
	}{
		{name: "service timeout", serviceUnjoined: true},
		{name: "service shutdown succeeds without done", serviceUnjoined: true, shutdownSuccess: true},
		{name: "monitor timeout", monitorUnjoined: true},
		{name: "monitor shutdown succeeds without done", monitorUnjoined: true, shutdownSuccess: true},
		{name: "missing service done", serviceMissing: true},
		{name: "missing monitor done", monitorMissing: true},
		{name: "partial start with unjoined service", serviceUnjoined: true, partialStartFailure: true},
		{name: "observed monitor exit with unjoined service", serviceUnjoined: true, unexpectedExit: "monitor"},
		{name: "observed service exit with unjoined monitor", monitorUnjoined: true, unexpectedExit: "service"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				monitor, service := newFakeMonitor(), newFakeService()
				resources := newFakeResourceCloser()
				readiness := &fakeReadiness{updates: make(chan bool, 2)}
				unjoinedShutdown := func(ctx context.Context) error {
					if test.shutdownSuccess {
						return nil
					}
					<-ctx.Done()
					return ctx.Err()
				}
				if test.serviceUnjoined || test.serviceMissing {
					service.shutdown = unjoinedShutdown
				}
				if test.monitorUnjoined || test.monitorMissing {
					monitor.shutdown = unjoinedShutdown
				}
				if test.serviceMissing {
					service.done = nil
				}
				if test.monitorMissing {
					monitor.done = nil
				}
				services := []OwnedService{{Name: "first", Service: service}}
				if test.partialStartFailure {
					second := newFakeService()
					second.startErr = errors.New("synthetic start failure")
					services = append(services, OwnedService{Name: "second", Service: second})
				}
				application, err := New(
					Options{Roles: []Role{RoleAPI}, ShutdownTimeout: time.Millisecond},
					readiness,
					monitor,
					resources,
					slog.New(slog.NewJSONHandler(io.Discard, nil)),
					services...,
				)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				result := make(chan error, 1)
				go func() { result <- application.Run(ctx) }()
				startupFailure := test.serviceMissing || test.monitorMissing || test.partialStartFailure
				if !startupFailure {
					if ready := <-readiness.updates; !ready {
						t.Fatal("admission did not open after complete startup")
					}
					switch test.unexpectedExit {
					case "monitor":
						monitor.done <- errors.New("synthetic monitor failure")
					case "service":
						service.done <- errors.New("synthetic service failure")
					default:
						cancel()
					}
				}
				synctest.Wait()
				if err := <-result; !errors.Is(err, ErrIncompleteShutdown) {
					t.Fatalf("Run() error = %v, want terminal incomplete shutdown", err)
				}
				select {
				case <-resources.closeCalled:
					t.Fatal("resources closed without every component join")
				default:
				}
				select {
				case <-monitor.shutdownCalled:
				default:
					t.Fatal("monitor stop was not signaled")
				}
				if !test.monitorMissing {
					select {
					case <-service.shutdownCalled:
					default:
						t.Fatal("service stop was not signaled")
					}
				}
				if !startupFailure && <-readiness.updates {
					t.Fatal("admission remained open after shutdown")
				}
			})
		})
	}
}

func TestApplicationClosesResourcesAfterReportedTermination(t *testing.T) {
	t.Parallel()
	componentErr := errors.New("synthetic terminal result")
	tests := []struct {
		name           string
		serviceResult  error
		monitorResult  error
		closedChannels bool
		unexpectedExit string
	}{
		{name: "service error still proves join", serviceResult: componentErr},
		{name: "monitor error still proves join", monitorResult: componentErr},
		{name: "closed channels prove join", closedChannels: true},
		{name: "already observed service result", unexpectedExit: "service"},
		{name: "already observed monitor result", unexpectedExit: "monitor"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				monitor, service := newFakeMonitor(), newFakeService()
				resources := newFakeResourceCloser()
				readiness := &fakeReadiness{updates: make(chan bool, 2)}
				service.shutdown = func(context.Context) error {
					switch {
					case test.unexpectedExit == "service":
					case test.closedChannels:
						close(service.done)
					default:
						service.done <- test.serviceResult
					}
					return nil
				}
				monitor.shutdown = func(context.Context) error {
					switch {
					case test.unexpectedExit == "monitor":
					case test.closedChannels:
						close(monitor.done)
					default:
						monitor.done <- test.monitorResult
					}
					return nil
				}
				application := mustApplicationWithResources(
					t,
					readiness,
					monitor,
					resources,
					service,
					time.Millisecond,
				)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				result := make(chan error, 1)
				go func() { result <- application.Run(ctx) }()
				<-readiness.updates
				switch test.unexpectedExit {
				case "service":
					service.done <- componentErr
				case "monitor":
					monitor.done <- componentErr
				default:
					cancel()
				}
				synctest.Wait()
				err := <-result
				if errors.Is(err, ErrIncompleteShutdown) {
					t.Fatalf("observed termination classified as incomplete: %v", err)
				}
				wantError := test.serviceResult != nil || test.monitorResult != nil || test.unexpectedExit != ""
				if wantError && !errors.Is(err, componentErr) {
					t.Fatalf("Run() error = %v, want terminal component result", err)
				}
				if !wantError && err != nil {
					t.Fatalf("Run() error = %v, want clean shutdown", err)
				}
				select {
				case <-resources.closeCalled:
				default:
					t.Fatal("resources retained after every observed join")
				}
			})
		})
	}
}

func TestApplicationRetainsResourcesDuringOwnedLateCleanup(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		readiness := &fakeReadiness{updates: make(chan bool, 2)}
		service := newFakeService()
		resources := newFakeResourceCloser()
		stop, release, cleanupEntered := make(chan struct{}), make(chan struct{}), make(chan struct{})
		service.start = func(context.Context) error {
			go func() {
				<-stop
				close(cleanupEntered)
				<-release
				service.done <- nil
			}()
			return nil
		}
		service.shutdown = func(ctx context.Context) error {
			close(stop)
			<-ctx.Done()
			return ctx.Err()
		}
		application := mustApplicationWithResources(
			t,
			readiness,
			newFakeMonitor(),
			resources,
			service,
			time.Millisecond,
		)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		result := make(chan error, 1)
		go func() { result <- application.Run(ctx) }()
		<-readiness.updates
		cancel()
		<-cleanupEntered
		synctest.Wait()
		runErr := <-result
		// Always release and join the fixture's owned goroutine, including failures.
		close(release)
		if err := <-service.done; err != nil {
			t.Fatalf("fixture cleanup failed: %v", err)
		}
		if !errors.Is(runErr, ErrIncompleteShutdown) || !errors.Is(runErr, context.DeadlineExceeded) {
			t.Fatalf("Run() error = %v, want bounded incomplete shutdown", runErr)
		}
		select {
		case <-resources.closeCalled:
			t.Fatal("resources closed while owned late cleanup had not joined")
		default:
		}
	})
}

func TestJoinOwnedKeepsEvidenceSeparateFromResult(t *testing.T) {
	t.Parallel()
	componentErr := errors.New("synthetic terminal deadline")
	tests := []struct {
		name   string
		done   chan error
		joined bool
		result error
	}{
		{name: "missing channel", joined: false, result: ErrUnexpectedServiceStop},
		{name: "open empty channel", done: make(chan error, 1), joined: false, result: context.Canceled},
		{name: "closed channel", done: make(chan error, 1), joined: true},
		{name: "published success", done: make(chan error, 1), joined: true},
		{name: "published failure", done: make(chan error, 1), joined: true, result: componentErr},
		{name: "published deadline failure", done: make(chan error, 1), joined: true, result: context.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if test.name == "closed channel" {
				close(test.done)
			} else if test.joined {
				test.done <- test.result
			}
			joined, err := joinOwned(ctx, "synthetic-owner", test.done)
			if joined != test.joined || !errors.Is(err, test.result) {
				t.Fatalf("joinOwned() = %t, %v; want %t, %v", joined, err, test.joined, test.result)
			}
		})
	}
}
