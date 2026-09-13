package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestNewRejectsInvalidLifecycleInputs(t *testing.T) {
	t.Parallel()

	validOptions := Options{Roles: []Role{RoleAPI}, ShutdownTimeout: time.Second}
	readiness := &fakeReadiness{updates: make(chan bool, 2)}
	monitor := newFakeMonitor()
	service := newFakeService()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	var typedNilReadiness *fakeReadiness
	var typedNilMonitor *fakeMonitor
	var typedNilService *fakeService

	tests := []struct {
		name      string
		options   Options
		readiness Readiness
		monitor   Monitor
		service   Service
		logger    *slog.Logger
	}{
		{name: "missing roles", options: Options{ShutdownTimeout: time.Second}, readiness: readiness, monitor: monitor, service: service, logger: logger},
		{name: "aggregate role", options: Options{Roles: []Role{RoleAll}, ShutdownTimeout: time.Second}, readiness: readiness, monitor: monitor, service: service, logger: logger},
		{name: "unknown role value", options: Options{Roles: []Role{Role(99)}, ShutdownTimeout: time.Second}, readiness: readiness, monitor: monitor, service: service, logger: logger},
		{name: "duplicate role", options: Options{Roles: []Role{RoleAPI, RoleAPI}, ShutdownTimeout: time.Second}, readiness: readiness, monitor: monitor, service: service, logger: logger},
		{name: "unbounded shutdown", options: Options{Roles: []Role{RoleAPI}}, readiness: readiness, monitor: monitor, service: service, logger: logger},
		{name: "missing readiness", options: validOptions, monitor: monitor, service: service, logger: logger},
		{name: "typed nil readiness", options: validOptions, readiness: typedNilReadiness, monitor: monitor, service: service, logger: logger},
		{name: "missing monitor", options: validOptions, readiness: readiness, service: service, logger: logger},
		{name: "typed nil monitor", options: validOptions, readiness: readiness, monitor: typedNilMonitor, service: service, logger: logger},
		{name: "missing service", options: validOptions, readiness: readiness, monitor: monitor, logger: logger},
		{name: "typed nil service", options: validOptions, readiness: readiness, monitor: monitor, service: typedNilService, logger: logger},
		{name: "missing logger", options: validOptions, readiness: readiness, monitor: monitor, service: service},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			application, err := New(test.options, test.readiness, test.monitor, test.service, test.logger)
			if !errors.Is(err, ErrInvalidApplication) {
				t.Fatalf("New() error = %v, want ErrInvalidApplication", err)
			}
			if application != nil {
				t.Fatalf("New() = %v, want nil", application)
			}
		})
	}
}

func TestApplicationRunOwnsReadinessAndShutdown(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		readiness := &fakeReadiness{updates: make(chan bool, 2)}
		monitor := newFakeMonitor()
		service := newFakeService()
		application := mustApplication(t, readiness, monitor, service, 100*time.Millisecond)
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		result := make(chan error, 1)
		go func() {
			result <- application.Run(ctx)
		}()

		<-monitor.started
		<-service.started
		if ready := <-readiness.updates; !ready {
			t.Fatal("readiness did not open after service start")
		}
		cancel()
		synctest.Wait()

		<-service.shutdownCalled
		if ready := <-readiness.updates; ready {
			t.Fatal("readiness did not close before shutdown")
		}
		if err := <-result; err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		select {
		case <-monitor.shutdownCalled:
		default:
			t.Fatal("dependency monitor shutdown was not called")
		}
		if !reflect.DeepEqual(application.roles, []Role{RoleAPI}) {
			t.Fatalf("application roles = %v, want [api]", application.roles)
		}
	})
}

func TestApplicationRunReturnsStartFailure(t *testing.T) {
	t.Parallel()

	startErr := errors.New("bind failed")
	readiness := &fakeReadiness{updates: make(chan bool, 1)}
	monitor := newFakeMonitor()
	service := newFakeService()
	service.startErr = startErr
	application := mustApplication(t, readiness, monitor, service, time.Second)

	err := application.Run(context.Background())
	if !errors.Is(err, startErr) {
		t.Fatalf("Run() error = %v, want start error", err)
	}
	select {
	case update := <-readiness.updates:
		t.Fatalf("unexpected readiness update: %v", update)
	default:
	}
	select {
	case <-monitor.shutdownCalled:
	default:
		t.Fatal("monitor was not cleaned up after service start failure")
	}
}

func TestApplicationRunReturnsMonitorStartFailureBeforeServiceStart(t *testing.T) {
	t.Parallel()

	startErr := errors.New("dependency check failed")
	readiness := &fakeReadiness{updates: make(chan bool, 1)}
	monitor := newFakeMonitor()
	monitor.startErr = startErr
	service := newFakeService()
	application := mustApplication(t, readiness, monitor, service, time.Second)

	err := application.Run(context.Background())
	if !errors.Is(err, startErr) {
		t.Fatalf("Run() error = %v, want monitor start error", err)
	}
	select {
	case <-service.started:
		t.Fatal("service started before dependency monitor succeeded")
	default:
	}
}

func TestApplicationRunReturnsUnexpectedServiceFailure(t *testing.T) {
	t.Parallel()

	serviceErr := errors.New("listener failed")
	readiness := &fakeReadiness{updates: make(chan bool, 2)}
	monitor := newFakeMonitor()
	service := newFakeService()
	application := mustApplication(t, readiness, monitor, service, time.Second)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	result := make(chan error, 1)
	go func() {
		result <- application.Run(ctx)
	}()

	<-service.started
	if ready := <-readiness.updates; !ready {
		t.Fatal("readiness did not open after service start")
	}
	service.done <- serviceErr

	if err := <-result; !errors.Is(err, serviceErr) {
		t.Fatalf("Run() error = %v, want service error", err)
	}
	if ready := <-readiness.updates; ready {
		t.Fatal("readiness did not close after service failure")
	}
}

func TestApplicationRunCleansServiceAfterUnexpectedMonitorExit(t *testing.T) {
	t.Parallel()

	monitorErr := errors.New("monitor failed")
	readiness := &fakeReadiness{updates: make(chan bool, 2)}
	monitor := newFakeMonitor()
	service := newFakeService()
	application := mustApplication(t, readiness, monitor, service, time.Second)
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	result := make(chan error, 1)
	go func() {
		result <- application.Run(ctx)
	}()

	<-service.started
	if ready := <-readiness.updates; !ready {
		t.Fatal("readiness did not open after service start")
	}
	monitor.done <- monitorErr

	if err := <-result; !errors.Is(err, monitorErr) {
		t.Fatalf("Run() error = %v, want monitor error", err)
	}
	if ready := <-readiness.updates; ready {
		t.Fatal("readiness did not close after monitor failure")
	}
	select {
	case <-service.shutdownCalled:
	default:
		t.Fatal("service was not cleaned up after monitor failure")
	}
}

func TestApplicationRunBoundsShutdown(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		readiness := &fakeReadiness{updates: make(chan bool, 2)}
		monitor := newFakeMonitor()
		service := newFakeService()
		service.shutdown = func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		}
		application := mustApplication(t, readiness, monitor, service, time.Millisecond)
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		result := make(chan error, 1)
		go func() {
			result <- application.Run(ctx)
		}()

		<-service.started
		<-readiness.updates
		cancel()
		synctest.Wait()

		err := <-result
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Run() error = %v, want context deadline exceeded", err)
		}
		if ready := <-readiness.updates; ready {
			t.Fatal("readiness did not close before bounded shutdown")
		}
	})
}

func mustApplication(
	t *testing.T,
	readiness Readiness,
	monitor Monitor,
	service Service,
	shutdownTimeout time.Duration,
) *Application {
	t.Helper()

	application, err := New(
		Options{Roles: []Role{RoleAPI}, ShutdownTimeout: shutdownTimeout},
		readiness,
		monitor,
		service,
		slog.New(slog.NewJSONHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return application
}

type fakeMonitor struct {
	started        chan struct{}
	shutdownCalled chan struct{}
	done           chan error
	startErr       error
	shutdown       func(context.Context) error
	startOnce      sync.Once
	shutdownOnce   sync.Once
}

func newFakeMonitor() *fakeMonitor {
	return &fakeMonitor{
		started:        make(chan struct{}),
		shutdownCalled: make(chan struct{}),
		done:           make(chan error, 1),
	}
}

func (monitor *fakeMonitor) Start(context.Context) error {
	if monitor.startErr != nil {
		return monitor.startErr
	}
	monitor.startOnce.Do(func() { close(monitor.started) })
	return nil
}

func (monitor *fakeMonitor) Shutdown(ctx context.Context) error {
	monitor.shutdownOnce.Do(func() {
		close(monitor.shutdownCalled)
		if monitor.shutdown == nil {
			monitor.done <- nil
		}
	})
	if monitor.shutdown != nil {
		return monitor.shutdown(ctx)
	}
	return nil
}

func (monitor *fakeMonitor) Done() <-chan error {
	return monitor.done
}

type fakeReadiness struct {
	updates chan bool
}

func (readiness *fakeReadiness) SetReady(ready bool) {
	readiness.updates <- ready
}

type fakeService struct {
	mu             sync.Mutex
	started        chan struct{}
	shutdownCalled chan struct{}
	done           chan error
	startErr       error
	shutdown       func(context.Context) error
}

func newFakeService() *fakeService {
	return &fakeService{
		started:        make(chan struct{}),
		shutdownCalled: make(chan struct{}),
		done:           make(chan error, 1),
	}
}

func (service *fakeService) Start(context.Context) error {
	if service.startErr != nil {
		return service.startErr
	}
	close(service.started)
	return nil
}

func (service *fakeService) Shutdown(ctx context.Context) error {
	service.mu.Lock()
	shutdown := service.shutdown
	service.mu.Unlock()
	close(service.shutdownCalled)
	if shutdown != nil {
		return shutdown(ctx)
	}
	service.done <- nil
	return nil
}

func (service *fakeService) Done() <-chan error {
	return service.done
}
