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
	resources := newFakeResourceCloser()
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

			application, err := New(
				test.options,
				test.readiness,
				test.monitor,
				resources,
				test.logger,
				OwnedService{Name: "health", Service: test.service},
			)
			if !errors.Is(err, ErrInvalidApplication) {
				t.Fatalf("New() error = %v, want ErrInvalidApplication", err)
			}
			if application != nil {
				t.Fatalf("New() = %v, want nil", application)
			}
		})
	}
}

func TestNewRejectsInvalidOwnedServices(t *testing.T) {
	t.Parallel()

	options := Options{Roles: []Role{RoleAPI}, ShutdownTimeout: time.Second}
	readiness := &fakeReadiness{updates: make(chan bool, 1)}
	monitor := newFakeMonitor()
	resources := newFakeResourceCloser()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	service := newFakeService()
	var typedNil *fakeService

	tests := []struct {
		name     string
		services []OwnedService
	}{
		{name: "missing services"},
		{name: "missing name", services: []OwnedService{{Service: service}}},
		{name: "unsafe name", services: []OwnedService{{Name: "Health Server", Service: service}}},
		{name: "missing service", services: []OwnedService{{Name: "health"}}},
		{name: "typed nil service", services: []OwnedService{{Name: "health", Service: typedNil}}},
		{
			name: "duplicate name",
			services: []OwnedService{
				{Name: "health", Service: service},
				{Name: "health", Service: newFakeService()},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			application, err := New(options, readiness, monitor, resources, logger, test.services...)
			if !errors.Is(err, ErrInvalidApplication) {
				t.Fatalf("New() error = %v, want ErrInvalidApplication", err)
			}
			if application != nil {
				t.Fatalf("New() = %v, want nil", application)
			}
		})
	}
}

func TestNewRejectsInvalidResourceCloser(t *testing.T) {
	t.Parallel()

	options := Options{Roles: []Role{RoleAPI}, ShutdownTimeout: time.Second}
	readiness := &fakeReadiness{updates: make(chan bool, 1)}
	monitor := newFakeMonitor()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	service := newFakeService()
	var typedNil *fakeResourceCloser

	for _, resources := range []ResourceCloser{nil, typedNil} {
		application, err := New(
			options,
			readiness,
			monitor,
			resources,
			logger,
			OwnedService{Name: "health", Service: service},
		)
		if !errors.Is(err, ErrInvalidApplication) {
			t.Fatalf("New() error = %v, want ErrInvalidApplication", err)
		}
		if application != nil {
			t.Fatalf("New() = %v, want nil", application)
		}
	}
}

func TestApplicationRunOwnsReadinessAndShutdown(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		readiness := &fakeReadiness{updates: make(chan bool, 2)}
		monitor := newFakeMonitor()
		resources := newFakeResourceCloser()
		service := newFakeService()
		application := mustApplicationWithResources(
			t,
			readiness,
			monitor,
			resources,
			service,
			100*time.Millisecond,
		)
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
		select {
		case <-resources.closeCalled:
		default:
			t.Fatal("runtime resources were not closed")
		}
		if !reflect.DeepEqual(application.roles, []Role{RoleAPI}) {
			t.Fatalf("application roles = %v, want [api]", application.roles)
		}
	})
}

func TestApplicationStartsInOrderAndStopsInReverseOrder(t *testing.T) {
	t.Parallel()

	var order []string
	first := newFakeService()
	first.start = func(context.Context) error {
		order = append(order, "start:first")
		return nil
	}
	first.shutdown = func(context.Context) error {
		order = append(order, "stop:first")
		first.done <- nil
		return nil
	}
	second := newFakeService()
	second.start = func(context.Context) error {
		order = append(order, "start:second")
		return nil
	}
	second.shutdown = func(context.Context) error {
		order = append(order, "stop:second")
		second.done <- nil
		return nil
	}
	monitor := newFakeMonitor()
	resources := newFakeResourceCloser()
	resources.close = func(context.Context) error {
		order = append(order, "close:resources")
		return nil
	}
	monitor.shutdown = func(context.Context) error {
		order = append(order, "stop:monitor")
		monitor.done <- nil
		return nil
	}
	readiness := &fakeReadiness{updates: make(chan bool, 2)}
	application, err := New(
		Options{Roles: []Role{RoleWorker}, ShutdownTimeout: time.Second},
		readiness,
		monitor,
		resources,
		slog.New(slog.NewJSONHandler(io.Discard, nil)),
		OwnedService{Name: "first", Service: first},
		OwnedService{Name: "second", Service: second},
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- application.Run(ctx) }()
	<-second.started
	if ready := <-readiness.updates; !ready {
		t.Fatal("readiness did not open after every service started")
	}
	cancel()
	if err := <-result; err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	want := []string{"start:first", "start:second", "stop:second", "stop:first", "stop:monitor", "close:resources"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("lifecycle order = %v, want %v", order, want)
	}
}

func TestApplicationSharesOneShutdownDeadlineWithResources(t *testing.T) {
	t.Parallel()

	var serviceDeadline time.Time
	service := newFakeService()
	service.shutdown = func(ctx context.Context) error {
		serviceDeadline, _ = ctx.Deadline()
		service.done <- nil
		return nil
	}
	var resourceDeadline time.Time
	resources := newFakeResourceCloser()
	resources.close = func(ctx context.Context) error {
		resourceDeadline, _ = ctx.Deadline()
		return nil
	}
	readiness := &fakeReadiness{updates: make(chan bool, 2)}
	application := mustApplicationWithResources(
		t,
		readiness,
		newFakeMonitor(),
		resources,
		service,
		time.Second,
	)
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- application.Run(ctx) }()
	<-service.started
	<-readiness.updates
	cancel()

	if err := <-result; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if serviceDeadline.IsZero() || !serviceDeadline.Equal(resourceDeadline) {
		t.Fatalf(
			"shutdown deadlines = service %v, resources %v; want one shared deadline",
			serviceDeadline,
			resourceDeadline,
		)
	}
}

func TestApplicationCleansStartedServicesAfterPartialStartFailure(t *testing.T) {
	t.Parallel()

	first := newFakeService()
	second := newFakeService()
	startErr := errors.New("second start failed")
	second.startErr = startErr
	monitor := newFakeMonitor()
	resources := newFakeResourceCloser()
	readiness := &fakeReadiness{updates: make(chan bool, 1)}
	application, err := New(
		Options{Roles: []Role{RoleWorker}, ShutdownTimeout: time.Second},
		readiness,
		monitor,
		resources,
		slog.New(slog.NewJSONHandler(io.Discard, nil)),
		OwnedService{Name: "first", Service: first},
		OwnedService{Name: "second", Service: second},
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	err = application.Run(t.Context())
	if !errors.Is(err, startErr) {
		t.Fatalf("Run() error = %v, want second start failure", err)
	}
	select {
	case <-first.shutdownCalled:
	default:
		t.Fatal("first service was not cleaned up")
	}
	select {
	case <-second.shutdownCalled:
		t.Fatal("service whose start failed was shut down")
	default:
	}
	select {
	case <-monitor.shutdownCalled:
	default:
		t.Fatal("monitor was not cleaned up")
	}
	select {
	case <-resources.closeCalled:
	default:
		t.Fatal("resources were not cleaned up")
	}
	select {
	case update := <-readiness.updates:
		t.Fatalf("unexpected readiness update: %v", update)
	default:
	}
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
	resources := newFakeResourceCloser()
	service := newFakeService()
	application := mustApplicationWithResources(t, readiness, monitor, resources, service, time.Second)

	err := application.Run(context.Background())
	if !errors.Is(err, startErr) {
		t.Fatalf("Run() error = %v, want monitor start error", err)
	}
	select {
	case <-service.started:
		t.Fatal("service started before dependency monitor succeeded")
	default:
	}
	select {
	case <-resources.closeCalled:
	default:
		t.Fatal("resources were not cleaned up after monitor start failure")
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
	return mustApplicationWithResources(
		t,
		readiness,
		monitor,
		newFakeResourceCloser(),
		service,
		shutdownTimeout,
	)
}

func mustApplicationWithResources(
	t *testing.T,
	readiness Readiness,
	monitor Monitor,
	resources ResourceCloser,
	service Service,
	shutdownTimeout time.Duration,
) *Application {
	t.Helper()

	application, err := New(
		Options{Roles: []Role{RoleAPI}, ShutdownTimeout: shutdownTimeout},
		readiness,
		monitor,
		resources,
		slog.New(slog.NewJSONHandler(io.Discard, nil)),
		OwnedService{Name: "health", Service: service},
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return application
}

type fakeResourceCloser struct {
	closeCalled chan struct{}
	close       func(context.Context) error
	closeOnce   sync.Once
}

func newFakeResourceCloser() *fakeResourceCloser {
	return &fakeResourceCloser{closeCalled: make(chan struct{})}
}

func (resources *fakeResourceCloser) Close(ctx context.Context) error {
	resources.closeOnce.Do(func() { close(resources.closeCalled) })
	if resources.close != nil {
		return resources.close(ctx)
	}
	return nil
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
	start          func(context.Context) error
	shutdown       func(context.Context) error
}

func newFakeService() *fakeService {
	return &fakeService{
		started:        make(chan struct{}),
		shutdownCalled: make(chan struct{}),
		done:           make(chan error, 1),
	}
}

func (service *fakeService) Start(ctx context.Context) error {
	if service.startErr != nil {
		return service.startErr
	}
	if service.start != nil {
		if err := service.start(ctx); err != nil {
			return err
		}
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
