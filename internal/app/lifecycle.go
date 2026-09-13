package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"time"
)

var (
	// ErrInvalidApplication indicates missing or inconsistent lifecycle inputs.
	ErrInvalidApplication = errors.New("invalid application")
	// ErrUnexpectedServiceStop indicates that an owned component exited before shutdown.
	ErrUnexpectedServiceStop = errors.New("service stopped unexpectedly")
)

// Monitor is the process-owned boundary for dependency checks. Start performs
// its initial check synchronously and starts its owned goroutine on success.
type Monitor interface {
	Start(context.Context) error
	Shutdown(context.Context) error
	Done() <-chan error
}

// Readiness is the process-owned admission gate.
type Readiness interface {
	SetReady(bool)
}

// ResourceCloser releases process dependencies after every service and the
// dependency monitor have joined. Close must respect the supplied context and
// must not start cleanup work that outlives the call.
type ResourceCloser interface {
	Close(context.Context) error
}

// Options contains validated application lifecycle settings.
type Options struct {
	Roles           []Role
	ShutdownTimeout time.Duration
}

// Application owns dependency monitoring, process services, admission, and
// their bounded reverse-order shutdown.
type Application struct {
	roles           []Role
	shutdownTimeout time.Duration
	readiness       Readiness
	monitor         Monitor
	resources       ResourceCloser
	services        []OwnedService
	logger          *slog.Logger
}

// New constructs an application from explicit lifecycle dependencies.
func New(
	options Options,
	readiness Readiness,
	monitor Monitor,
	resources ResourceCloser,
	logger *slog.Logger,
	services ...OwnedService,
) (*Application, error) {
	if isNilLifecycleDependency(readiness) ||
		isNilLifecycleDependency(monitor) ||
		isNilLifecycleDependency(resources) ||
		logger == nil ||
		options.ShutdownTimeout <= 0 ||
		!validOwnedServices(services) {
		return nil, ErrInvalidApplication
	}
	if err := validateActiveRoles(options.Roles); err != nil {
		return nil, err
	}

	return &Application{
		roles:           append([]Role(nil), options.Roles...),
		shutdownTimeout: options.ShutdownTimeout,
		readiness:       readiness,
		monitor:         monitor,
		resources:       resources,
		services:        append([]OwnedService(nil), services...),
		logger:          logger,
	}, nil
}

// Run checks dependencies, starts services in declaration order, opens
// admission, and blocks until cancellation or an owned component exits. Every
// exit path closes admission before bounded reverse-order cleanup.
func (application *Application) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.Join(
			ErrInvalidApplication,
			application.closeResources(context.Background()),
		)
	}
	if ctx.Err() != nil {
		return application.closeResources(ctx)
	}

	if err := application.monitor.Start(ctx); err != nil {
		return errors.Join(
			fmt.Errorf("start dependency monitor: %w", err),
			application.closeResources(ctx),
		)
	}
	monitorDone := application.monitor.Done()
	if monitorDone == nil {
		return errors.Join(
			ErrUnexpectedServiceStop,
			application.stopMonitor(context.WithoutCancel(ctx), monitorDone),
		)
	}

	startedServices, startErr := application.startServices(ctx)
	if startErr != nil {
		cleanupErr := application.stopStarted(
			ctx,
			startedServices,
			monitorDone,
			noExitedService,
			false,
		)
		return errors.Join(startErr, cleanupErr)
	}

	application.readiness.SetReady(true)
	application.logger.InfoContext(ctx, "runtime ready", "roles", roleNames(application.roles))

	exit := application.wait(ctx, monitorDone, startedServices)
	application.readiness.SetReady(false)
	cleanupErr := application.stopStarted(
		ctx,
		startedServices,
		monitorDone,
		exit.serviceIndex,
		exit.monitor,
	)
	result := errors.Join(exit.err, cleanupErr)
	if result == nil {
		application.logger.InfoContext(
			context.WithoutCancel(ctx),
			"runtime stopped",
			"roles", roleNames(application.roles),
		)
	}
	return result
}

func (application *Application) startServices(ctx context.Context) ([]startedService, error) {
	started := make([]startedService, 0, len(application.services))
	for _, owned := range application.services {
		if err := owned.Service.Start(ctx); err != nil {
			return started, fmt.Errorf("start %s: %w", owned.Name, err)
		}
		service := startedService{
			name:    owned.Name,
			service: owned.Service,
			done:    owned.Service.Done(),
		}
		started = append(started, service)
		if service.done == nil {
			return started, fmt.Errorf("%w: %s", ErrUnexpectedServiceStop, owned.Name)
		}
	}
	return started, nil
}

const noExitedService = -1

type lifecycleExit struct {
	serviceIndex int
	monitor      bool
	err          error
}

func (application *Application) wait(
	ctx context.Context,
	monitorDone <-chan error,
	services []startedService,
) lifecycleExit {
	cases := make([]reflect.SelectCase, 0, len(services)+2)
	cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(ctx.Done())})
	cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(monitorDone)})
	for _, service := range services {
		cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(service.done)})
	}

	chosen, value, ok := reflect.Select(cases)
	switch chosen {
	case 0:
		return lifecycleExit{serviceIndex: noExitedService}
	case 1:
		return lifecycleExit{
			serviceIndex: noExitedService,
			monitor:      true,
			err:          unexpectedExit("dependency monitor", receivedError(value, ok), ok),
		}
	default:
		serviceIndex := chosen - 2
		return lifecycleExit{
			serviceIndex: serviceIndex,
			err: unexpectedExit(
				services[serviceIndex].name,
				receivedError(value, ok),
				ok,
			),
		}
	}
}

func receivedError(value reflect.Value, ok bool) error {
	if !ok || value.IsNil() {
		return nil
	}
	componentErr, _ := value.Interface().(error)
	return componentErr
}

func unexpectedExit(name string, componentErr error, ok bool) error {
	if !ok || componentErr == nil {
		return fmt.Errorf("%w: %s", ErrUnexpectedServiceStop, name)
	}
	return fmt.Errorf("%w: %s: %w", ErrUnexpectedServiceStop, name, componentErr)
}
