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
	// ErrUnexpectedServiceStop indicates that the process listener exited before shutdown.
	ErrUnexpectedServiceStop = errors.New("service stopped unexpectedly")
)

// Service is the process-owned boundary for a stoppable, joinable listener.
// Done must return a non-nil join channel after Start succeeds.
type Service interface {
	Start(context.Context) error
	Shutdown(context.Context) error
	Done() <-chan error
}

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

// Options contains validated application lifecycle settings.
type Options struct {
	Roles           []Role
	ShutdownTimeout time.Duration
}

// Application coordinates admission, listener ownership, and bounded shutdown.
type Application struct {
	roles           []Role
	shutdownTimeout time.Duration
	readiness       Readiness
	monitor         Monitor
	service         Service
	logger          *slog.Logger
}

// New constructs an application from explicit lifecycle dependencies.
func New(
	options Options,
	readiness Readiness,
	monitor Monitor,
	service Service,
	logger *slog.Logger,
) (*Application, error) {
	if isNilLifecycleDependency(readiness) ||
		isNilLifecycleDependency(monitor) ||
		isNilLifecycleDependency(service) ||
		logger == nil ||
		options.ShutdownTimeout <= 0 {
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
		service:         service,
		logger:          logger,
	}, nil
}

// Run checks and monitors dependencies before starting the process listener,
// then opens admission and blocks until cancellation or an owned component
// exits. Every exit path closes admission before bounded reverse-order cleanup.
func (application *Application) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidApplication
	}
	if ctx.Err() != nil {
		return nil
	}

	if err := application.monitor.Start(ctx); err != nil {
		return fmt.Errorf("start dependency monitor: %w", err)
	}
	if application.monitor.Done() == nil {
		return errors.Join(
			ErrUnexpectedServiceStop,
			application.stopMonitor(context.WithoutCancel(ctx)),
		)
	}

	if err := application.service.Start(ctx); err != nil {
		cleanupErr := application.stopMonitor(context.WithoutCancel(ctx))
		return errors.Join(fmt.Errorf("start process service: %w", err), cleanupErr)
	}
	if application.service.Done() == nil {
		application.readiness.SetReady(false)
		return errors.Join(
			ErrUnexpectedServiceStop,
			application.shutdown(ctx, false, false),
		)
	}

	application.readiness.SetReady(true)
	application.logger.InfoContext(ctx, "runtime ready", "roles", roleNames(application.roles))

	var (
		runErr        error
		serviceExited bool
		monitorExited bool
	)
	select {
	case serviceErr, ok := <-application.service.Done():
		serviceExited = true
		runErr = unexpectedExit("process service", serviceErr, ok)
	case monitorErr, ok := <-application.monitor.Done():
		monitorExited = true
		runErr = unexpectedExit("dependency monitor", monitorErr, ok)
	case <-ctx.Done():
	}

	application.readiness.SetReady(false)
	cleanupErr := application.shutdown(ctx, serviceExited, monitorExited)
	result := errors.Join(runErr, cleanupErr)
	if result == nil {
		application.logger.InfoContext(
			context.WithoutCancel(ctx),
			"runtime stopped",
			"roles", roleNames(application.roles),
		)
	}
	return result
}

func unexpectedExit(name string, componentErr error, ok bool) error {
	if !ok || componentErr == nil {
		return fmt.Errorf("%w: %s", ErrUnexpectedServiceStop, name)
	}
	return fmt.Errorf("%w: %s: %w", ErrUnexpectedServiceStop, name, componentErr)
}

func (application *Application) shutdown(
	parent context.Context,
	serviceExited bool,
	monitorExited bool,
) error {
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), application.shutdownTimeout)
	defer cancel()

	var results []error
	serviceShutdownErr := application.service.Shutdown(shutdownCtx)
	if serviceShutdownErr != nil {
		results = append(results, fmt.Errorf("shut down process service: %w", serviceShutdownErr))
	}
	if !serviceExited {
		if err := joinOwned(shutdownCtx, "process service", application.service.Done()); err != nil {
			results = append(results, err)
		}
	}

	monitorShutdownErr := application.monitor.Shutdown(shutdownCtx)
	if monitorShutdownErr != nil {
		results = append(results, fmt.Errorf("shut down dependency monitor: %w", monitorShutdownErr))
	}
	if !monitorExited {
		if err := joinOwned(shutdownCtx, "dependency monitor", application.monitor.Done()); err != nil {
			results = append(results, err)
		}
	}
	return errors.Join(results...)
}

func (application *Application) stopMonitor(parent context.Context) error {
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), application.shutdownTimeout)
	defer cancel()

	shutdownErr := application.monitor.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		shutdownErr = fmt.Errorf("shut down dependency monitor: %w", shutdownErr)
	}
	joinErr := joinOwned(shutdownCtx, "dependency monitor", application.monitor.Done())
	return errors.Join(shutdownErr, joinErr)
}

func joinOwned(ctx context.Context, name string, done <-chan error) error {
	if done == nil {
		return fmt.Errorf("join %s: %w", name, ErrUnexpectedServiceStop)
	}
	select {
	case componentErr, ok := <-done:
		if ok && componentErr != nil {
			return fmt.Errorf("join %s: %w", name, componentErr)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("join %s: %w", name, ctx.Err())
	}
}

func validateActiveRoles(roles []Role) error {
	if len(roles) == 0 {
		return ErrInvalidApplication
	}
	seen := make(map[Role]struct{}, len(roles))
	for _, role := range roles {
		switch role {
		case RoleAPI, RoleControl, RoleWorker, RoleRelay:
		default:
			return ErrInvalidApplication
		}
		if _, exists := seen[role]; exists {
			return ErrInvalidApplication
		}
		seen[role] = struct{}{}
	}
	return nil
}

func roleNames(roles []Role) []string {
	names := make([]string, len(roles))
	for index, role := range roles {
		names[index] = role.String()
	}
	return names
}

func isNilLifecycleDependency(dependency any) bool {
	if dependency == nil {
		return true
	}

	value := reflect.ValueOf(dependency)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
