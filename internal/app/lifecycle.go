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
	Start() error
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
	service         Service
	logger          *slog.Logger
}

// New constructs an application from explicit lifecycle dependencies.
func New(
	options Options,
	readiness Readiness,
	service Service,
	logger *slog.Logger,
) (*Application, error) {
	if isNilLifecycleDependency(readiness) ||
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
		service:         service,
		logger:          logger,
	}, nil
}

// Run starts the process listener, opens readiness, and blocks until either the
// parent context is canceled or the listener fails. Cancellation closes
// readiness before a bounded drain and join.
func (application *Application) Run(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidApplication
	}
	if ctx.Err() != nil {
		return nil
	}

	if err := application.service.Start(); err != nil {
		return fmt.Errorf("start process service: %w", err)
	}

	application.readiness.SetReady(true)
	application.logger.InfoContext(ctx, "runtime ready", "roles", roleNames(application.roles))

	select {
	case serviceErr, ok := <-application.service.Done():
		application.readiness.SetReady(false)
		if !ok || serviceErr == nil {
			return ErrUnexpectedServiceStop
		}
		return fmt.Errorf("process service stopped: %w", serviceErr)
	case <-ctx.Done():
		application.readiness.SetReady(false)
		return application.shutdown(ctx)
	}
}

func (application *Application) shutdown(parent context.Context) error {
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), application.shutdownTimeout)
	defer cancel()

	shutdownErr := application.service.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		shutdownErr = fmt.Errorf("shut down process service: %w", shutdownErr)
	}

	var joinErr error
	select {
	case serviceErr, ok := <-application.service.Done():
		if ok && serviceErr != nil {
			joinErr = fmt.Errorf("join process service: %w", serviceErr)
		}
	case <-shutdownCtx.Done():
		joinErr = fmt.Errorf("join process service: %w", shutdownCtx.Err())
	}

	result := errors.Join(shutdownErr, joinErr)
	if result == nil {
		application.logger.InfoContext(
			context.WithoutCancel(parent),
			"runtime stopped",
			"roles", roleNames(application.roles),
		)
	}
	return result
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
