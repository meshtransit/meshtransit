package app

import (
	"context"
	"errors"
	"fmt"
)

func (application *Application) stopStarted(
	parent context.Context,
	services []startedService,
	monitorDone <-chan error,
	exitedService int,
	monitorExited bool,
) error {
	shutdownCtx, cancel := context.WithTimeout(
		context.WithoutCancel(parent),
		application.shutdownTimeout,
	)
	defer cancel()

	var results []error
	allJoined := true
	for index := len(services) - 1; index >= 0; index-- {
		service := services[index]
		if err := service.service.Shutdown(shutdownCtx); err != nil {
			results = append(results, fmt.Errorf("shut down %s: %w", service.name, err))
		}
		if index != exitedService {
			joined, err := joinOwned(shutdownCtx, service.name, service.done)
			allJoined = allJoined && joined
			if err != nil {
				results = append(results, err)
			}
		}
	}

	if err := application.monitor.Shutdown(shutdownCtx); err != nil {
		results = append(results, fmt.Errorf("shut down dependency monitor: %w", err))
	}
	if !monitorExited {
		joined, err := joinOwned(shutdownCtx, "dependency monitor", monitorDone)
		allJoined = allJoined && joined
		if err != nil {
			results = append(results, err)
		}
	}
	if !allJoined {
		return errors.Join(ErrIncompleteShutdown, errors.Join(results...))
	}
	if err := application.resources.Close(shutdownCtx); err != nil {
		results = append(results, fmt.Errorf("close runtime resources: %w", err))
	}
	return errors.Join(results...)
}

func (application *Application) stopMonitor(parent context.Context, monitorDone <-chan error) error {
	shutdownCtx, cancel := context.WithTimeout(
		context.WithoutCancel(parent),
		application.shutdownTimeout,
	)
	defer cancel()

	shutdownErr := application.monitor.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		shutdownErr = fmt.Errorf("shut down dependency monitor: %w", shutdownErr)
	}
	joined, joinErr := joinOwned(shutdownCtx, "dependency monitor", monitorDone)
	if !joined {
		return errors.Join(ErrIncompleteShutdown, shutdownErr, joinErr)
	}
	resourceErr := application.resources.Close(shutdownCtx)
	if resourceErr != nil {
		resourceErr = fmt.Errorf("close runtime resources: %w", resourceErr)
	}
	return errors.Join(shutdownErr, joinErr, resourceErr)
}

func (application *Application) closeResources(parent context.Context) error {
	shutdownCtx, cancel := context.WithTimeout(
		context.WithoutCancel(parent),
		application.shutdownTimeout,
	)
	defer cancel()

	if err := application.resources.Close(shutdownCtx); err != nil {
		return fmt.Errorf("close runtime resources: %w", err)
	}
	return nil
}

// joinOwned separates termination evidence from the component's result. An
// already published result wins over an expired deadline; absence retains
// resources even if Shutdown itself returned nil.
func joinOwned(ctx context.Context, name string, done <-chan error) (bool, error) {
	if done == nil {
		return false, fmt.Errorf("join %s: %w", name, ErrUnexpectedServiceStop)
	}
	select {
	case componentErr := <-done:
		return true, ownedJoinError(name, componentErr)
	default:
	}
	select {
	case componentErr := <-done:
		return true, ownedJoinError(name, componentErr)
	case <-ctx.Done():
		return false, fmt.Errorf("join %s: %w", name, ctx.Err())
	}
}

func ownedJoinError(name string, componentErr error) error {
	if componentErr != nil {
		return fmt.Errorf("join %s: %w", name, componentErr)
	}
	return nil
}
