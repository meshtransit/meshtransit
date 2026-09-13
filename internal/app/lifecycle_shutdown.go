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
	for index := len(services) - 1; index >= 0; index-- {
		service := services[index]
		if err := service.service.Shutdown(shutdownCtx); err != nil {
			results = append(results, fmt.Errorf("shut down %s: %w", service.name, err))
		}
		if index != exitedService {
			if err := joinOwned(shutdownCtx, service.name, service.done); err != nil {
				results = append(results, err)
			}
		}
	}

	if err := application.monitor.Shutdown(shutdownCtx); err != nil {
		results = append(results, fmt.Errorf("shut down dependency monitor: %w", err))
	}
	if !monitorExited {
		if err := joinOwned(shutdownCtx, "dependency monitor", monitorDone); err != nil {
			results = append(results, err)
		}
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
	joinErr := joinOwned(shutdownCtx, "dependency monitor", monitorDone)
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
