package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var errInvalidOwnedResource = errors.New("invalid owned resource")

type resourceOwner struct {
	mu        sync.Mutex
	resources []ownedResource
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

type ownedResource struct {
	name  string
	close func(context.Context) error
}

func (owner *resourceOwner) Add(name string, closeFunc func(context.Context) error) error {
	if owner == nil || name == "" || closeFunc == nil {
		return errInvalidOwnedResource
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.closed {
		return errInvalidOwnedResource
	}
	owner.resources = append(owner.resources, ownedResource{name: name, close: closeFunc})
	return nil
}

func (owner *resourceOwner) Close(ctx context.Context) error {
	if owner == nil || ctx == nil {
		return errInvalidOwnedResource
	}
	owner.closeOnce.Do(func() {
		owner.mu.Lock()
		owner.closed = true
		resources := owner.resources
		owner.resources = nil
		owner.mu.Unlock()

		owner.closeErr = closeOwnedResources(ctx, resources)
	})
	return owner.closeErr
}

func closeOwnedResources(ctx context.Context, resources []ownedResource) error {
	var closeErrors []error
	for index := len(resources) - 1; index >= 0; index-- {
		resource := resources[index]
		if err := ctx.Err(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close %s: %w", resource.name, err))
			continue
		}
		if err := resource.close(ctx); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close %s: %w", resource.name, err))
		}
	}
	return errors.Join(closeErrors...)
}
