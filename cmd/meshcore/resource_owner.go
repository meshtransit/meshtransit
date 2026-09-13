package main

import (
	"errors"
	"fmt"
)

type resourceOwner struct {
	resources []ownedResource
}

type ownedResource struct {
	name  string
	close func() error
}

func (owner *resourceOwner) Add(name string, closeFunc func() error) {
	owner.resources = append(owner.resources, ownedResource{name: name, close: closeFunc})
}

func (owner *resourceOwner) Close() error {
	var closeErrors []error
	for index := len(owner.resources) - 1; index >= 0; index-- {
		resource := owner.resources[index]
		if err := resource.close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close %s: %w", resource.name, err))
		}
	}
	owner.resources = nil
	return errors.Join(closeErrors...)
}
