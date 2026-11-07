package main

import (
	"errors"
	"testing"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/config"
)

func TestDeviceAliasWorkerCompositionRejectsMissingWorkerDependencies(t *testing.T) {
	t.Parallel()
	hints := newAliasWorkHints(discardCompositionLogger())
	for _, pool := range []*postgresadapter.Pool{nil, {}} {
		worker, metrics, err := composeDeviceAliasWorker(config.DeviceAliasWorkerConfig{}, pool, hints, discardCompositionLogger())
		if worker != nil || metrics != nil || !errors.Is(err, errInvalidDeviceAliasWorkerComposition) {
			t.Fatal("invalid worker pool accepted", err)
		}
	}
	worker, metrics, err := composeDeviceAliasWorker(config.DeviceAliasWorkerConfig{}, &postgresadapter.Pool{}, hints, nil)
	if worker != nil || metrics != nil || !errors.Is(err, errInvalidDeviceAliasWorkerComposition) {
		t.Fatal("missing logger accepted", err)
	}
	worker, metrics, err = composeDeviceAliasWorker(config.DeviceAliasWorkerConfig{}, &postgresadapter.Pool{}, nil,
		discardCompositionLogger())
	if worker != nil || metrics != nil || !errors.Is(err, errInvalidDeviceAliasWorkerComposition) {
		t.Fatal("missing hints accepted", err)
	}
}
