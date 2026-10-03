package main

import (
	"errors"
	"testing"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/config"
)

func TestDeviceAliasWorkerCompositionRejectsMissingWorkerDependencies(t *testing.T) {
	t.Parallel()
	for _, pool := range []*postgresadapter.Pool{nil, {}} {
		worker, metrics, err := composeDeviceAliasWorker(config.DeviceAliasWorkerConfig{}, pool, discardCompositionLogger())
		if worker != nil || metrics != nil || !errors.Is(err, errInvalidDeviceAliasWorkerComposition) {
			t.Fatal("invalid worker pool accepted", err)
		}
	}
	worker, metrics, err := composeDeviceAliasWorker(config.DeviceAliasWorkerConfig{}, &postgresadapter.Pool{}, nil)
	if worker != nil || metrics != nil || !errors.Is(err, errInvalidDeviceAliasWorkerComposition) {
		t.Fatal("missing logger accepted", err)
	}
}
