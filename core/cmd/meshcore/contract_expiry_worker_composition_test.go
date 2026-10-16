package main

import (
	"errors"
	"testing"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/config"
)

func TestContractExpiryWorkerCompositionRejectsMissingWorkerDependencies(t *testing.T) {
	t.Parallel()
	for _, pool := range []*postgresadapter.Pool{nil, {}} {
		workers, err := composeContractEndWorkers(config.ContractExpiryWorkerConfig{}, pool, discardCompositionLogger())
		if workers != nil || !errors.Is(err, errInvalidContractExpiryWorkerComposition) {
			t.Fatal("invalid worker pool accepted", err)
		}
	}
	workers, err := composeContractEndWorkers(config.ContractExpiryWorkerConfig{}, &postgresadapter.Pool{}, nil)
	if workers != nil || !errors.Is(err, errInvalidContractExpiryWorkerComposition) {
		t.Fatal("missing logger accepted", err)
	}
}
