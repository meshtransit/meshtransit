package main

import (
	"errors"
	"testing"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/config"
)

func TestContractExpiryWorkerCompositionRejectsMissingWorkerDependencies(t *testing.T) {
	t.Parallel()
	for _, pool := range []*postgresadapter.Pool{nil, {}} {
		worker, metrics, err := composeContractExpiryWorker(config.ContractExpiryWorkerConfig{}, pool, discardCompositionLogger())
		if worker != nil || metrics != nil || !errors.Is(err, errInvalidContractExpiryWorkerComposition) {
			t.Fatal("invalid worker pool accepted", err)
		}
	}
	worker, metrics, err := composeContractExpiryWorker(config.ContractExpiryWorkerConfig{}, &postgresadapter.Pool{}, nil)
	if worker != nil || metrics != nil || !errors.Is(err, errInvalidContractExpiryWorkerComposition) {
		t.Fatal("missing logger accepted", err)
	}
}
