package main

import (
	"errors"
	"testing"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/config"
)

func TestAccessLedgerWorkerCompositionRejectsMissingWorkerDependencies(t *testing.T) {
	t.Parallel()
	for _, pool := range []*postgresadapter.Pool{nil, {}} {
		worker, metrics, err := composeAccessLedgerWorker(config.AccessLedgerWorkerConfig{}, pool, discardCompositionLogger())
		if worker != nil || metrics != nil || !errors.Is(err, errInvalidAccessLedgerWorkerComposition) {
			t.Fatal("invalid worker pool accepted", err)
		}
	}
	worker, metrics, err := composeAccessLedgerWorker(config.AccessLedgerWorkerConfig{}, &postgresadapter.Pool{}, nil)
	if worker != nil || metrics != nil || !errors.Is(err, errInvalidAccessLedgerWorkerComposition) {
		t.Fatal("missing logger accepted", err)
	}
}
