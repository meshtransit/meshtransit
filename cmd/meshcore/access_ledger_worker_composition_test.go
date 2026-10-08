package main

import (
	"errors"
	"testing"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/config"
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
