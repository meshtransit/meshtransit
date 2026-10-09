package main

import (
	"errors"
	"log/slog"

	"github.com/meshtransit/meshtransit/core/internal/adapter/httpapi"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph/ledger"
	"github.com/meshtransit/meshtransit/core/internal/platform/app"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
	"github.com/prometheus/client_golang/prometheus"
)

var errInvalidAccessLedgerWorkerComposition = errors.New("invalid access ledger worker composition")

func composeAccessLedgerWorker(settings config.AccessLedgerWorkerConfig, pool *postgresadapter.Pool, logger *slog.Logger) (*ledger.Worker, prometheus.Collector, error) {
	if pool == nil || logger == nil {
		return nil, nil, errInvalidAccessLedgerWorkerComposition
	}
	store, err := postgresadapter.NewAccessLedgerStore(pool)
	if err != nil {
		return nil, nil, errors.Join(errInvalidAccessLedgerWorkerComposition, err)
	}
	worker, err := ledger.New(ledger.Options{
		DeploymentID: settings.DeploymentID, BatchSize: settings.BatchSize, PollInterval: settings.PollInterval,
		PruneInterval: settings.PruneInterval, OperationTimeout: settings.OperationTimeout,
	}, store, store, store, logger)
	if err != nil {
		return nil, nil, errors.Join(errInvalidAccessLedgerWorkerComposition, err)
	}
	metrics, err := httpapi.NewAccessLedgerWorkerMetricsCollector(worker)
	if err != nil {
		return nil, nil, errors.Join(errInvalidAccessLedgerWorkerComposition, err)
	}
	return worker, metrics, nil
}

var _ app.Service = (*ledger.Worker)(nil)
