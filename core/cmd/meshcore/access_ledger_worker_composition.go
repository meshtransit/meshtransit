package main

import (
	"errors"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/adapter/httpapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/accessgraph/ledger"
	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/core/internal/platform/config"
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
