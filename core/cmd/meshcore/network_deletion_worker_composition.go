package main

import (
	"errors"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/adapter/httpapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/network/deletion"
	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidNetworkDeletionWorkerComposition = errors.New("invalid network deletion worker composition")

func composeNetworkDeletionWorker(settings config.NetworkDeletionWorkerConfig, pool *postgresadapter.Pool,
	logger *slog.Logger) (*deletion.Worker, prometheus.Collector, error) {
	if pool == nil || logger == nil {
		return nil, nil, errInvalidNetworkDeletionWorkerComposition
	}
	store, err := postgresadapter.NewNetworkDeletionWorkerStore(pool)
	if err != nil {
		return nil, nil, errors.Join(errInvalidNetworkDeletionWorkerComposition, err)
	}
	worker, err := deletion.NewWorker(deletion.WorkerOptions{DeploymentID: settings.DeploymentID,
		BatchSize: settings.BatchSize, PollInterval: settings.PollInterval,
		OperationTimeout: settings.OperationTimeout}, store, logger)
	if err != nil {
		return nil, nil, errors.Join(errInvalidNetworkDeletionWorkerComposition, err)
	}
	metrics, err := httpapi.NewNetworkDeletionWorkerMetricsCollector(worker)
	if err != nil {
		return nil, nil, errors.Join(errInvalidNetworkDeletionWorkerComposition, err)
	}
	return worker, metrics, nil
}

var _ app.Service = (*deletion.Worker)(nil)
