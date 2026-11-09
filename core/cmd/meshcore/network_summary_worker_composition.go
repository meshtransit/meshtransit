package main

import (
	"errors"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/adapter/httpapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/networksummary"
	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidNetworkSummaryWorkerComposition = errors.New("invalid network summary worker composition")

func composeNetworkSummaryWorker(settings config.NetworkSummaryWorkerConfig, pool *postgresadapter.Pool,
	logger *slog.Logger) (*networksummary.Worker, prometheus.Collector, error) {
	if pool == nil || logger == nil {
		return nil, nil, errInvalidNetworkSummaryWorkerComposition
	}
	store, err := postgresadapter.NewNetworkSummaryStore(pool)
	if err != nil {
		return nil, nil, errors.Join(errInvalidNetworkSummaryWorkerComposition, err)
	}
	worker, err := networksummary.New(networksummary.Options{
		DeploymentID: settings.DeploymentID, BatchSize: settings.BatchSize, PollInterval: settings.PollInterval,
		OperationTimeout: settings.OperationTimeout, Lease: settings.Lease,
	}, store, logger)
	if err != nil {
		return nil, nil, errors.Join(errInvalidNetworkSummaryWorkerComposition, err)
	}
	metrics, err := httpapi.NewNetworkSummaryWorkerMetricsCollector(worker)
	if err != nil {
		return nil, nil, errors.Join(errInvalidNetworkSummaryWorkerComposition, err)
	}
	return worker, metrics, nil
}

var _ app.Service = (*networksummary.Worker)(nil)
