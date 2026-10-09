package main

import (
	"errors"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/adapter/httpapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/sharing/contractexpiry"
	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidContractExpiryWorkerComposition = errors.New("invalid Trust Contract expiry worker composition")

func composeContractExpiryWorker(settings config.ContractExpiryWorkerConfig, pool *postgresadapter.Pool, logger *slog.Logger) (*contractexpiry.Worker, prometheus.Collector, error) {
	if pool == nil || logger == nil {
		return nil, nil, errInvalidContractExpiryWorkerComposition
	}
	store, err := postgresadapter.NewTrustContractExpiryStore(pool)
	if err != nil {
		return nil, nil, errors.Join(errInvalidContractExpiryWorkerComposition, err)
	}
	worker, err := contractexpiry.New(contractexpiry.Options{
		DeploymentID: settings.DeploymentID, BatchSize: settings.BatchSize,
		PollInterval: settings.PollInterval, OperationTimeout: settings.OperationTimeout,
	}, store, store, logger)
	if err != nil {
		return nil, nil, errors.Join(errInvalidContractExpiryWorkerComposition, err)
	}
	metrics, err := httpapi.NewContractExpiryWorkerMetricsCollector(worker)
	if err != nil {
		return nil, nil, errors.Join(errInvalidContractExpiryWorkerComposition, err)
	}
	return worker, metrics, nil
}

var _ app.Service = (*contractexpiry.Worker)(nil)
