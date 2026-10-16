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

// contractEndWorker is one composed finalizer with its metrics.
type contractEndWorker struct {
	name    string
	worker  *contractexpiry.Worker
	metrics prometheus.Collector
}

// composeContractEndWorkers builds the expiry worker and, with the same
// settings, the worker that ends shares of removed provider Devices.
func composeContractEndWorkers(settings config.ContractExpiryWorkerConfig, pool *postgresadapter.Pool, logger *slog.Logger) ([]contractEndWorker, error) {
	if pool == nil || logger == nil {
		return nil, errInvalidContractExpiryWorkerComposition
	}
	expiry, err := postgresadapter.NewTrustContractExpiryStore(pool)
	if err != nil {
		return nil, errors.Join(errInvalidContractExpiryWorkerComposition, err)
	}
	removal, err := postgresadapter.NewTrustContractDeviceRemovalStore(pool)
	if err != nil {
		return nil, errors.Join(errInvalidContractExpiryWorkerComposition, err)
	}
	type finalizer interface {
		contractexpiry.Candidates
		contractexpiry.Finalizer
	}
	var composed []contractEndWorker
	for _, part := range []struct {
		name    string
		kind    contractexpiry.Kind
		store   finalizer
		metrics func(*contractexpiry.Worker) (prometheus.Collector, error)
	}{
		{"trust-contract-expiry-worker", contractexpiry.KindExpiry, expiry, httpapi.NewContractExpiryWorkerMetricsCollector},
		{"trust-contract-device-removal-worker", contractexpiry.KindDeviceRemoval, removal, httpapi.NewContractDeviceRemovalWorkerMetricsCollector},
	} {
		worker, err := contractexpiry.New(contractexpiry.Options{
			Kind: part.kind, DeploymentID: settings.DeploymentID, BatchSize: settings.BatchSize,
			PollInterval: settings.PollInterval, OperationTimeout: settings.OperationTimeout,
		}, part.store, part.store, logger)
		if err != nil {
			return nil, errors.Join(errInvalidContractExpiryWorkerComposition, err)
		}
		metrics, err := part.metrics(worker)
		if err != nil {
			return nil, errors.Join(errInvalidContractExpiryWorkerComposition, err)
		}
		composed = append(composed, contractEndWorker{name: part.name, worker: worker, metrics: metrics})
	}
	return composed, nil
}

var _ app.Service = (*contractexpiry.Worker)(nil)
