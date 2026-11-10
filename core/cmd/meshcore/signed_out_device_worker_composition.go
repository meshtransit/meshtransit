package main

import (
	"errors"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/adapter/httpapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/network/deletion"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidSignedOutDeviceWorkerComposition = errors.New("invalid signed-out Device worker composition")

// composeSignedOutDeviceWorker runs the removal of Devices signed out past
// their hold (schema 284) in the Network deletion worker's loop, one Device
// a step.
func composeSignedOutDeviceWorker(settings config.SignedOutDeviceWorkerConfig, pool *postgresadapter.Pool,
	logger *slog.Logger) (*deletion.Worker, prometheus.Collector, error) {
	if pool == nil || logger == nil {
		return nil, nil, errInvalidSignedOutDeviceWorkerComposition
	}
	store, err := postgresadapter.NewSignedOutRevocationWorkerStore(pool)
	if err != nil {
		return nil, nil, errors.Join(errInvalidSignedOutDeviceWorkerComposition, err)
	}
	worker, err := deletion.NewWorker(deletion.WorkerOptions{Name: "signed-out Device removal",
		DeploymentID: settings.DeploymentID, BatchSize: 1, PollInterval: settings.PollInterval,
		OperationTimeout: settings.OperationTimeout}, store, logger)
	if err != nil {
		return nil, nil, errors.Join(errInvalidSignedOutDeviceWorkerComposition, err)
	}
	metrics, err := httpapi.NewSignedOutDeviceWorkerMetricsCollector(worker)
	if err != nil {
		return nil, nil, errors.Join(errInvalidSignedOutDeviceWorkerComposition, err)
	}
	return worker, metrics, nil
}
