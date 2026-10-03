package main

import (
	"errors"
	"log/slog"

	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/app"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/sharing/devicealias"
	"github.com/prometheus/client_golang/prometheus"
)

var errInvalidDeviceAliasWorkerComposition = errors.New("invalid Device alias worker composition")

func composeDeviceAliasWorker(settings config.DeviceAliasWorkerConfig, pool *postgresadapter.Pool, logger *slog.Logger) (*devicealias.Worker, prometheus.Collector, error) {
	if pool == nil || logger == nil {
		return nil, nil, errInvalidDeviceAliasWorkerComposition
	}
	store, err := postgresadapter.NewDeviceAliasWorkerStore(pool)
	if err != nil {
		return nil, nil, errors.Join(errInvalidDeviceAliasWorkerComposition, err)
	}
	worker, err := devicealias.New(devicealias.Options{DeploymentID: settings.DeploymentID, BatchSize: settings.BatchSize, PollInterval: settings.PollInterval, OperationTimeout: settings.OperationTimeout}, store, store, logger)
	if err != nil {
		return nil, nil, errors.Join(errInvalidDeviceAliasWorkerComposition, err)
	}
	metrics, err := httpapi.NewDeviceAliasWorkerMetricsCollector(worker)
	if err != nil {
		return nil, nil, errors.Join(errInvalidDeviceAliasWorkerComposition, err)
	}
	return worker, metrics, nil
}

var _ app.Service = (*devicealias.Worker)(nil)
