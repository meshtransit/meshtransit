package main

import (
	"errors"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/adapter/httpapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/domain/node/enforcementledger"
	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidEnforcementLedgerWorkerComposition = errors.New("invalid enforcement ledger worker composition")

func composeEnforcementLedgerWorker(settings config.EnforcementLedgerWorkerConfig, pool *postgresadapter.Pool,
	redisClient *redisadapter.Client, logger *slog.Logger) (*enforcementledger.Worker, prometheus.Collector, error) {
	if pool == nil || redisClient == nil || logger == nil {
		return nil, nil, errInvalidEnforcementLedgerWorkerComposition
	}
	store, err := postgresadapter.NewEnforcementLedgerStore(pool)
	if err != nil {
		return nil, nil, errors.Join(errInvalidEnforcementLedgerWorkerComposition, err)
	}
	worker, err := enforcementledger.New(enforcementledger.Options{
		DeploymentID: settings.DeploymentID, PollInterval: settings.PollInterval,
		PruneInterval: settings.PruneInterval, OperationTimeout: settings.OperationTimeout,
	}, store, redisClient, store, store, logger)
	if err != nil {
		return nil, nil, errors.Join(errInvalidEnforcementLedgerWorkerComposition, err)
	}
	metrics, err := httpapi.NewEnforcementLedgerWorkerMetricsCollector(worker)
	if err != nil {
		return nil, nil, errors.Join(errInvalidEnforcementLedgerWorkerComposition, err)
	}
	return worker, metrics, nil
}

var _ app.Service = (*enforcementledger.Worker)(nil)
