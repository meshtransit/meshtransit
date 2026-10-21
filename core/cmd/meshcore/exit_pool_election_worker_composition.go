package main

import (
	"errors"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/adapter/httpapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/primaryelection"
	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidExitPoolElectionWorkerComposition = errors.New("invalid Exit Pool election worker composition")

// composeExitPoolElectionWorker elects Exit Pool primaries, and spread
// pools' serving sets, from the exit nodes' health in Redis, with the
// election Sites use. It runs with the
// enforcement ledger worker when the deployment has exit nodes.
func composeExitPoolElectionWorker(settings config.EnforcementLedgerWorkerConfig, pool *postgresadapter.Pool,
	redisClient *redisadapter.Client, spread bool, logger *slog.Logger,
) (*primaryelection.Worker, prometheus.Collector, error) {
	if pool == nil || redisClient == nil || logger == nil {
		return nil, nil, errInvalidExitPoolElectionWorkerComposition
	}
	store, err := postgresadapter.NewExitPoolPrimaryStore(pool)
	if err != nil {
		return nil, nil, errors.Join(errInvalidExitPoolElectionWorkerComposition, err)
	}
	worker, err := primaryelection.New(primaryelection.Options{
		DeploymentID: settings.DeploymentID, PollInterval: siteElectionPoll,
		OperationTimeout: settings.OperationTimeout, Health: exitpool.ElectionHealth,
		Label: "Exit Pool", Key: "exit_pool", Code: "exit_pool_election", Overloaded: exitpool.Overloaded,
		Serving: spread,
	}, store, store, redisClient, accountsession.SystemClock{}, logger)
	if err != nil {
		return nil, nil, errors.Join(errInvalidExitPoolElectionWorkerComposition, err)
	}
	metrics, err := httpapi.NewExitPoolElectionWorkerMetricsCollector(worker)
	if err != nil {
		return nil, nil, errors.Join(errInvalidExitPoolElectionWorkerComposition, err)
	}
	return worker, metrics, nil
}

var _ app.Service = (*primaryelection.Worker)(nil)
