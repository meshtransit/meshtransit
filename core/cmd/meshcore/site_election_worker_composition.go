package main

import (
	"errors"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/adapter/httpapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/site/election"
	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidSiteElectionWorkerComposition = errors.New("invalid Site election worker composition")

// siteElectionPoll is how often Sites are elected for: well inside the
// hold-down and silence bounds of design §6.2.
const siteElectionPoll = 10 * time.Second

// composeSiteElectionWorker elects Site primaries from the router health in
// Redis. It runs with the enforcement ledger worker, which reads the same
// delivery records for the same installation.
func composeSiteElectionWorker(settings config.EnforcementLedgerWorkerConfig, pool *postgresadapter.Pool,
	redisClient *redisadapter.Client, logger *slog.Logger) (*election.Worker, prometheus.Collector, error) {
	if pool == nil || redisClient == nil || logger == nil {
		return nil, nil, errInvalidSiteElectionWorkerComposition
	}
	store, err := postgresadapter.NewSitePrimaryStore(pool)
	if err != nil {
		return nil, nil, errors.Join(errInvalidSiteElectionWorkerComposition, err)
	}
	worker, err := election.New(election.Options{
		DeploymentID: settings.DeploymentID, PollInterval: siteElectionPoll,
		OperationTimeout: settings.OperationTimeout,
	}, store, store, redisClient, accountsession.SystemClock{}, logger)
	if err != nil {
		return nil, nil, errors.Join(errInvalidSiteElectionWorkerComposition, err)
	}
	metrics, err := httpapi.NewSiteElectionWorkerMetricsCollector(worker)
	if err != nil {
		return nil, nil, errors.Join(errInvalidSiteElectionWorkerComposition, err)
	}
	return worker, metrics, nil
}

var _ app.Service = (*election.Worker)(nil)
