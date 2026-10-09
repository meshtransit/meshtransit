package main

import (
	"errors"
	"log/slog"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/domain/network/revisionworker"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidWorkerComposition = errors.New("invalid worker composition")

func composeRevisionWorker(
	workerConfig config.RevisionWorkerConfig,
	workerPool *postgresadapter.Pool,
	redisClient *redisadapter.Client,
	telemetry *revisionworker.Telemetry,
	logger *slog.Logger,
) (*revisionworker.Dispatcher, error) {
	if workerPool == nil || redisClient == nil || telemetry == nil || logger == nil {
		return nil, errInvalidWorkerComposition
	}
	outbox, err := postgresadapter.NewOutboxStore(workerPool)
	if err != nil {
		return nil, err
	}
	workerID, err := revisionworker.NewWorkerID()
	if err != nil {
		return nil, err
	}
	return revisionworker.New(
		revisionworker.Options{
			WorkerID:         workerID,
			BatchSize:        workerConfig.BatchSize,
			Lease:            workerConfig.Lease,
			PollInterval:     workerConfig.PollInterval,
			RetryDelay:       workerConfig.RetryDelay,
			OperationTimeout: workerConfig.OperationTimeout,
		},
		outbox,
		redisClient,
		telemetry,
		logger,
	)
}
