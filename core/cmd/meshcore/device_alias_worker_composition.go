package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/adapter/httpapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/domain/sharing/devicealias"
	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidDeviceAliasWorkerComposition = errors.New("invalid Device alias worker composition")

func composeDeviceAliasWorker(settings config.DeviceAliasWorkerConfig, pool *postgresadapter.Pool, hints *aliasWorkHints,
	logger *slog.Logger,
) (*devicealias.Worker, prometheus.Collector, error) {
	if pool == nil || hints == nil || logger == nil {
		return nil, nil, errInvalidDeviceAliasWorkerComposition
	}
	store, err := postgresadapter.NewDeviceAliasWorkerStore(pool)
	if err != nil {
		return nil, nil, errors.Join(errInvalidDeviceAliasWorkerComposition, err)
	}
	worker, err := devicealias.New(devicealias.Options{
		DeploymentID: settings.DeploymentID, BatchSize: settings.BatchSize, PollInterval: settings.PollInterval,
		OperationTimeout: settings.OperationTimeout, IdleInterval: settings.IdleInterval, Hints: hints,
	}, store, store, logger)
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

// composeDeviceAliasHints wakes the Device alias worker on recorded alias
// claims and on Network revisions (docs/performance-logic-plan.md §8, L1b).
func composeDeviceAliasHints(client *redisadapter.Client, logger *slog.Logger) *aliasWorkHints {
	return newAliasWorkHints(logger,
		aliasHintSource{name: "alias_claims", subscribe: func(ctx context.Context) (aliasHintSubscription, error) {
			subscription, err := client.SubscribeDeviceAliasClaimed(ctx)
			if err != nil {
				return nil, err
			}
			return claimHintSubscription{subscription}, nil
		}},
		aliasHintSource{name: "network_revisions", subscribe: func(ctx context.Context) (aliasHintSubscription, error) {
			subscription, err := client.SubscribeNetworkRevisionAdvanced(ctx)
			if err != nil {
				return nil, err
			}
			return revisionHintSubscription{subscription}, nil
		}},
	)
}

type claimHintSubscription struct {
	*redisadapter.DeviceAliasSubscription
}

func (subscription claimHintSubscription) Receive(ctx context.Context) error {
	return claimHintResult(subscription.DeviceAliasSubscription.Receive(ctx))
}

// claimHintResult skips a malformed claim hint; the subscription goes on.
func claimHintResult(err error) error {
	if errors.Is(err, redisadapter.ErrInvalidDeviceAliasWakeup) {
		return errors.Join(errMalformedAliasHint, err)
	}
	return err
}

type revisionHintSubscription struct {
	*redisadapter.RevisionSubscription
}

func (subscription revisionHintSubscription) Receive(ctx context.Context) error {
	_, err := subscription.RevisionSubscription.Receive(ctx)
	return revisionHintResult(err)
}

// revisionHintResult counts a revision wakeup the worker cannot decode (a
// payload version from a newer release, during a rollout) as a hint all the
// same: only its arrival matters here.
func revisionHintResult(err error) error {
	if errors.Is(err, redisadapter.ErrInvalidRevisionWakeup) {
		return nil
	}
	return err
}

var _ app.Service = (*aliasWorkHints)(nil)
var _ app.Service = (*aliasClaimAnnouncer)(nil)
