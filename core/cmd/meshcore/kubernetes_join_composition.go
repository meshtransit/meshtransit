package main

import (
	"context"
	"errors"
	"log/slog"

	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/domain/kubeca/certqueue"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidKubernetesJoinComposition = errors.New("invalid Kubernetes join composition")

// clusterJoinStores opens replicas' requests with the cluster store, which
// verifies join keys, and completes them with the completion store.
type clusterJoinStores struct {
	*postgresadapter.KubernetesClusterStore
	*postgresadapter.KubernetesJoinCompletionStore
}

var _ mtcpadapter.ClusterJoins = clusterJoinStores{}

// composeClusterJoins builds what MTCP sessions use to let Kubernetes
// gateway replicas join (mtcp-v1 §6.6), bounded like registrations.
func composeClusterJoins(enrollmentConfig config.EnrollmentConfig,
	runtimePool *postgresadapter.Pool) (mtcpadapter.ClusterJoins, error) {
	if runtimePool == nil {
		return nil, errInvalidKubernetesJoinComposition
	}
	keyring, err := composeCredentialVerifier(enrollmentConfig.CredentialDigest)
	if err != nil {
		return nil, errors.Join(errInvalidKubernetesJoinComposition, err)
	}
	database := enrollmentConfig.Registration.Database
	requests, err := postgresadapter.NewKubernetesClusterStore(runtimePool, postgresadapter.AccountSessionOptions{
		StatementTimeout: database.StatementTimeout, IdleTimeout: database.IdleTimeout,
	}, keyring)
	if err != nil {
		return nil, errors.Join(errInvalidKubernetesJoinComposition, err)
	}
	completions, err := postgresadapter.NewKubernetesJoinCompletionStore(runtimePool,
		postgresadapter.RegistrationTransactionOptions{
			StatementTimeout:      database.StatementTimeout,
			LockTimeout:           database.LockTimeout,
			IdleTimeout:           database.IdleTimeout,
			AddressCandidateLimit: enrollmentConfig.Registration.AddressCandidateLimit,
		})
	if err != nil {
		return nil, errors.Join(errInvalidKubernetesJoinComposition, err)
	}
	return clusterJoinStores{KubernetesClusterStore: requests, KubernetesJoinCompletionStore: completions}, nil
}

// composeGatewayKeys builds the store that moves Kubernetes gateways to new
// machine keys (mtcp-v1 §6.8). It is composed whether joins are enabled or
// not: gateways that joined keep rotating.
func composeGatewayKeys(registration config.RegistrationConfig,
	runtimePool *postgresadapter.Pool) (*postgresadapter.KubernetesGatewayKeyStore, error) {
	if runtimePool == nil {
		return nil, errInvalidKubernetesJoinComposition
	}
	store, err := postgresadapter.NewKubernetesGatewayKeyStore(runtimePool, postgresadapter.RegistrationTransactionOptions{
		StatementTimeout:      registration.Database.StatementTimeout,
		LockTimeout:           registration.Database.LockTimeout,
		IdleTimeout:           registration.Database.IdleTimeout,
		AddressCandidateLimit: registration.AddressCandidateLimit,
	})
	if err != nil {
		return nil, errors.Join(errInvalidKubernetesJoinComposition, err)
	}
	return store, nil
}

// composeKubeCertificates builds the certificate queue Kubernetes gateways
// ask through (gateway.cert1, mtcp-v1 §6.9), bounded like registrations.
// With Redis it also returns the hints service: queued requests wake the
// signing workers and settled ones wake the sessions waiting for them;
// without, the workers poll and sessions read back.
func composeKubeCertificates(registration config.RegistrationConfig, runtimePool *postgresadapter.Pool,
	client *redisadapter.Client, logger *slog.Logger,
) (*certqueue.Service, *kubeCertHints, error) {
	if runtimePool == nil || logger == nil {
		return nil, nil, errInvalidKubernetesJoinComposition
	}
	store, err := postgresadapter.NewKubernetesGatewayCertificateQueueStore(runtimePool,
		postgresadapter.RegistrationTransactionOptions{
			StatementTimeout:      registration.Database.StatementTimeout,
			LockTimeout:           registration.Database.LockTimeout,
			IdleTimeout:           registration.Database.IdleTimeout,
			AddressCandidateLimit: registration.AddressCandidateLimit,
		})
	if err != nil {
		return nil, nil, errors.Join(errInvalidKubernetesJoinComposition, err)
	}
	options := certqueue.Options{}
	var hints *kubeCertHints
	var service *certqueue.Service
	if client != nil {
		hints = newKubeCertHints("settled", func(ctx context.Context) (kubeCertHintSubscription, error) {
			return client.SubscribeKubeCertSettled(ctx)
		}, func(request publicid.ID) { service.Settled(request) }, logger)
		options.Queued = func(context.Context) {
			hints.Publish(func(ctx context.Context) { _ = client.PublishKubeCertQueued(ctx) })
		}
	}
	service, err = certqueue.New(store, options)
	if err != nil {
		return nil, nil, errors.Join(errInvalidKubernetesJoinComposition, err)
	}
	return service, hints, nil
}

// queuedKubeCertHints wakes an idle signing worker when a request is
// queued, and publishes the worker's settled requests.
func queuedKubeCertHints(client *redisadapter.Client, wake chan<- struct{}, logger *slog.Logger) *kubeCertHints {
	return newKubeCertHints("queued", func(ctx context.Context) (kubeCertHintSubscription, error) {
		return client.SubscribeKubeCertQueued(ctx)
	}, func(publicid.ID) {
		select {
		case wake <- struct{}{}:
		default:
		}
	}, logger)
}

// malformedHint reports a hint that could not be read; the subscription
// goes on.
func malformedHint(err error) bool { return errors.Is(err, redisadapter.ErrInvalidKubeCertWakeup) }
