package main

import (
	"errors"

	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
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
