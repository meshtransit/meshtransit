package main

import (
	"errors"

	"meshtransit.net/core/internal/adapter/httpapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidKubernetesClusterComposition = errors.New("invalid Kubernetes cluster composition")

// composeKubernetesClusters builds the Kubernetes cluster service when the
// process has the enrollment digest keys, which digest join keys too;
// without them it returns nil and the API reports clusters unavailable.
func composeKubernetesClusters(
	runtimePool *postgresadapter.Pool,
	digest *config.CredentialDigestConfig,
) (httpapi.KubernetesClusterManager, error) {
	if digest == nil {
		return nil, nil
	}
	if runtimePool == nil {
		return nil, errInvalidKubernetesClusterComposition
	}
	keyring, err := composeCredentialVerifier(*digest)
	if err != nil {
		return nil, errors.Join(errInvalidKubernetesClusterComposition, err)
	}
	store, err := postgresadapter.NewKubernetesClusterStore(runtimePool, postgresadapter.AccountSessionOptions{
		StatementTimeout: managementStatementTimeout, IdleTimeout: managementTransactionIdle,
	}, keyring)
	if err != nil {
		return nil, errors.Join(errInvalidKubernetesClusterComposition, err)
	}
	service, err := kubecluster.NewService(store, accountsession.SystemClock{}, kubecluster.SystemSecrets{})
	if err != nil {
		return nil, errors.Join(errInvalidKubernetesClusterComposition, err)
	}
	return service, nil
}
