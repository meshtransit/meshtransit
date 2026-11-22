package main

import (
	"context"
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
	tokens, err := kubecluster.NewInstallTokens(store, accountsession.SystemClock{}, kubecluster.SystemSecrets{})
	if err != nil {
		return nil, errors.Join(errInvalidKubernetesClusterComposition, err)
	}
	trusts, err := kubecluster.NewTrusts(store, accountsession.SystemClock{})
	if err != nil {
		return nil, errors.Join(errInvalidKubernetesClusterComposition, err)
	}
	return kubernetesClusterManager{Service: service, tokens: tokens, trusts: trusts}, nil
}

// kubernetesClusterManager is the cluster service with its install tokens
// and trust actions (V1-12), which the management API finds as
// httpapi.KubernetesTrustManager.
type kubernetesClusterManager struct {
	*kubecluster.Service
	tokens *kubecluster.InstallTokens
	trusts *kubecluster.Trusts
}

var _ httpapi.KubernetesTrustManager = kubernetesClusterManager{}

func (manager kubernetesClusterManager) SetClusterTrustMode(ctx context.Context,
	change kubecluster.TrustModeChange) (kubecluster.TrustModeResult, error) {
	return manager.tokens.SetTrustMode(ctx, change)
}

func (manager kubernetesClusterManager) IssueInstallToken(ctx context.Context,
	request kubecluster.InstallTokenRequest) (kubecluster.IssuedInstallToken, error) {
	return manager.tokens.Issue(ctx, request)
}

func (manager kubernetesClusterManager) ConfirmClusterTrust(ctx context.Context,
	decision kubecluster.TrustDecision) (kubecluster.TrustDecisionResult, error) {
	return manager.trusts.Confirm(ctx, decision)
}

func (manager kubernetesClusterManager) ChooseClusterTrust(ctx context.Context,
	decision kubecluster.TrustDecision) (kubecluster.TrustDecisionResult, error) {
	return manager.trusts.Choose(ctx, decision)
}

func (manager kubernetesClusterManager) ResetClusterTrust(ctx context.Context,
	reset kubecluster.TrustReset) (kubecluster.TrustDecisionResult, error) {
	return manager.trusts.Reset(ctx, reset)
}
