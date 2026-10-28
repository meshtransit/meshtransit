package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/adapter/httpapi"
	"meshtransit.net/core/internal/adapter/kubecustody"
	"meshtransit.net/core/internal/adapter/kubetoken"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/kubeca/lifecycle"
	"meshtransit.net/core/internal/domain/kubeca/signing"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/core/internal/platform/buildinfo"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/shared/kubejoin"
	"meshtransit.net/shared/mtcp"
)

var errInvalidKubernetesCAWorkerComposition = errors.New("invalid Kubernetes CA worker composition")

// kubernetesCAWorkers are the worker's two Kubernetes CA services: the
// lifecycle of the CAs, and the signing of gateway certificates (a3).
type kubernetesCAWorkers struct {
	lifecycle *lifecycle.Worker
	signer    *signing.Worker
	// hints, with Redis, wakes the signer when control queues a request.
	hints   *kubeCertHints
	metrics []prometheus.Collector
}

func composeKubernetesCAWorker(settings config.KubernetesCAWorkerConfig, suffix dnsname.Suffix,
	pool *postgresadapter.Pool, marks lifecycle.MarkKeeper, hints *redisadapter.Client, logger *slog.Logger,
) (kubernetesCAWorkers, error) {
	if pool == nil || marks == nil || logger == nil || !suffix.IsValid() {
		return kubernetesCAWorkers{}, errInvalidKubernetesCAWorkerComposition
	}
	store, err := postgresadapter.NewKubernetesClusterCAStore(pool)
	if err != nil {
		return kubernetesCAWorkers{}, errors.Join(errInvalidKubernetesCAWorkerComposition, err)
	}
	certificates, err := postgresadapter.NewKubernetesGatewayCertificateStore(pool)
	if err != nil {
		return kubernetesCAWorkers{}, errors.Join(errInvalidKubernetesCAWorkerComposition, err)
	}
	version := buildinfo.Current().Version
	if version == "" {
		version = "unknown"
	}
	worker, err := lifecycle.New(lifecycle.Options{
		DeploymentID: settings.DeploymentID, Suffix: suffix, BatchSize: settings.BatchSize,
		PollInterval: settings.PollInterval, OperationTimeout: settings.OperationTimeout, Version: version,
		Policy: lifecycle.DefaultPolicy(), Marks: marks,
	}, store, fileCustodySource(settings), logger)
	if err != nil {
		return kubernetesCAWorkers{}, errors.Join(errInvalidKubernetesCAWorkerComposition, err)
	}
	signerOptions := signing.Options{
		DeploymentID: settings.DeploymentID, Suffix: suffix, Version: version,
		BatchSize: kubernetesCertificateBatch, OperationTimeout: settings.OperationTimeout,
		MaximumPerSecond: kubernetesCertificatesPerSecond,
	}
	var wakeups *kubeCertHints
	if hints != nil {
		// Redis hints (a3 §14 R-H3): control's queued requests wake the
		// signer; each settled request wakes the session waiting for it.
		wake := make(chan struct{}, 1)
		wakeups = queuedKubeCertHints(hints, wake, logger)
		signerOptions.Wake = wake
		signerOptions.Settled = func(_ context.Context, request publicid.ID) {
			wakeups.Publish(func(ctx context.Context) { _ = hints.PublishKubeCertSettled(ctx, request) })
		}
	}
	signer, err := signing.New(signerOptions, certificates, fileCustodySource(settings), verifyGatewayCertificateToken, mtcp.VerifyKubeCertRenewal, logger)
	if err != nil {
		return kubernetesCAWorkers{}, errors.Join(errInvalidKubernetesCAWorkerComposition, err)
	}
	lifecycleMetrics, err := httpapi.NewKubernetesCAWorkerMetricsCollector(worker)
	if err != nil {
		return kubernetesCAWorkers{}, errors.Join(errInvalidKubernetesCAWorkerComposition, err)
	}
	signerMetrics, err := httpapi.NewKubernetesCertificateSignerMetricsCollector(signer)
	if err != nil {
		return kubernetesCAWorkers{}, errors.Join(errInvalidKubernetesCAWorkerComposition, err)
	}
	return kubernetesCAWorkers{
		lifecycle: worker, signer: signer, hints: wakeups,
		metrics: []prometheus.Collector{lifecycleMetrics, signerMetrics},
	}, nil
}

const (
	// kubernetesCertificateBatch is how many requests one claim takes.
	kubernetesCertificateBatch = 8
	// kubernetesCertificatesPerSecond bounds the signing rate of one worker
	// process (§4).
	kubernetesCertificatesPerSecond = 100
)

// verifyGatewayCertificateToken checks a certificate request's pod token
// against its cluster's signing trust and the pod the Device's join named,
// as a key rotation's (K1.1 §7.3).
func verifyGatewayCertificateToken(raw string, trust signing.Trust, now time.Time) (signing.TokenUse, error) {
	jwks, err := kubejoin.ParseJWKS(trust.JWKS)
	if err != nil {
		return signing.TokenUse{}, err
	}
	claims, err := kubetoken.Verify(raw, kubetoken.Expectation{
		Issuer: trust.Issuer, JWKS: jwks, Namespace: trust.Namespace, ServiceAccount: trust.ServiceAccount,
		PodName: trust.PodName,
	}, now)
	if err != nil {
		return signing.TokenUse{}, err
	}
	return signing.TokenUse{JTI: claims.JTI, ExpiresAt: claims.Expiry, PodName: claims.PodName}, nil
}

// fileCustodySource reads the wrap key and the previous ones each time the
// worker builds its custody, every minute: a key file mounted or rotated
// after start is picked up within a minute (K1a4 §13 N8).
func fileCustodySource(settings config.KubernetesCAWorkerConfig) lifecycle.CustodySource {
	return func(context.Context) (kubeca.Custody, string, error) {
		primary, err := readWrapKey(settings.WrapKeyFile)
		if err != nil {
			return nil, "", err
		}
		previous := make([]kubeca.DataKey, 0, len(settings.PreviousWrapKeyFiles))
		for _, file := range settings.PreviousWrapKeyFiles {
			key, err := readWrapKey(file)
			if err != nil {
				return nil, "", err
			}
			previous = append(previous, key)
		}
		custody, err := kubecustody.NewFile(primary, previous)
		if err != nil {
			return nil, "", err
		}
		return custody, config.KubernetesCACustodyFile, nil
	}
}

// readWrapKey reads a 32-byte wrap key written in base64, URL-safe or
// standard, with or without padding (`openssl rand -base64 32`).
func readWrapKey(file config.SecretFile) (kubeca.DataKey, error) {
	encoded, err := file.Read()
	if err != nil {
		return kubeca.DataKey{}, err
	}
	canonical := strings.NewReplacer("+", "-", "/", "_").Replace(strings.TrimRight(encoded, "="))
	decoded, err := base64.RawURLEncoding.DecodeString(canonical)
	defer clear(decoded)
	if err != nil || len(decoded) != len(kubeca.DataKey{}) {
		return kubeca.DataKey{}, kubeca.ErrInvalid
	}
	key := kubeca.DataKey(decoded)
	if key.IsZero() {
		return kubeca.DataKey{}, kubeca.ErrInvalid
	}
	return key, nil
}

var (
	_ app.Service = (*lifecycle.Worker)(nil)
	_ app.Service = (*signing.Worker)(nil)
)
