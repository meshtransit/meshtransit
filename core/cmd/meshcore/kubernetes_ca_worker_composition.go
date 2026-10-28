package main

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/adapter/httpapi"
	"meshtransit.net/core/internal/adapter/kubecustody"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/kubeca/lifecycle"
	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/core/internal/platform/buildinfo"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidKubernetesCAWorkerComposition = errors.New("invalid Kubernetes CA worker composition")

func composeKubernetesCAWorker(settings config.KubernetesCAWorkerConfig, suffix dnsname.Suffix,
	pool *postgresadapter.Pool, logger *slog.Logger,
) (*lifecycle.Worker, prometheus.Collector, error) {
	if pool == nil || logger == nil || !suffix.IsValid() {
		return nil, nil, errInvalidKubernetesCAWorkerComposition
	}
	store, err := postgresadapter.NewKubernetesClusterCAStore(pool)
	if err != nil {
		return nil, nil, errors.Join(errInvalidKubernetesCAWorkerComposition, err)
	}
	version := buildinfo.Current().Version
	if version == "" {
		version = "unknown"
	}
	worker, err := lifecycle.New(lifecycle.Options{
		DeploymentID: settings.DeploymentID, Suffix: suffix, BatchSize: settings.BatchSize,
		PollInterval: settings.PollInterval, OperationTimeout: settings.OperationTimeout, Version: version,
		Policy: lifecycle.DefaultPolicy(),
	}, store, fileCustodySource(settings), logger)
	if err != nil {
		return nil, nil, errors.Join(errInvalidKubernetesCAWorkerComposition, err)
	}
	metrics, err := httpapi.NewKubernetesCAWorkerMetricsCollector(worker)
	if err != nil {
		return nil, nil, errors.Join(errInvalidKubernetesCAWorkerComposition, err)
	}
	return worker, metrics, nil
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

var _ app.Service = (*lifecycle.Worker)(nil)
