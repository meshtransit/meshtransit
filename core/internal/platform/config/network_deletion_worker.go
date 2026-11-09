package config

import (
	"log/slog"
	"strconv"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/platform/app"
)

const (
	envNetworkDeletionWorkerEnabled    = "MESHTRANSIT_NETWORK_DELETION_WORKER_ENABLED"
	envNetworkDeletionWorkerDeployment = "MESHTRANSIT_NETWORK_DELETION_WORKER_DEPLOYMENT_PUBLIC_ID"
	envNetworkDeletionWorkerBatch      = "MESHTRANSIT_NETWORK_DELETION_WORKER_BATCH_SIZE"
	envNetworkDeletionWorkerPoll       = "MESHTRANSIT_NETWORK_DELETION_WORKER_POLL_INTERVAL"
	envNetworkDeletionWorkerTimeout    = "MESHTRANSIT_NETWORK_DELETION_WORKER_OPERATION_TIMEOUT"
)

// NetworkDeletionWorkerConfig assigns the Network deletion worker (phase 2,
// docs/network-delete-design.md) to one installation.
type NetworkDeletionWorkerConfig struct {
	DeploymentID                   deployment.ID
	BatchSize                      int
	PollInterval, OperationTimeout time.Duration
}

// String redacts the trusted assignment in generic formatting.
func (NetworkDeletionWorkerConfig) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (NetworkDeletionWorkerConfig) GoString() string {
	return "config.NetworkDeletionWorkerConfig([REDACTED])"
}

// LogValue redacts structured formatting.
func (NetworkDeletionWorkerConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

func loadNetworkDeletionWorkerConfig(lookup LookupFunc, role app.Role) (*NetworkDeletionWorkerConfig, error) {
	enabled := valueOrDefault(lookup, envNetworkDeletionWorkerEnabled, "false")
	if enabled != "true" && enabled != "false" {
		return nil, settingError(envNetworkDeletionWorkerEnabled)
	}
	settings := []string{envNetworkDeletionWorkerDeployment, envNetworkDeletionWorkerBatch,
		envNetworkDeletionWorkerPoll, envNetworkDeletionWorkerTimeout}
	if enabled == "false" {
		for _, name := range settings {
			if _, present := lookup(name); present {
				return nil, settingError(name)
			}
		}
		return nil, nil
	}
	if role != app.RoleAll && role != app.RoleWorker {
		return nil, settingError(envNetworkDeletionWorkerEnabled)
	}
	installation, err := deployment.ParseID(valueOrDefault(lookup, envNetworkDeletionWorkerDeployment, ""))
	if err != nil {
		return nil, settingError(envNetworkDeletionWorkerDeployment)
	}
	batch, err := parseIntInRange(valueOrDefault(lookup, envNetworkDeletionWorkerBatch, strconv.Itoa(500)), 1, 2000)
	if err != nil {
		return nil, settingError(envNetworkDeletionWorkerBatch)
	}
	poll, err := parseDurationInRange(valueOrDefault(lookup, envNetworkDeletionWorkerPoll, "10s"),
		time.Second, 5*time.Minute)
	if err != nil {
		return nil, settingError(envNetworkDeletionWorkerPoll)
	}
	timeout, err := parseDurationInRange(valueOrDefault(lookup, envNetworkDeletionWorkerTimeout, "30s"),
		time.Second, time.Minute)
	if err != nil {
		return nil, settingError(envNetworkDeletionWorkerTimeout)
	}
	return &NetworkDeletionWorkerConfig{DeploymentID: installation, BatchSize: batch, PollInterval: poll,
		OperationTimeout: timeout}, nil
}
