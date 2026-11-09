package config

import (
	"log/slog"
	"strconv"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/platform/app"
)

const (
	envNetworkSummaryWorkerEnabled    = "MESHTRANSIT_NETWORK_SUMMARY_WORKER_ENABLED"
	envNetworkSummaryWorkerDeployment = "MESHTRANSIT_NETWORK_SUMMARY_WORKER_DEPLOYMENT_PUBLIC_ID"
	envNetworkSummaryWorkerBatch      = "MESHTRANSIT_NETWORK_SUMMARY_WORKER_BATCH_SIZE"
	envNetworkSummaryWorkerPoll       = "MESHTRANSIT_NETWORK_SUMMARY_WORKER_POLL_INTERVAL"
	envNetworkSummaryWorkerTimeout    = "MESHTRANSIT_NETWORK_SUMMARY_WORKER_OPERATION_TIMEOUT"
	envNetworkSummaryWorkerLease      = "MESHTRANSIT_NETWORK_SUMMARY_WORKER_LEASE"
)

// NetworkSummaryWorkerConfig assigns the Network summary worker (TD-CON-48)
// to one installation.
type NetworkSummaryWorkerConfig struct {
	DeploymentID                          deployment.ID
	BatchSize                             int
	PollInterval, OperationTimeout, Lease time.Duration
}

// String redacts the trusted assignment in generic formatting.
func (NetworkSummaryWorkerConfig) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (NetworkSummaryWorkerConfig) GoString() string {
	return "config.NetworkSummaryWorkerConfig([REDACTED])"
}

// LogValue redacts structured formatting.
func (NetworkSummaryWorkerConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

func loadNetworkSummaryWorkerConfig(lookup LookupFunc, role app.Role) (*NetworkSummaryWorkerConfig, error) {
	enabled := valueOrDefault(lookup, envNetworkSummaryWorkerEnabled, "false")
	if enabled != "true" && enabled != "false" {
		return nil, settingError(envNetworkSummaryWorkerEnabled)
	}
	settings := []string{envNetworkSummaryWorkerDeployment, envNetworkSummaryWorkerBatch,
		envNetworkSummaryWorkerPoll, envNetworkSummaryWorkerTimeout, envNetworkSummaryWorkerLease}
	if enabled == "false" {
		for _, name := range settings {
			if _, present := lookup(name); present {
				return nil, settingError(name)
			}
		}
		return nil, nil
	}
	if role != app.RoleAll && role != app.RoleWorker {
		return nil, settingError(envNetworkSummaryWorkerEnabled)
	}
	installation, err := deployment.ParseID(valueOrDefault(lookup, envNetworkSummaryWorkerDeployment, ""))
	if err != nil {
		return nil, settingError(envNetworkSummaryWorkerDeployment)
	}
	batch, err := parseIntInRange(valueOrDefault(lookup, envNetworkSummaryWorkerBatch, strconv.Itoa(8)), 1, 64)
	if err != nil {
		return nil, settingError(envNetworkSummaryWorkerBatch)
	}
	poll, err := parseDurationInRange(valueOrDefault(lookup, envNetworkSummaryWorkerPoll, "5s"),
		500*time.Millisecond, time.Minute)
	if err != nil {
		return nil, settingError(envNetworkSummaryWorkerPoll)
	}
	timeout, err := parseDurationInRange(valueOrDefault(lookup, envNetworkSummaryWorkerTimeout, "10s"),
		100*time.Millisecond, 30*time.Second)
	if err != nil {
		return nil, settingError(envNetworkSummaryWorkerTimeout)
	}
	lease, err := parseDurationInRange(valueOrDefault(lookup, envNetworkSummaryWorkerLease, "2m"),
		5*time.Second, 5*time.Minute)
	// The lease covers a whole batch counted one Network at a time.
	if err != nil || lease < time.Duration(batch)*timeout+10*time.Second || lease%time.Second != 0 {
		return nil, settingError(envNetworkSummaryWorkerLease)
	}
	return &NetworkSummaryWorkerConfig{DeploymentID: installation, BatchSize: batch, PollInterval: poll,
		OperationTimeout: timeout, Lease: lease}, nil
}
