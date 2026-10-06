package config

import (
	"log/slog"
	"strconv"
	"time"

	"github.com/meshtransit/meshtransit/internal/app"
	"github.com/meshtransit/meshtransit/internal/deployment"
)

const (
	envContractExpiryWorkerEnabled    = "MESHTRANSIT_CONTRACT_EXPIRY_WORKER_ENABLED"
	envContractExpiryWorkerDeployment = "MESHTRANSIT_CONTRACT_EXPIRY_WORKER_DEPLOYMENT_PUBLIC_ID"
	envContractExpiryWorkerBatch      = "MESHTRANSIT_CONTRACT_EXPIRY_WORKER_BATCH_SIZE"
	envContractExpiryWorkerPoll       = "MESHTRANSIT_CONTRACT_EXPIRY_WORKER_POLL_INTERVAL"
	envContractExpiryWorkerTimeout    = "MESHTRANSIT_CONTRACT_EXPIRY_WORKER_OPERATION_TIMEOUT"
)

// ContractExpiryWorkerConfig assigns the Trust Contract expiry finalizer to one
// installation. It carries no credentials, table scope or packet rule.
type ContractExpiryWorkerConfig struct {
	DeploymentID                   deployment.ID
	BatchSize                      int
	PollInterval, OperationTimeout time.Duration
}

// String redacts the trusted assignment in generic formatting.
func (ContractExpiryWorkerConfig) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (ContractExpiryWorkerConfig) GoString() string {
	return "config.ContractExpiryWorkerConfig([REDACTED])"
}

// LogValue redacts structured formatting.
func (ContractExpiryWorkerConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

func loadContractExpiryWorkerConfig(lookup LookupFunc, role app.Role) (*ContractExpiryWorkerConfig, error) {
	enabled := valueOrDefault(lookup, envContractExpiryWorkerEnabled, "false")
	if enabled != "true" && enabled != "false" {
		return nil, settingError(envContractExpiryWorkerEnabled)
	}
	settings := []string{envContractExpiryWorkerDeployment, envContractExpiryWorkerBatch, envContractExpiryWorkerPoll, envContractExpiryWorkerTimeout}
	if enabled == "false" {
		for _, name := range settings {
			if _, present := lookup(name); present {
				return nil, settingError(name)
			}
		}
		return nil, nil
	}
	if role != app.RoleAll && role != app.RoleWorker {
		return nil, settingError(envContractExpiryWorkerEnabled)
	}
	installation, err := deployment.ParseID(valueOrDefault(lookup, envContractExpiryWorkerDeployment, ""))
	if err != nil {
		return nil, settingError(envContractExpiryWorkerDeployment)
	}
	batch, err := parseIntInRange(valueOrDefault(lookup, envContractExpiryWorkerBatch, strconv.Itoa(16)), 1, 128)
	if err != nil {
		return nil, settingError(envContractExpiryWorkerBatch)
	}
	poll, err := parseDurationInRange(valueOrDefault(lookup, envContractExpiryWorkerPoll, "2s"), 100*time.Millisecond, time.Minute)
	if err != nil {
		return nil, settingError(envContractExpiryWorkerPoll)
	}
	timeout, err := parseDurationInRange(valueOrDefault(lookup, envContractExpiryWorkerTimeout, "10s"), 100*time.Millisecond, 15*time.Second)
	if err != nil {
		return nil, settingError(envContractExpiryWorkerTimeout)
	}
	return &ContractExpiryWorkerConfig{DeploymentID: installation, BatchSize: batch, PollInterval: poll, OperationTimeout: timeout}, nil
}
