package config

import (
	"log/slog"
	"strconv"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/platform/app"
)

const (
	envAccessLedgerWorkerEnabled    = "MESHTRANSIT_ACCESS_LEDGER_WORKER_ENABLED"
	envAccessLedgerWorkerDeployment = "MESHTRANSIT_ACCESS_LEDGER_WORKER_DEPLOYMENT_PUBLIC_ID"
	envAccessLedgerWorkerBatch      = "MESHTRANSIT_ACCESS_LEDGER_WORKER_BATCH_SIZE"
	envAccessLedgerWorkerPoll       = "MESHTRANSIT_ACCESS_LEDGER_WORKER_POLL_INTERVAL"
	envAccessLedgerWorkerPrune      = "MESHTRANSIT_ACCESS_LEDGER_WORKER_PRUNE_INTERVAL"
	envAccessLedgerWorkerTimeout    = "MESHTRANSIT_ACCESS_LEDGER_WORKER_OPERATION_TIMEOUT"
)

// AccessLedgerWorkerConfig assigns the access edge ledger (R1-68) to one
// installation. Retention is fixed by the schema, not configured here.
type AccessLedgerWorkerConfig struct {
	DeploymentID                                  deployment.ID
	BatchSize                                     int
	PollInterval, PruneInterval, OperationTimeout time.Duration
}

// String redacts the trusted assignment in generic formatting.
func (AccessLedgerWorkerConfig) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (AccessLedgerWorkerConfig) GoString() string {
	return "config.AccessLedgerWorkerConfig([REDACTED])"
}

// LogValue redacts structured formatting.
func (AccessLedgerWorkerConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

func loadAccessLedgerWorkerConfig(lookup LookupFunc, role app.Role) (*AccessLedgerWorkerConfig, error) {
	enabled := valueOrDefault(lookup, envAccessLedgerWorkerEnabled, "false")
	if enabled != "true" && enabled != "false" {
		return nil, settingError(envAccessLedgerWorkerEnabled)
	}
	settings := []string{envAccessLedgerWorkerDeployment, envAccessLedgerWorkerBatch, envAccessLedgerWorkerPoll,
		envAccessLedgerWorkerPrune, envAccessLedgerWorkerTimeout}
	if enabled == "false" {
		for _, name := range settings {
			if _, present := lookup(name); present {
				return nil, settingError(name)
			}
		}
		return nil, nil
	}
	if role != app.RoleAll && role != app.RoleWorker {
		return nil, settingError(envAccessLedgerWorkerEnabled)
	}
	installation, err := deployment.ParseID(valueOrDefault(lookup, envAccessLedgerWorkerDeployment, ""))
	if err != nil {
		return nil, settingError(envAccessLedgerWorkerDeployment)
	}
	batch, err := parseIntInRange(valueOrDefault(lookup, envAccessLedgerWorkerBatch, strconv.Itoa(16)), 1, 64)
	if err != nil {
		return nil, settingError(envAccessLedgerWorkerBatch)
	}
	poll, err := parseDurationInRange(valueOrDefault(lookup, envAccessLedgerWorkerPoll, "3s"), 100*time.Millisecond, time.Minute)
	if err != nil {
		return nil, settingError(envAccessLedgerWorkerPoll)
	}
	prune, err := parseDurationInRange(valueOrDefault(lookup, envAccessLedgerWorkerPrune, "1h"), time.Minute, 24*time.Hour)
	if err != nil {
		return nil, settingError(envAccessLedgerWorkerPrune)
	}
	timeout, err := parseDurationInRange(valueOrDefault(lookup, envAccessLedgerWorkerTimeout, "25s"), 100*time.Millisecond, 30*time.Second)
	if err != nil {
		return nil, settingError(envAccessLedgerWorkerTimeout)
	}
	return &AccessLedgerWorkerConfig{DeploymentID: installation, BatchSize: batch, PollInterval: poll,
		PruneInterval: prune, OperationTimeout: timeout}, nil
}
