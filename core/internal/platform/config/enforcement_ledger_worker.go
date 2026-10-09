package config

import (
	"log/slog"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/platform/app"
)

const (
	envEnforcementLedgerWorkerEnabled    = "MESHTRANSIT_ENFORCEMENT_LEDGER_WORKER_ENABLED"
	envEnforcementLedgerWorkerDeployment = "MESHTRANSIT_ENFORCEMENT_LEDGER_WORKER_DEPLOYMENT_PUBLIC_ID"
	envEnforcementLedgerWorkerPoll       = "MESHTRANSIT_ENFORCEMENT_LEDGER_WORKER_POLL_INTERVAL"
	envEnforcementLedgerWorkerPrune      = "MESHTRANSIT_ENFORCEMENT_LEDGER_WORKER_PRUNE_INTERVAL"
	envEnforcementLedgerWorkerTimeout    = "MESHTRANSIT_ENFORCEMENT_LEDGER_WORKER_OPERATION_TIMEOUT"
)

// EnforcementLedgerWorkerConfig assigns the enforcement evidence ledger
// (R1-69) to one installation. Retention is fixed by the schema.
type EnforcementLedgerWorkerConfig struct {
	DeploymentID                                  deployment.ID
	PollInterval, PruneInterval, OperationTimeout time.Duration
}

// String redacts the trusted assignment in generic formatting.
func (EnforcementLedgerWorkerConfig) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (EnforcementLedgerWorkerConfig) GoString() string {
	return "config.EnforcementLedgerWorkerConfig([REDACTED])"
}

// LogValue redacts structured formatting.
func (EnforcementLedgerWorkerConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

func loadEnforcementLedgerWorkerConfig(lookup LookupFunc, role app.Role) (*EnforcementLedgerWorkerConfig, error) {
	enabled := valueOrDefault(lookup, envEnforcementLedgerWorkerEnabled, "false")
	if enabled != "true" && enabled != "false" {
		return nil, settingError(envEnforcementLedgerWorkerEnabled)
	}
	settings := []string{envEnforcementLedgerWorkerDeployment, envEnforcementLedgerWorkerPoll,
		envEnforcementLedgerWorkerPrune, envEnforcementLedgerWorkerTimeout}
	if enabled == "false" {
		for _, name := range settings {
			if _, present := lookup(name); present {
				return nil, settingError(name)
			}
		}
		return nil, nil
	}
	if role != app.RoleAll && role != app.RoleWorker {
		return nil, settingError(envEnforcementLedgerWorkerEnabled)
	}
	installation, err := deployment.ParseID(valueOrDefault(lookup, envEnforcementLedgerWorkerDeployment, ""))
	if err != nil {
		return nil, settingError(envEnforcementLedgerWorkerDeployment)
	}
	poll, err := parseDurationInRange(valueOrDefault(lookup, envEnforcementLedgerWorkerPoll, "15s"),
		100*time.Millisecond, 5*time.Minute)
	if err != nil {
		return nil, settingError(envEnforcementLedgerWorkerPoll)
	}
	prune, err := parseDurationInRange(valueOrDefault(lookup, envEnforcementLedgerWorkerPrune, "1h"),
		time.Minute, 24*time.Hour)
	if err != nil {
		return nil, settingError(envEnforcementLedgerWorkerPrune)
	}
	timeout, err := parseDurationInRange(valueOrDefault(lookup, envEnforcementLedgerWorkerTimeout, "10s"),
		100*time.Millisecond, 30*time.Second)
	if err != nil {
		return nil, settingError(envEnforcementLedgerWorkerTimeout)
	}
	return &EnforcementLedgerWorkerConfig{DeploymentID: installation, PollInterval: poll, PruneInterval: prune,
		OperationTimeout: timeout}, nil
}
