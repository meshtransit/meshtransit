package config

import (
	"log/slog"
	"strconv"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/platform/app"
)

const (
	envDeviceAliasWorkerEnabled    = "MESHTRANSIT_DEVICE_ALIAS_WORKER_ENABLED"
	envDeviceAliasWorkerDeployment = "MESHTRANSIT_DEVICE_ALIAS_DEPLOYMENT_PUBLIC_ID"
	envDeviceAliasWorkerBatch      = "MESHTRANSIT_DEVICE_ALIAS_WORKER_BATCH_SIZE"
	envDeviceAliasWorkerPoll       = "MESHTRANSIT_DEVICE_ALIAS_WORKER_POLL_INTERVAL"
	envDeviceAliasWorkerTimeout    = "MESHTRANSIT_DEVICE_ALIAS_WORKER_OPERATION_TIMEOUT"
	envDeviceAliasWorkerIdle       = "MESHTRANSIT_DEVICE_ALIAS_WORKER_IDLE_INTERVAL"
	// defaultDeviceAliasWorkerIdle is the longest pause between two sweeps
	// that found no work while the worker hears alias claims and Network
	// revisions (docs/performance-logic-plan.md §8, L1b).
	defaultDeviceAliasWorkerIdle = 5 * time.Second
)

// DeviceAliasWorkerConfig is an explicit client-only installation assignment.
// It contains no gateway origin, credentials, table scope or packet rule.
type DeviceAliasWorkerConfig struct {
	DeploymentID                   deployment.ID
	BatchSize                      int
	PollInterval, OperationTimeout time.Duration
	// IdleInterval is the longest pause between two sweeps without work.
	IdleInterval time.Duration
}

// String redacts the trusted assignment in generic formatting.
func (DeviceAliasWorkerConfig) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (DeviceAliasWorkerConfig) GoString() string { return "config.DeviceAliasWorkerConfig([REDACTED])" }

// LogValue redacts structured formatting.
func (DeviceAliasWorkerConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

func loadDeviceAliasWorkerConfig(lookup LookupFunc, role app.Role) (*DeviceAliasWorkerConfig, error) {
	enabled := valueOrDefault(lookup, envDeviceAliasWorkerEnabled, "false")
	if enabled != "true" && enabled != "false" {
		return nil, settingError(envDeviceAliasWorkerEnabled)
	}
	settings := []string{envDeviceAliasWorkerDeployment, envDeviceAliasWorkerBatch, envDeviceAliasWorkerPoll, envDeviceAliasWorkerTimeout, envDeviceAliasWorkerIdle}
	if enabled == "false" {
		for _, name := range settings {
			if _, present := lookup(name); present {
				return nil, settingError(name)
			}
		}
		return nil, nil
	}
	if role != app.RoleAll && role != app.RoleWorker {
		return nil, settingError(envDeviceAliasWorkerEnabled)
	}
	installation, err := deployment.ParseID(valueOrDefault(lookup, envDeviceAliasWorkerDeployment, ""))
	if err != nil {
		return nil, settingError(envDeviceAliasWorkerDeployment)
	}
	batch, err := parseIntInRange(valueOrDefault(lookup, envDeviceAliasWorkerBatch, strconv.Itoa(8)), 1, 128)
	if err != nil {
		return nil, settingError(envDeviceAliasWorkerBatch)
	}
	poll, err := parseDurationInRange(valueOrDefault(lookup, envDeviceAliasWorkerPoll, "500ms"), 100*time.Millisecond, time.Minute)
	if err != nil {
		return nil, settingError(envDeviceAliasWorkerPoll)
	}
	timeout, err := parseDurationInRange(valueOrDefault(lookup, envDeviceAliasWorkerTimeout, "10s"), 100*time.Millisecond, 15*time.Second)
	if err != nil {
		return nil, settingError(envDeviceAliasWorkerTimeout)
	}
	idle, err := parseDurationInRange(valueOrDefault(lookup, envDeviceAliasWorkerIdle, max(defaultDeviceAliasWorkerIdle, poll).String()), poll, time.Minute)
	if err != nil {
		return nil, settingError(envDeviceAliasWorkerIdle)
	}
	return &DeviceAliasWorkerConfig{DeploymentID: installation, BatchSize: batch, PollInterval: poll, OperationTimeout: timeout, IdleInterval: idle}, nil
}
