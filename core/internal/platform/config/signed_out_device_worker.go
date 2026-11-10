package config

import (
	"log/slog"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/platform/app"
)

const (
	envSignedOutDeviceWorkerEnabled    = "MESHTRANSIT_SIGNED_OUT_DEVICE_WORKER_ENABLED"
	envSignedOutDeviceWorkerDeployment = "MESHTRANSIT_SIGNED_OUT_DEVICE_WORKER_DEPLOYMENT_PUBLIC_ID"
	envSignedOutDeviceWorkerPoll       = "MESHTRANSIT_SIGNED_OUT_DEVICE_WORKER_POLL_INTERVAL"
	envSignedOutDeviceWorkerTimeout    = "MESHTRANSIT_SIGNED_OUT_DEVICE_WORKER_OPERATION_TIMEOUT"
)

// SignedOutDeviceWorkerConfig assigns the worker that removes Devices
// signed out past their hold (schema 284) to one installation.
type SignedOutDeviceWorkerConfig struct {
	DeploymentID                   deployment.ID
	PollInterval, OperationTimeout time.Duration
}

// String redacts the trusted assignment in generic formatting.
func (SignedOutDeviceWorkerConfig) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (SignedOutDeviceWorkerConfig) GoString() string {
	return "config.SignedOutDeviceWorkerConfig([REDACTED])"
}

// LogValue redacts structured formatting.
func (SignedOutDeviceWorkerConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

func loadSignedOutDeviceWorkerConfig(lookup LookupFunc, role app.Role) (*SignedOutDeviceWorkerConfig, error) {
	enabled := valueOrDefault(lookup, envSignedOutDeviceWorkerEnabled, "false")
	if enabled != "true" && enabled != "false" {
		return nil, settingError(envSignedOutDeviceWorkerEnabled)
	}
	settings := []string{envSignedOutDeviceWorkerDeployment, envSignedOutDeviceWorkerPoll,
		envSignedOutDeviceWorkerTimeout}
	if enabled == "false" {
		for _, name := range settings {
			if _, present := lookup(name); present {
				return nil, settingError(name)
			}
		}
		return nil, nil
	}
	if role != app.RoleAll && role != app.RoleWorker {
		return nil, settingError(envSignedOutDeviceWorkerEnabled)
	}
	installation, err := deployment.ParseID(valueOrDefault(lookup, envSignedOutDeviceWorkerDeployment, ""))
	if err != nil {
		return nil, settingError(envSignedOutDeviceWorkerDeployment)
	}
	// A Device is due 30 days after it signed out: a minute's delay is fine.
	poll, err := parseDurationInRange(valueOrDefault(lookup, envSignedOutDeviceWorkerPoll, "1m"),
		time.Second, time.Hour)
	if err != nil {
		return nil, settingError(envSignedOutDeviceWorkerPoll)
	}
	timeout, err := parseDurationInRange(valueOrDefault(lookup, envSignedOutDeviceWorkerTimeout, "30s"),
		time.Second, time.Minute)
	if err != nil {
		return nil, settingError(envSignedOutDeviceWorkerTimeout)
	}
	return &SignedOutDeviceWorkerConfig{DeploymentID: installation, PollInterval: poll,
		OperationTimeout: timeout}, nil
}
