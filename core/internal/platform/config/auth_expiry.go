package config

import (
	"log/slog"
	"strconv"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/platform/app"
)

const (
	envAuthExpiryEnabled         = "MESHTRANSIT_AUTH_EXPIRY_ENABLED"
	envAuthExpiryDeploymentID    = "MESHTRANSIT_AUTH_EXPIRY_DEPLOYMENT_PUBLIC_ID"
	envAuthExpiryBatchSize       = "MESHTRANSIT_AUTH_EXPIRY_BATCH_SIZE"
	envAuthExpiryPollInterval    = "MESHTRANSIT_AUTH_EXPIRY_POLL_INTERVAL"
	envAuthExpirySweepTimeout    = "MESHTRANSIT_AUTH_EXPIRY_SWEEP_TIMEOUT"
	envAuthExpiryUnitTimeout     = "MESHTRANSIT_AUTH_EXPIRY_UNIT_TIMEOUT"
	envAuthExpiryRollbackTimeout = "MESHTRANSIT_AUTH_EXPIRY_ROLLBACK_TIMEOUT"
)

// AuthExpiryConfig is an opt-in no-grant worker with one trusted exact assignment.
// It neither enables public browser login nor proves target cleanup coverage.
type AuthExpiryConfig struct {
	DeploymentID                                            deployment.ID
	BatchSize                                               int
	PollInterval, PassTimeout, UnitTimeout, RollbackTimeout time.Duration
}

// String omits private deployment assignment from effective configuration output.
func (AuthExpiryConfig) String() string { return "[REDACTED]" }

// GoString redacts detailed formatting.
func (AuthExpiryConfig) GoString() string { return "config.AuthExpiryConfig([REDACTED])" }

// LogValue redacts structured logging.
func (AuthExpiryConfig) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func loadAuthExpiryConfig(lookup LookupFunc, role app.Role, shutdown time.Duration) (*AuthExpiryConfig, error) {
	enabled := valueOrDefault(lookup, envAuthExpiryEnabled, "false")
	if enabled != "true" && enabled != "false" {
		return nil, settingError(envAuthExpiryEnabled)
	}
	settings := []string{
		envAuthExpiryDeploymentID, envAuthExpiryBatchSize, envAuthExpiryPollInterval,
		envAuthExpirySweepTimeout, envAuthExpiryUnitTimeout, envAuthExpiryRollbackTimeout,
	}
	if enabled == "false" {
		for _, key := range settings {
			if _, present := lookup(key); present {
				return nil, settingError(key)
			}
		}
		return nil, nil
	}
	if role != app.RoleAll && role != app.RoleWorker {
		return nil, settingError(envAuthExpiryEnabled)
	}
	dep, err := deployment.ParseID(valueOrDefault(lookup, envAuthExpiryDeploymentID, ""))
	if err != nil {
		return nil, settingError(envAuthExpiryDeploymentID)
	}
	batch, err := parseIntInRange(valueOrDefault(lookup, envAuthExpiryBatchSize, strconv.Itoa(8)), 1, 128)
	if err != nil {
		return nil, settingError(envAuthExpiryBatchSize)
	}
	result := &AuthExpiryConfig{DeploymentID: dep, BatchSize: batch}
	for _, field := range []struct {
		key                        string
		fallback, minimum, maximum time.Duration
		destination                *time.Duration
	}{
		{key: envAuthExpiryPollInterval, fallback: time.Second, minimum: 100 * time.Millisecond,
			maximum: time.Minute, destination: &result.PollInterval},
		{key: envAuthExpirySweepTimeout, fallback: 10 * time.Second, minimum: 100 * time.Millisecond,
			maximum: 30 * time.Second, destination: &result.PassTimeout},
		{key: envAuthExpiryUnitTimeout, fallback: time.Second, minimum: 100 * time.Millisecond,
			maximum: 30 * time.Second, destination: &result.UnitTimeout},
		{key: envAuthExpiryRollbackTimeout, fallback: time.Second, minimum: 100 * time.Millisecond,
			maximum: 5 * time.Second, destination: &result.RollbackTimeout},
	} {
		value, parseErr := parseDurationInRange(
			valueOrDefault(lookup, field.key, field.fallback.String()),
			field.minimum,
			field.maximum,
		)
		if parseErr != nil {
			return nil, settingError(field.key)
		}
		*field.destination = value
	}
	if result.UnitTimeout > result.PassTimeout {
		return nil, settingError(envAuthExpiryUnitTimeout)
	}
	// Adapter-owned setup/read rollback is two seconds, independent of the pass.
	cleanupReserve := max(2*time.Second, result.RollbackTimeout) + time.Second
	if shutdown <= cleanupReserve {
		return nil, settingError(envShutdownTimeout)
	}
	return result, nil
}
