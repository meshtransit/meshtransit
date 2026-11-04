//go:build dexbroker

package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"

	"meshtransit.net/core/internal/adapter/dexbroker"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/observability"
)

type identityFingerprintOutput struct {
	Algorithm     string `json:"algorithm"`
	Fingerprint   string `json:"fingerprint"`
	SchemaVersion int    `json:"schema_version"`
}

func runIdentityFingerprint(
	ctx context.Context,
	lookup config.LookupFunc,
	output io.Writer,
	errorOutput io.Writer,
) int {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}
	identity, err := config.LoadIdentityFingerprintInput(lookup)
	if err != nil {
		logger.ErrorContext(ctx, "identity fingerprint failed", "error_code", "invalid_configuration")
		return 1
	}
	fingerprint, err := dexbroker.CalculateConfigurationFingerprint(identityServiceOptions(identity))
	if err != nil {
		logger.ErrorContext(ctx, "identity fingerprint failed", "error_code", "invalid_secret_material")
		return 1
	}
	result := identityFingerprintOutput{
		Algorithm: "sha256-v2", Fingerprint: fingerprint, SchemaVersion: config.SchemaVersion,
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		logger.ErrorContext(ctx, "identity fingerprint failed", "error_code", "output_failure")
		return 1
	}
	return 0
}

// identityFingerprintFromSettings fingerprints identity settings given as a
// table (meshcore setup), exactly as "identity fingerprint" does from the
// environment.
func identityFingerprintFromSettings(settings map[string]string) (string, error) {
	identity, err := config.LoadIdentityFingerprintInput(settingsLookup(settings))
	if err != nil {
		return "", err
	}
	return dexbroker.CalculateConfigurationFingerprint(identityServiceOptions(identity))
}
