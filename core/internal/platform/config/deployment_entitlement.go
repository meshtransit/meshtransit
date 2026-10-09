package config

import (
	"context"
	"errors"
	"log/slog"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/platform/app"
)

const (
	envEntitlementDeploymentID    = "MESHTRANSIT_ENTITLEMENT_DEPLOYMENT_PUBLIC_ID"
	envEntitlementFile            = "MESHTRANSIT_DEPLOYMENT_ENTITLEMENT_FILE"
	envEntitlementInstallationKey = "MESHTRANSIT_DEPLOYMENT_INSTALLATION_KEY_FILE"
)

// DeploymentEntitlementConfig names the mounted signed entitlement and the
// installation key (ADR-050 D1). Both files are read and verified at startup;
// paths and contents are never formatted.
type DeploymentEntitlementConfig struct {
	DeploymentID    deployment.ID
	entitlement     SecretFile
	installationKey SecretFile
}

// String redacts the assignment.
func (DeploymentEntitlementConfig) String() string { return redactedValue }

// GoString redacts detailed formatting.
func (DeploymentEntitlementConfig) GoString() string {
	return "config.DeploymentEntitlementConfig([REDACTED])"
}

// LogValue redacts structured logging.
func (DeploymentEntitlementConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// Load reads the single-line envelope and the 32-byte installation seed. The
// caller verifies the envelope and clears the seed after deriving the key.
func (entitlementConfig DeploymentEntitlementConfig) Load(ctx context.Context) ([]byte, [32]byte, error) {
	envelope, err := entitlementConfig.entitlement.Read()
	if err != nil {
		return nil, [32]byte{}, errors.Join(ErrInvalid, settingError(envEntitlementFile))
	}
	seed, err := entitlementConfig.installationKey.readPrivateIdentityKey(ctx)
	if err != nil {
		return nil, [32]byte{}, errors.Join(ErrInvalid, settingError(envEntitlementInstallationKey))
	}
	return []byte(envelope), seed, nil
}

// loadDeploymentEntitlementConfig is all-or-nothing. Entitlement authority is
// served with the Console capability surface, so only api and all accept it.
func loadDeploymentEntitlementConfig(lookup LookupFunc, role app.Role) (*DeploymentEntitlementConfig, error) {
	keys := []string{envEntitlementDeploymentID, envEntitlementFile, envEntitlementInstallationKey}
	present := 0
	for _, key := range keys {
		if _, ok := lookup(key); ok {
			present++
		}
	}
	if present == 0 {
		return nil, nil
	}
	if present != len(keys) {
		for _, key := range keys {
			if _, ok := lookup(key); !ok {
				return nil, settingError(key)
			}
		}
	}
	if role != app.RoleAPI && role != app.RoleAll {
		return nil, settingError(envEntitlementFile)
	}
	deploymentID, err := deployment.ParseID(valueOrDefault(lookup, envEntitlementDeploymentID, ""))
	if err != nil {
		return nil, settingError(envEntitlementDeploymentID)
	}
	entitlementFile, err := NewSecretFile(valueOrDefault(lookup, envEntitlementFile, ""))
	if err != nil {
		return nil, settingError(envEntitlementFile)
	}
	keyFile, err := NewSecretFile(valueOrDefault(lookup, envEntitlementInstallationKey, ""))
	if err != nil {
		return nil, settingError(envEntitlementInstallationKey)
	}
	return &DeploymentEntitlementConfig{
		DeploymentID: deploymentID, entitlement: entitlementFile, installationKey: keyFile,
	}, nil
}
