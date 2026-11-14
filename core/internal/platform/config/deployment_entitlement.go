package config

import (
	"context"
	"errors"
	"log/slog"
	"regexp"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/platform/app"
)

const (
	envEntitlementDeploymentID    = "MESHTRANSIT_ENTITLEMENT_DEPLOYMENT_PUBLIC_ID"
	envEntitlementFile            = "MESHTRANSIT_DEPLOYMENT_ENTITLEMENT_FILE"
	envEntitlementInstallationKey = "MESHTRANSIT_DEPLOYMENT_INSTALLATION_KEY_FILE"
	envEntitlementRenewalKeyID    = "MESHTRANSIT_DEPLOYMENT_ENTITLEMENT_RENEWAL_KEY_ID"
	envEntitlementRenewalKey      = "MESHTRANSIT_DEPLOYMENT_ENTITLEMENT_RENEWAL_KEY_FILE"
)

// DeploymentEntitlementConfig names the mounted signed entitlement and the
// installation key (ADR-050 D1). Both files are read and verified at startup;
// paths and contents are never formatted.
//
// The optional self-renewal key (auto-renewal-design.md §3) lets the api role
// sign the next generation; it is only ever mounted into api.
type DeploymentEntitlementConfig struct {
	DeploymentID    deployment.ID
	entitlement     SecretFile
	installationKey SecretFile
	renewalKeyID    string
	renewalKey      *SecretFile
}

// RenewalKeyID names the self-renewal key, or is empty when none is mounted.
func (entitlementConfig DeploymentEntitlementConfig) RenewalKeyID() string {
	return entitlementConfig.renewalKeyID
}

// LoadRenewalKey reads the self-renewal key's 32-byte seed. The caller
// clears it after deriving the key.
func (entitlementConfig DeploymentEntitlementConfig) LoadRenewalKey(ctx context.Context) ([32]byte, error) {
	if entitlementConfig.renewalKey == nil {
		return [32]byte{}, settingError(envEntitlementRenewalKey)
	}
	seed, err := entitlementConfig.renewalKey.readPrivateIdentityKey(ctx)
	if err != nil {
		return [32]byte{}, errors.Join(ErrInvalid, settingError(envEntitlementRenewalKey))
	}
	return seed, nil
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
	_, renewalID := lookup(envEntitlementRenewalKeyID)
	_, renewalFile := lookup(envEntitlementRenewalKey)
	if present == 0 {
		if renewalID || renewalFile {
			return nil, settingError(envEntitlementFile)
		}
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
	result := &DeploymentEntitlementConfig{
		DeploymentID: deploymentID, entitlement: entitlementFile, installationKey: keyFile,
	}
	if renewalID != renewalFile {
		if !renewalID {
			return nil, settingError(envEntitlementRenewalKeyID)
		}
		return nil, settingError(envEntitlementRenewalKey)
	}
	if renewalID {
		result.renewalKeyID = valueOrDefault(lookup, envEntitlementRenewalKeyID, "")
		if !renewalKeyIDPattern.MatchString(result.renewalKeyID) {
			return nil, settingError(envEntitlementRenewalKeyID)
		}
		renewalKey, err := NewSecretFile(valueOrDefault(lookup, envEntitlementRenewalKey, ""))
		if err != nil {
			return nil, settingError(envEntitlementRenewalKey)
		}
		result.renewalKey = &renewalKey
	}
	return result, nil
}

// renewalKeyIDPattern is the entitlement key ID form.
var renewalKeyIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
