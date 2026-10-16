package config

import (
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
)

const (
	envEnrollmentDigestActiveKeyID     = "MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_ID"
	envEnrollmentDigestActiveKeyFile   = "MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_FILE"
	envEnrollmentDigestPreviousKeyID   = "MESHTRANSIT_ENROLLMENT_DIGEST_PREVIOUS_KEY_ID"
	envEnrollmentDigestPreviousKeyFile = "MESHTRANSIT_ENROLLMENT_DIGEST_PREVIOUS_KEY_FILE"
)

// EnrollmentConfig contains control-plane credential verification settings.
type EnrollmentConfig struct {
	CredentialDigest CredentialDigestConfig
	Registration     RegistrationConfig
}

// CredentialDigestConfig defines an active key and an optional previous key
// for a bounded credential-verification rotation window.
type CredentialDigestConfig struct {
	Active   CredentialDigestKeyConfig
	Previous *CredentialDigestKeyConfig
}

// CredentialDigestKeyConfig contains a public key version and an opaque secret
// file reference. The key material is read only by the composition boundary.
type CredentialDigestKeyConfig struct {
	ID           enrollment.DigestKeyID
	MaterialFile SecretFile
}

func loadEnrollmentConfig(lookup LookupFunc, shutdownTimeout time.Duration) (EnrollmentConfig, error) {
	digest, err := loadCredentialDigestConfig(lookup)
	if err != nil {
		return EnrollmentConfig{}, err
	}
	registration, err := loadRegistrationConfig(lookup, shutdownTimeout)
	if err != nil {
		return EnrollmentConfig{}, err
	}

	return EnrollmentConfig{CredentialDigest: digest, Registration: registration}, nil
}

// loadCredentialDigestConfig reads the enrollment credential digest keys:
// the active one and an optional previous one.
func loadCredentialDigestConfig(lookup LookupFunc) (CredentialDigestConfig, error) {
	active, err := loadCredentialDigestKeyConfig(
		lookup,
		envEnrollmentDigestActiveKeyID,
		envEnrollmentDigestActiveKeyFile,
	)
	if err != nil {
		return CredentialDigestConfig{}, err
	}
	previous, err := loadPreviousCredentialDigestKeyConfig(lookup)
	if err != nil {
		return CredentialDigestConfig{}, err
	}
	if previous != nil {
		if previous.ID == active.ID {
			return CredentialDigestConfig{}, settingError(envEnrollmentDigestPreviousKeyID)
		}
		if previous.MaterialFile.path == active.MaterialFile.path {
			return CredentialDigestConfig{}, settingError(envEnrollmentDigestPreviousKeyFile)
		}
	}
	return CredentialDigestConfig{Active: active, Previous: previous}, nil
}

// loadEnrollmentKeyDigestConfig reads the digest keys an api role uses to
// issue enrollment keys, when the deployment gives it them; nil otherwise,
// and key issue then reports itself unavailable.
func loadEnrollmentKeyDigestConfig(lookup LookupFunc) (*CredentialDigestConfig, error) {
	_, hasID := lookup(envEnrollmentDigestActiveKeyID)
	_, hasFile := lookup(envEnrollmentDigestActiveKeyFile)
	if !hasID && !hasFile {
		return nil, nil
	}
	digest, err := loadCredentialDigestConfig(lookup)
	if err != nil {
		return nil, err
	}
	return &digest, nil
}

func loadPreviousCredentialDigestKeyConfig(lookup LookupFunc) (*CredentialDigestKeyConfig, error) {
	_, hasID := lookup(envEnrollmentDigestPreviousKeyID)
	_, hasFile := lookup(envEnrollmentDigestPreviousKeyFile)
	if !hasID && !hasFile {
		return nil, nil
	}
	if !hasID {
		return nil, settingError(envEnrollmentDigestPreviousKeyID)
	}
	if !hasFile {
		return nil, settingError(envEnrollmentDigestPreviousKeyFile)
	}

	key, err := loadCredentialDigestKeyConfig(
		lookup,
		envEnrollmentDigestPreviousKeyID,
		envEnrollmentDigestPreviousKeyFile,
	)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func loadCredentialDigestKeyConfig(
	lookup LookupFunc,
	idSetting string,
	fileSetting string,
) (CredentialDigestKeyConfig, error) {
	idValue, err := requiredValue(lookup, idSetting, validateCredentialDigestKeyID)
	if err != nil {
		return CredentialDigestKeyConfig{}, err
	}
	id, err := enrollment.NewDigestKeyID(idValue)
	if err != nil {
		return CredentialDigestKeyConfig{}, settingError(idSetting)
	}
	filePath, err := requiredFile(lookup, fileSetting)
	if err != nil {
		return CredentialDigestKeyConfig{}, err
	}
	return CredentialDigestKeyConfig{
		ID:           id,
		MaterialFile: SecretFile{path: filePath},
	}, nil
}

func validateCredentialDigestKeyID(value string) error {
	_, err := enrollment.NewDigestKeyID(value)
	return err
}
