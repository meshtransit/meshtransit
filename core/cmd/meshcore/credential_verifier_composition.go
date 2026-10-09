package main

import (
	"encoding/base64"
	"errors"

	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

var errInvalidCredentialVerifierComposition = errors.New("invalid credential verifier composition")

func composeCredentialVerifier(
	digestConfig config.CredentialDigestConfig,
) (*enrollment.CredentialKeyring, error) {
	active, err := loadCredentialDigestKey(digestConfig.Active)
	if err != nil {
		return nil, errors.Join(errInvalidCredentialVerifierComposition, errors.New("active key rejected"))
	}
	if digestConfig.Previous == nil {
		keyring, err := enrollment.NewCredentialKeyring(active)
		if err != nil {
			return nil, errInvalidCredentialVerifierComposition
		}
		return keyring, nil
	}

	previous, err := loadCredentialDigestKey(*digestConfig.Previous)
	if err != nil {
		return nil, errors.Join(errInvalidCredentialVerifierComposition, errors.New("previous key rejected"))
	}
	keyring, err := enrollment.NewCredentialKeyring(active, previous)
	if err != nil {
		return nil, errInvalidCredentialVerifierComposition
	}
	return keyring, nil
}

func loadCredentialDigestKey(keyConfig config.CredentialDigestKeyConfig) (enrollment.DigestKey, error) {
	encoded, err := keyConfig.MaterialFile.Read()
	if err != nil {
		return enrollment.DigestKey{}, errInvalidCredentialVerifierComposition
	}
	material, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	defer clear(material)
	if err != nil || base64.RawURLEncoding.EncodeToString(material) != encoded {
		return enrollment.DigestKey{}, errInvalidCredentialVerifierComposition
	}
	key, err := enrollment.NewDigestKey(keyConfig.ID, material)
	if err != nil {
		return enrollment.DigestKey{}, errInvalidCredentialVerifierComposition
	}
	return key, nil
}
