//go:build windows

package main

import (
	"errors"
	"fmt"

	"meshtransit.net/client/internal/identity"
	"meshtransit.net/client/internal/secretstore"
)

// loadIdentityProtector opens the DPAPI-sealed envelope key, and creates it
// on the service's first start. A missing key next to existing identity
// records is an error: only that key opens them.
func loadIdentityProtector(path, stateDir string) (*secretstore.Protector, error) {
	protector, err := secretstore.LoadDPAPI(path)
	if !errors.Is(err, secretstore.ErrKeyMissing) {
		return protector, err
	}
	hasRecords, recordsErr := identity.HasRecords(stateDir)
	if recordsErr != nil {
		return nil, recordsErr
	}
	if hasRecords {
		return nil, fmt.Errorf("%w: identity records exist without their key; restore the key file", err)
	}

	return secretstore.CreateDPAPI(path)
}
