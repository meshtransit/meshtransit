package config

import (
	"strconv"

	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

// The login route's identity outside the login profile (V1-11 S2h): a
// version 5 profile carries no IDs; Core takes them from these settings,
// which the chart reads from the install's record. All or none.
const (
	envLoginProviderID         = "MESHTRANSIT_LOGIN_PROVIDER_ID"
	envLoginClientID           = "MESHTRANSIT_LOGIN_CLIENT_ID"
	envLoginProviderGeneration = "MESHTRANSIT_LOGIN_PROVIDER_GENERATION"
	envLoginRecoveryEpoch      = "MESHTRANSIT_LOGIN_RECOVERY_EPOCH"
)

// LoginIdentityConfig is the login route's provider and client and their
// generations, from the environment.
type LoginIdentityConfig struct {
	ProviderID         oidcauth.ProviderID
	ClientID           oidcauth.ClientID
	ProviderGeneration int64
	RecoveryEpoch      int64
}

func loadLoginIdentity(lookup LookupFunc) (*LoginIdentityConfig, error) {
	keys := []string{envLoginProviderID, envLoginClientID, envLoginProviderGeneration, envLoginRecoveryEpoch}
	present := 0
	for _, key := range keys {
		if _, ok := lookup(key); ok {
			present++
		}
	}
	if present == 0 {
		return nil, nil
	}
	for _, key := range keys {
		if _, ok := lookup(key); !ok {
			return nil, settingError(key)
		}
	}
	provider, err := oidcauth.ParseProviderID(valueOrDefault(lookup, envLoginProviderID, ""))
	if err != nil {
		return nil, settingError(envLoginProviderID)
	}
	client, err := oidcauth.ParseClientID(valueOrDefault(lookup, envLoginClientID, ""))
	if err != nil {
		return nil, settingError(envLoginClientID)
	}
	generation, err := strconv.ParseInt(valueOrDefault(lookup, envLoginProviderGeneration, ""), 10, 64)
	if err != nil || generation < 1 {
		return nil, settingError(envLoginProviderGeneration)
	}
	epoch, err := strconv.ParseInt(valueOrDefault(lookup, envLoginRecoveryEpoch, ""), 10, 64)
	if err != nil || epoch < 1 {
		return nil, settingError(envLoginRecoveryEpoch)
	}
	return &LoginIdentityConfig{ProviderID: provider, ClientID: client, ProviderGeneration: generation,
		RecoveryEpoch: epoch}, nil
}
