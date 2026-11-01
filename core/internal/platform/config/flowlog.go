package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"regexp"

	"meshtransit.net/core/internal/platform/app"
)

const (
	envFlowLogCredentialKey   = "MESHTRANSIT_FLOWLOG_CREDENTIAL_KEY"
	envFlowLogCredentialKeyID = "MESHTRANSIT_FLOWLOG_CREDENTIAL_KEY_ID"
)

var flowLogKeyID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

// FlowLogConfig is the connection log receiver's side Core needs
// (connection logs design §16b). CredentialKey is the receiver's public
// X25519 key storage secrets are sealed to; Core never holds its private
// half.
type FlowLogConfig struct {
	CredentialKey   *ecdh.PublicKey
	CredentialKeyID string
}

// loadFlowLogConfig is all-or-nothing and only for roles that serve the
// management API.
func loadFlowLogConfig(lookup LookupFunc, role app.Role) (*FlowLogConfig, error) {
	keyText, hasKey := lookup(envFlowLogCredentialKey)
	keyID, hasID := lookup(envFlowLogCredentialKeyID)
	if !hasKey && !hasID {
		return nil, nil
	}
	if !hasKey {
		return nil, settingError(envFlowLogCredentialKey)
	}
	if !hasID || !flowLogKeyID.MatchString(keyID) {
		return nil, settingError(envFlowLogCredentialKeyID)
	}
	if role != app.RoleAPI && role != app.RoleAll {
		return nil, settingError(envFlowLogCredentialKey)
	}
	raw, err := hex.DecodeString(keyText)
	if err != nil || len(raw) != 32 {
		return nil, settingError(envFlowLogCredentialKey)
	}
	key, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, settingError(envFlowLogCredentialKey)
	}
	// A low-order point would make every sealed secret readable: X25519
	// with it yields all zeros, which crypto/ecdh refuses.
	probe, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, settingError(envFlowLogCredentialKey)
	}
	if _, err := probe.ECDH(key); err != nil {
		return nil, settingError(envFlowLogCredentialKey)
	}
	return &FlowLogConfig{CredentialKey: key, CredentialKeyID: keyID}, nil
}
