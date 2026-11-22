package selfhost

import (
	"errors"
	"fmt"
)

// IdentityStatus compares the identity configuration with what was approved.
type IdentityStatus int

const (
	// IdentityUnapproved means nothing is approved yet (a new installation).
	IdentityUnapproved IdentityStatus = iota + 1
	// IdentityApproved means the configuration is the approved one.
	IdentityApproved
	// IdentityChanged means the configuration differs from the approved one. Core
	// keeps the approved pin and refuses to start the broker until the
	// operator approves the change.
	IdentityChanged
)

// CheckIdentity fingerprints the current identity settings and compares the
// result with the approved one.
func CheckIdentity(config Config, state State, layout Layout, fingerprint IdentityFingerprint) (IdentityStatus, error) {
	if fingerprint == nil {
		return 0, errors.New("self-host identity: no fingerprint function")
	}
	current, err := fingerprint(IdentitySettings(config, state, layout))
	if err != nil {
		return 0, fmt.Errorf("self-host identity: fingerprint: %w", err)
	}
	status := IdentityChanged
	switch {
	case state.IdentityFingerprint == "":
		status = IdentityUnapproved
	case current == state.IdentityFingerprint:
		status = IdentityApproved
	}
	if !state.providerMatches(config, status) {
		if state.Format == stateFormatV1 {
			return 0, ErrStateV1Changed
		}
		return 0, ErrProviderChanged
	}
	return status, nil
}

// ErrStateV1Changed reports an identity change on a state written before
// V1-22, which records no provider: it cannot tell a rotated secret from
// another provider.
var ErrStateV1Changed = errors.New("state.json predates the record of the sign-in provider: " +
	"run setup apply (or approve-identity) once with the configuration it approved, then make the change")

// UpgradeApprovedState records the provider in a v1 state whose approved
// fingerprint the configuration still matches (which proves the provider).
// It reports whether it wrote state.json.
func UpgradeApprovedState(config Config, layout Layout, fingerprint IdentityFingerprint, owner *Owner) (bool, error) {
	state, err := LoadState(layout.SecretsDir)
	if err != nil || state.Format != stateFormatV1 || state.IdentityFingerprint == "" {
		return false, err
	}
	status, err := CheckIdentity(config, state, layout, fingerprint)
	if err != nil {
		return false, err
	}
	if status != IdentityApproved || !state.publicNamesMatch(config) {
		return false, nil
	}
	state.Format, state.Provider = stateFormat, providerOf(config)
	return true, writeState(layout.SecretsDir, state, owner, true)
}

// ErrProviderChanged reports a sign-in provider (issuer, client or
// connector) other than the approved one. Accounts are keyed by the
// provider's subjects: another provider would orphan every Account, the
// owner's too. Changing it is a procedure (runbook), not a configuration
// edit.
var ErrProviderChanged = errors.New("the sign-in provider differs from the approved one: " +
	"changing it orphans every Account; follow the runbook to move to another provider")

// ApproveIdentity pins the current identity configuration in state.json.
// Approving a change also moves the connector and Core client generations
// on, so the broker and Core treat the new trust as new. It returns the
// state it wrote.
func ApproveIdentity(config Config, layout Layout, fingerprint IdentityFingerprint, owner *Owner) (State, error) {
	state, err := LoadState(layout.SecretsDir)
	if err != nil {
		return State{}, err
	}
	status, err := CheckIdentity(config, state, layout, fingerprint)
	if err != nil {
		return State{}, err
	}
	if !state.publicNamesMatch(config) {
		return State{}, ErrPublicNamesChanged
	}
	switch status {
	case IdentityApproved:
		if state.Format == stateFormat {
			return state, nil
		}
		// A v1 state: record the provider it approved, nothing else moves.
	case IdentityChanged:
		state.ConnectorGeneration++
		state.CoreClientGeneration++
	case IdentityUnapproved:
		state.ApprovedIssuer, state.ApprovedOrigin = issuer(config), consoleOrigin(config)
	}
	state.Format, state.Provider = stateFormat, providerOf(config)
	approved, err := fingerprint(IdentitySettings(config, state, layout))
	if err != nil {
		return State{}, fmt.Errorf("self-host identity: fingerprint: %w", err)
	}
	state.IdentityFingerprint = approved
	if err := writeState(layout.SecretsDir, state, owner, true); err != nil {
		return State{}, err
	}
	return state, nil
}
