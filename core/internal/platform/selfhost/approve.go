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
	switch {
	case state.IdentityFingerprint == "":
		return IdentityUnapproved, nil
	case current == state.IdentityFingerprint:
		return IdentityApproved, nil
	default:
		return IdentityChanged, nil
	}
}

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
		return state, nil
	case IdentityChanged:
		state.ConnectorGeneration++
		state.CoreClientGeneration++
	case IdentityUnapproved:
		state.ApprovedIssuer, state.ApprovedOrigin = issuer(config), consoleOrigin(config)
	}
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
