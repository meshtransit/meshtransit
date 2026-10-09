package enrollment

import (
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
)

var (
	// ErrInvalidRegistration reports malformed durable registration state.
	ErrInvalidRegistration = errors.New("enrollment: invalid registration")
	// ErrRegistrationTransition reports a transition that is not valid from the current state.
	ErrRegistrationTransition = errors.New("enrollment: invalid registration transition")
	// ErrRegistrationExpired reports a transition attempted after the registration deadline.
	ErrRegistrationExpired = errors.New("enrollment: registration expired")
)

// RegistrationState identifies a pending registration lifecycle state.
type RegistrationState uint8

const (
	// RegistrationStateUnknown is the invalid zero-value state.
	RegistrationStateUnknown RegistrationState = iota
	// RegistrationStatePending awaits credential or interactive authorization.
	RegistrationStatePending
	// RegistrationStateAuthorized has authority to create or resume one Node.
	RegistrationStateAuthorized
	// RegistrationStateCompleted records the single resulting Node.
	RegistrationStateCompleted
	// RegistrationStateRejected is a terminal explicit denial.
	RegistrationStateRejected
	// RegistrationStateExpired is a terminal timeout.
	RegistrationStateExpired
)

// RegistrationParams contains the complete durable pending-registration state.
type RegistrationParams struct {
	ID                 RegistrationID
	Scope              network.Scope
	ProfileID          ProfileID
	MachineFingerprint [32]byte
	State              RegistrationState
	NodeID             node.ID
	CreatedAt          time.Time
	ExpiresAt          time.Time
}

// Registration is an immutable explicit registration state machine.
type Registration struct {
	id                 RegistrationID
	scope              network.Scope
	profileID          ProfileID
	machineFingerprint [32]byte
	state              RegistrationState
	nodeID             node.ID
	createdAt          time.Time
	expiresAt          time.Time
}

// NewRegistration validates and rehydrates durable registration state.
func NewRegistration(params RegistrationParams) (Registration, error) {
	if !params.ID.IsValid() || !params.Scope.IsValid() || !params.ProfileID.IsValid() ||
		params.MachineFingerprint == ([32]byte{}) || params.CreatedAt.IsZero() ||
		!params.ExpiresAt.After(params.CreatedAt) {
		return Registration{}, ErrInvalidRegistration
	}
	if (params.State == RegistrationStateCompleted) != params.NodeID.IsValid() {
		return Registration{}, ErrInvalidRegistration
	}
	switch params.State {
	case RegistrationStatePending, RegistrationStateAuthorized,
		RegistrationStateCompleted, RegistrationStateRejected, RegistrationStateExpired:
	default:
		return Registration{}, ErrInvalidRegistration
	}
	return Registration{
		id:                 params.ID,
		scope:              params.Scope,
		profileID:          params.ProfileID,
		machineFingerprint: params.MachineFingerprint,
		state:              params.State,
		nodeID:             params.NodeID,
		createdAt:          params.CreatedAt.UTC(),
		expiresAt:          params.ExpiresAt.UTC(),
	}, nil
}

// ID returns the registration intent identity.
func (registration Registration) ID() RegistrationID { return registration.id }

// Scope returns the exact server-derived registration scope.
func (registration Registration) Scope() network.Scope { return registration.scope }

// ProfileID returns the enrollment profile being applied.
func (registration Registration) ProfileID() ProfileID { return registration.profileID }

// MachineFingerprint returns the authenticated machine identity digest.
func (registration Registration) MachineFingerprint() [32]byte {
	return registration.machineFingerprint
}

// State returns the registration lifecycle state.
func (registration Registration) State() RegistrationState { return registration.state }

// NodeID returns the completed Node result and whether one exists.
func (registration Registration) NodeID() (node.ID, bool) {
	return registration.nodeID, registration.state == RegistrationStateCompleted
}

// CreatedAt returns the registration creation time.
func (registration Registration) CreatedAt() time.Time { return registration.createdAt }

// ExpiresAt returns the exclusive registration deadline.
func (registration Registration) ExpiresAt() time.Time { return registration.expiresAt }

// IsValid reports whether the registration represents valid durable state.
func (registration Registration) IsValid() bool {
	if !registration.id.IsValid() || !registration.scope.IsValid() ||
		!registration.profileID.IsValid() ||
		registration.machineFingerprint == ([32]byte{}) || registration.createdAt.IsZero() ||
		!registration.expiresAt.After(registration.createdAt) ||
		(registration.state == RegistrationStateCompleted) != registration.nodeID.IsValid() {
		return false
	}
	switch registration.state {
	case RegistrationStatePending, RegistrationStateAuthorized,
		RegistrationStateCompleted, RegistrationStateRejected, RegistrationStateExpired:
		return true
	default:
		return false
	}
}

// Authorize transitions pending registration to authorized state.
func (registration Registration) Authorize(now time.Time) (Registration, error) {
	if !registration.IsValid() || now.IsZero() {
		return Registration{}, ErrInvalidRegistration
	}
	if registration.state == RegistrationStateAuthorized {
		return registration, nil
	}
	if registration.state != RegistrationStatePending {
		return Registration{}, ErrRegistrationTransition
	}
	if !now.Before(registration.expiresAt) {
		return Registration{}, ErrRegistrationExpired
	}
	authorized := registration
	authorized.state = RegistrationStateAuthorized
	return authorized, nil
}

// Complete binds the single Node result to an authorized registration.
func (registration Registration) Complete(nodeID node.ID, now time.Time) (Registration, error) {
	if !registration.IsValid() || now.IsZero() {
		return Registration{}, ErrInvalidRegistration
	}
	if !nodeID.IsValid() {
		return Registration{}, ErrRegistrationTransition
	}
	if registration.state == RegistrationStateCompleted {
		if registration.nodeID == nodeID {
			return registration, nil
		}
		return Registration{}, ErrRegistrationTransition
	}
	if registration.state != RegistrationStateAuthorized {
		return Registration{}, ErrRegistrationTransition
	}
	if !now.Before(registration.expiresAt) {
		return Registration{}, ErrRegistrationExpired
	}
	completed := registration
	completed.state = RegistrationStateCompleted
	completed.nodeID = nodeID
	return completed, nil
}

// Reject transitions pending or authorized registration to a terminal denial.
func (registration Registration) Reject(now time.Time) (Registration, error) {
	if !registration.IsValid() || now.IsZero() {
		return Registration{}, ErrInvalidRegistration
	}
	if registration.state == RegistrationStateRejected {
		return registration, nil
	}
	if registration.state != RegistrationStatePending &&
		registration.state != RegistrationStateAuthorized {
		return Registration{}, ErrRegistrationTransition
	}
	if !now.Before(registration.expiresAt) {
		return Registration{}, ErrRegistrationExpired
	}
	rejected := registration
	rejected.state = RegistrationStateRejected
	return rejected, nil
}

// Expire transitions an overdue pending or authorized registration to terminal state.
func (registration Registration) Expire(now time.Time) (Registration, error) {
	if !registration.IsValid() || now.IsZero() {
		return Registration{}, ErrInvalidRegistration
	}
	if registration.state == RegistrationStateExpired {
		return registration, nil
	}
	if registration.state != RegistrationStatePending &&
		registration.state != RegistrationStateAuthorized {
		return Registration{}, ErrRegistrationTransition
	}
	if now.Before(registration.expiresAt) {
		return Registration{}, ErrRegistrationTransition
	}
	expired := registration
	expired.state = RegistrationStateExpired
	return expired, nil
}
