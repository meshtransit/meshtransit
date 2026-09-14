// Package intake authenticates enrollment credentials and prepares durable
// registration intents before the registration mutation is executed.
package intake

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/node"
)

// ErrInvalidRequest reports malformed untrusted registration input.
var ErrInvalidRequest = errors.New("registration intake: invalid request")

// Request contains untrusted registration semantics and one bearer proof. It
// deliberately contains no Workspace, Network, profile, or recovery authority.
type Request struct {
	RegistrationID enrollment.RegistrationID
	CredentialID   enrollment.CredentialID
	Token          enrollment.CredentialToken
	Identity       node.RegistrationIdentity
	Hostname       node.Hostname
}

// IsValid reports whether the request is structurally safe to authenticate.
func (request Request) IsValid() bool {
	return request.RegistrationID.IsValid() && request.CredentialID.IsValid() &&
		request.Token.IsValid() && request.Identity.IsValid() && request.Hostname.IsValid()
}

// Lookup is the non-secret key set required to lock credential and intent state.
type Lookup struct {
	RegistrationID     enrollment.RegistrationID
	CredentialID       enrollment.CredentialID
	MachineFingerprint [32]byte
}

// IsValid reports whether the lookup is bounded and complete.
func (lookup Lookup) IsValid() bool {
	return lookup.RegistrationID.IsValid() && lookup.CredentialID.IsValid() &&
		lookup.MachineFingerprint != ([32]byte{})
}
