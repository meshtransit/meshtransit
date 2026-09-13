// Package enrollment owns credential, profile, and registration state machines.
package enrollment

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/publicid"
)

// ErrInvalidID reports an absent or malformed enrollment public ID.
var ErrInvalidID = errors.New("enrollment: invalid id")

// ProfileID identifies one immutable enrollment authority profile.
type ProfileID publicid.ID

// CredentialID identifies one enrollment credential lifecycle.
type CredentialID publicid.ID

// RegistrationID identifies one idempotent registration intent.
type RegistrationID publicid.ID

// ParseProfileID validates and returns an Enrollment Profile ID.
func ParseProfileID(value string) (ProfileID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ProfileID{}, ErrInvalidID
	}
	return ProfileID(id), nil
}

// ParseCredentialID validates and returns an Enrollment Credential ID.
func ParseCredentialID(value string) (CredentialID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return CredentialID{}, ErrInvalidID
	}
	return CredentialID(id), nil
}

// ParseRegistrationID validates and returns a Registration ID.
func ParseRegistrationID(value string) (RegistrationID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return RegistrationID{}, ErrInvalidID
	}
	return RegistrationID(id), nil
}

// String returns the canonical Profile ID.
func (id ProfileID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the Profile ID is valid.
func (id ProfileID) IsValid() bool { return publicid.ID(id).IsValid() }

// String returns the canonical Credential ID.
func (id CredentialID) String() string { return publicid.ID(id).String() }

// Bytes returns a copy of the binary UUID representation.
func (id CredentialID) Bytes() [16]byte { return publicid.ID(id).Bytes() }

// IsValid reports whether the Credential ID is valid.
func (id CredentialID) IsValid() bool { return publicid.ID(id).IsValid() }

// String returns the canonical Registration ID.
func (id RegistrationID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the Registration ID is valid.
func (id RegistrationID) IsValid() bool { return publicid.ID(id).IsValid() }
