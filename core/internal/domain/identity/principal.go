// Package identity owns stable human and service principal identity.
package identity

import (
	"errors"

	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

// ErrInvalidPrincipalID reports an absent or malformed principal public ID.
var ErrInvalidPrincipalID = errors.New("identity: invalid principal id")

// PrincipalID is a validated opaque UUIDv7 identifying a human or service principal.
type PrincipalID publicid.ID

// NewPrincipalID validates a principal ID from its binary representation.
func NewPrincipalID(value [16]byte) (PrincipalID, error) {
	id, err := publicid.FromBytes(value)
	if err != nil {
		return PrincipalID{}, ErrInvalidPrincipalID
	}
	return PrincipalID(id), nil
}

// ParsePrincipalID validates a principal ID from its canonical string.
func ParsePrincipalID(value string) (PrincipalID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return PrincipalID{}, ErrInvalidPrincipalID
	}
	return PrincipalID(id), nil
}

// String returns the lowercase canonical UUID representation.
func (id PrincipalID) String() string { return publicid.ID(id).String() }

// Bytes returns a copy of the binary UUID representation.
func (id PrincipalID) Bytes() [16]byte { return publicid.ID(id).Bytes() }

// IsValid reports whether the principal ID satisfies the identity contract.
func (id PrincipalID) IsValid() bool { return publicid.ID(id).IsValid() }
