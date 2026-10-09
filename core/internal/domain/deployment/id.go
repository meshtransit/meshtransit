// Package deployment owns installation identity and recovery authority.
package deployment

import (
	"errors"

	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

// ErrInvalidID reports an absent or malformed Deployment public ID.
var ErrInvalidID = errors.New("deployment: invalid id")

// ID is a validated opaque UUIDv7 identifying one MeshTransit installation.
type ID publicid.ID

// NewID validates and returns a Deployment ID from its binary representation.
func NewID(value [16]byte) (ID, error) {
	id, err := publicid.FromBytes(value)
	if err != nil {
		return ID{}, ErrInvalidID
	}
	return ID(id), nil
}

// ParseID validates and returns a Deployment ID from its canonical string.
func ParseID(value string) (ID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ID{}, ErrInvalidID
	}
	return ID(id), nil
}

// Bytes returns a copy of the binary UUID representation.
func (id ID) Bytes() [16]byte { return publicid.ID(id).Bytes() }

// String returns the lowercase canonical UUID representation.
func (id ID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the ID satisfies the Deployment identity contract.
func (id ID) IsValid() bool { return publicid.ID(id).IsValid() }
