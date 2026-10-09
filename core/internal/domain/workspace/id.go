// Package workspace owns Workspace identity and governance invariants.
package workspace

import (
	"errors"

	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

// ErrInvalidID reports an absent or malformed Workspace public ID.
var ErrInvalidID = errors.New("workspace: invalid id")

// ID is a validated opaque UUIDv7 identifying one Workspace.
type ID publicid.ID

// NewID validates and returns a Workspace ID from its binary representation.
func NewID(value [16]byte) (ID, error) {
	id, err := publicid.FromBytes(value)
	if err != nil {
		return ID{}, ErrInvalidID
	}
	return ID(id), nil
}

// ParseID validates and returns a Workspace ID from its canonical string.
func ParseID(value string) (ID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ID{}, ErrInvalidID
	}
	return ID(id), nil
}

// String returns the lowercase canonical UUID representation.
func (id ID) String() string { return publicid.ID(id).String() }

// Bytes returns a copy of the binary UUID representation.
func (id ID) Bytes() [16]byte { return publicid.ID(id).Bytes() }

// IsValid reports whether the ID satisfies the Workspace identity contract.
func (id ID) IsValid() bool { return publicid.ID(id).IsValid() }
