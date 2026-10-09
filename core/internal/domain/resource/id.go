// Package resource owns stable resource identity, destination grouping, and
// target-generation invariants independently of management or wire protocols.
package resource

import (
	"errors"

	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

var (
	// ErrInvalidID reports an absent or malformed Resource public ID.
	ErrInvalidID = errors.New("resource: invalid id")
	// ErrInvalidGroupID reports an absent or malformed Resource Group public ID.
	ErrInvalidGroupID = errors.New("resource: invalid group id")
)

// ID is a validated opaque UUIDv7 identifying one Resource.
type ID publicid.ID

// NewID validates a Resource ID from its binary representation.
func NewID(value [16]byte) (ID, error) {
	id, err := publicid.FromBytes(value)
	if err != nil {
		return ID{}, ErrInvalidID
	}
	return ID(id), nil
}

// ParseID validates a Resource ID from its canonical string.
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

// IsValid reports whether the ID satisfies the Resource identity contract.
func (id ID) IsValid() bool { return publicid.ID(id).IsValid() }

// GroupID is a validated opaque UUIDv7 identifying one Resource Group.
type GroupID publicid.ID

// NewGroupID validates a Resource Group ID from its binary representation.
func NewGroupID(value [16]byte) (GroupID, error) {
	id, err := publicid.FromBytes(value)
	if err != nil {
		return GroupID{}, ErrInvalidGroupID
	}
	return GroupID(id), nil
}

// ParseGroupID validates a Resource Group ID from its canonical string.
func ParseGroupID(value string) (GroupID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return GroupID{}, ErrInvalidGroupID
	}
	return GroupID(id), nil
}

// String returns the lowercase canonical UUID representation.
func (id GroupID) String() string { return publicid.ID(id).String() }

// Bytes returns a copy of the binary UUID representation.
func (id GroupID) Bytes() [16]byte { return publicid.ID(id).Bytes() }

// IsValid reports whether the ID satisfies the Resource Group identity contract.
func (id GroupID) IsValid() bool { return publicid.ID(id).IsValid() }
