package network

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/publicid"
)

// ErrInvalidID reports an absent or malformed Network public ID.
var ErrInvalidID = errors.New("network: invalid id")

// ID is a validated opaque UUIDv7 identifying one Network.
type ID publicid.ID

// NewID validates and returns a Network ID from its binary representation.
func NewID(value [16]byte) (ID, error) {
	id, err := publicid.FromBytes(value)
	if err != nil {
		return ID{}, ErrInvalidID
	}
	return ID(id), nil
}

// ParseID validates and returns a Network ID from its canonical string.
func ParseID(value string) (ID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ID{}, ErrInvalidID
	}
	return ID(id), nil
}

// String returns the lowercase canonical UUID representation.
func (id ID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the ID satisfies the Network identity contract.
func (id ID) IsValid() bool { return publicid.ID(id).IsValid() }
