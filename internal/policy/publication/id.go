// Package publication owns the atomic activation use case for compiled packet policy.
package publication

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/publicid"
)

var (
	// ErrInvalidReleaseID reports an absent or malformed Policy Release identity.
	ErrInvalidReleaseID = errors.New("policy publication: invalid release id")
	// ErrInvalidProjectionID reports an absent or malformed compiled-rule identity.
	ErrInvalidProjectionID = errors.New("policy publication: invalid projection id")
)

// ReleaseID is a validated UUIDv7 identifying one immutable Policy Release.
type ReleaseID publicid.ID

// ParseReleaseID validates a canonical Policy Release identity.
func ParseReleaseID(value string) (ReleaseID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ReleaseID{}, ErrInvalidReleaseID
	}
	return ReleaseID(id), nil
}

// String returns the canonical lower-case UUID representation.
func (id ReleaseID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the ID satisfies the UUIDv7 contract.
func (id ReleaseID) IsValid() bool { return publicid.ID(id).IsValid() }

// ProjectionID is a validated UUIDv7 identifying one immutable compiled rule row.
type ProjectionID publicid.ID

// ParseProjectionID validates a canonical compiled-rule projection identity.
func ParseProjectionID(value string) (ProjectionID, error) {
	id, err := publicid.Parse(value)
	if err != nil {
		return ProjectionID{}, ErrInvalidProjectionID
	}
	return ProjectionID(id), nil
}

// String returns the canonical lower-case UUID representation.
func (id ProjectionID) String() string { return publicid.ID(id).String() }

// IsValid reports whether the ID satisfies the UUIDv7 contract.
func (id ProjectionID) IsValid() bool { return publicid.ID(id).IsValid() }
