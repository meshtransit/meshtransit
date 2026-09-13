// Package network owns Network identity and monotonic revision invariants.
package network

import (
	"errors"
)

// ErrInvalidRevision indicates an unusable Network revision fact.
var ErrInvalidRevision = errors.New("invalid network revision")

// RevisionAdvanced is an already-committed Network revision fact. It carries
// no topology or authorization state and is safe to use as a convergence hint.
type RevisionAdvanced struct {
	networkID ID
	number    int64
}

// NewRevisionAdvanced validates a canonical UUIDv7 Network ID and a positive
// authoritative revision number.
func NewRevisionAdvanced(networkPublicID string, number int64) (RevisionAdvanced, error) {
	networkID, err := ParseID(networkPublicID)
	if err != nil || number <= 0 {
		return RevisionAdvanced{}, ErrInvalidRevision
	}
	return RevisionAdvanced{networkID: networkID, number: number}, nil
}

// NetworkPublicID returns the opaque public Network identifier.
func (revision RevisionAdvanced) NetworkPublicID() string { return revision.networkID.String() }

// Number returns the observed authoritative Network revision.
func (revision RevisionAdvanced) Number() int64 { return revision.number }

// IsValid reports whether the value satisfies its construction invariants.
func (revision RevisionAdvanced) IsValid() bool {
	return revision.networkID.IsValid() && revision.number > 0
}
