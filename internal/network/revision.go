// Package network owns Network identity and monotonic revision invariants.
package network

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/publicid"
)

// ErrInvalidRevision indicates an unusable Network revision fact.
var ErrInvalidRevision = errors.New("invalid network revision")

// RevisionAdvanced is an already-committed Network revision fact. It carries
// no topology or authorization state and is safe to use as a convergence hint.
type RevisionAdvanced struct {
	networkPublicID string
	number          int64
}

// NewRevisionAdvanced validates a canonical UUIDv7 Network ID and a positive
// authoritative revision number.
func NewRevisionAdvanced(networkPublicID string, number int64) (RevisionAdvanced, error) {
	if !validCanonicalUUIDv7(networkPublicID) || number <= 0 {
		return RevisionAdvanced{}, ErrInvalidRevision
	}
	return RevisionAdvanced{networkPublicID: networkPublicID, number: number}, nil
}

// NetworkPublicID returns the opaque public Network identifier.
func (revision RevisionAdvanced) NetworkPublicID() string { return revision.networkPublicID }

// Number returns the observed authoritative Network revision.
func (revision RevisionAdvanced) Number() int64 { return revision.number }

// IsValid reports whether the value satisfies its construction invariants.
func (revision RevisionAdvanced) IsValid() bool {
	return validCanonicalUUIDv7(revision.networkPublicID) && revision.number > 0
}

func validCanonicalUUIDv7(value string) bool {
	_, err := publicid.Parse(value)
	return err == nil
}
