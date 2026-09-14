package node

import (
	"errors"
	"time"
)

const (
	minimumEndpointObservationTTL = time.Second
	maximumEndpointObservationTTL = 5 * time.Minute
)

// ErrInvalidEndpointObservation reports an unsafe transient connectivity record.
var ErrInvalidEndpointObservation = errors.New("node: invalid endpoint observation")

// EndpointObservation binds a transient endpoint set to one Node generation.
// It carries no membership, ownership, or policy authority.
type EndpointObservation struct {
	nodeID     ID
	generation int64
	set        EndpointSet
	ttl        time.Duration
}

// NewEndpointObservation validates a generation-fenced transient observation.
func NewEndpointObservation(
	nodeID ID,
	generation int64,
	set EndpointSet,
	ttl time.Duration,
) (EndpointObservation, error) {
	observation := EndpointObservation{
		nodeID:     nodeID,
		generation: generation,
		set:        set,
		ttl:        ttl,
	}
	if !observation.IsValid() {
		return EndpointObservation{}, ErrInvalidEndpointObservation
	}
	return observation, nil
}

// NodeID returns the logical Node whose connectivity was observed.
func (observation EndpointObservation) NodeID() ID { return observation.nodeID }

// Generation returns the authoritative session-generation fence.
func (observation EndpointObservation) Generation() int64 { return observation.generation }

// Set returns the immutable connectivity report.
func (observation EndpointObservation) Set() EndpointSet { return observation.set }

// TTL returns the bounded lifetime of this non-authoritative record.
func (observation EndpointObservation) TTL() time.Duration { return observation.ttl }

// IsValid reports whether the observation is safe for ephemeral storage.
func (observation EndpointObservation) IsValid() bool {
	return observation.nodeID.IsValid() && observation.generation > 0 &&
		observation.set.IsValid() && observation.ttl >= minimumEndpointObservationTTL &&
		observation.ttl <= maximumEndpointObservationTTL
}
