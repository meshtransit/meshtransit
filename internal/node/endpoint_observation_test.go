package node

import (
	"errors"
	"testing"
	"time"
)

func TestEndpointObservationValidatesGenerationAndTTL(t *testing.T) {
	t.Parallel()

	set := endpointSetFixture(t)
	nodeID, err := ParseID("01890f00-0000-7000-8000-000000000701")
	if err != nil {
		t.Fatalf("ParseID() error = %v", err)
	}
	observation, err := NewEndpointObservation(nodeID, 7, set, 30*time.Second)
	if err != nil {
		t.Fatalf("NewEndpointObservation() error = %v", err)
	}
	if !observation.IsValid() || observation.NodeID() != nodeID || observation.Generation() != 7 ||
		observation.Set().DiscoveryKey() != set.DiscoveryKey() || observation.TTL() != 30*time.Second {
		t.Fatalf("EndpointObservation = %+v, want validated observation", observation)
	}

	for _, test := range []struct {
		name       string
		nodeID     ID
		generation int64
		set        EndpointSet
		ttl        time.Duration
	}{
		{name: "missing Node id", generation: 7, set: set, ttl: 30 * time.Second},
		{name: "zero generation", nodeID: nodeID, set: set, ttl: 30 * time.Second},
		{name: "missing endpoint set", nodeID: nodeID, generation: 7, ttl: 30 * time.Second},
		{name: "short ttl", nodeID: nodeID, generation: 7, set: set, ttl: time.Millisecond},
		{name: "excess ttl", nodeID: nodeID, generation: 7, set: set, ttl: maximumEndpointObservationTTL + time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewEndpointObservation(test.nodeID, test.generation, test.set, test.ttl); !errors.Is(
				err,
				ErrInvalidEndpointObservation,
			) {
				t.Fatalf("NewEndpointObservation() error = %v, want ErrInvalidEndpointObservation", err)
			}
		})
	}
}
