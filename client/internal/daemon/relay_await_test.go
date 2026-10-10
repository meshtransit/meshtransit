package daemon

import (
	"sync/atomic"
	"testing"
	"time"

	"meshtransit.net/client/internal/relay"
)

// connectingRelays reports region 2 connected from the given call on.
type connectingRelays struct {
	calls       atomic.Int32
	connectedAt int32
}

func (c *connectingRelays) RelayHealth() relay.HealthSnapshot {
	call := c.calls.Add(1)
	health := relay.HealthSnapshot{Available: true, HomeRegion: 1}
	if c.connectedAt > 0 && call >= c.connectedAt {
		health.Regions = []relay.RegionHealth{{RegionID: 2, Connected: true, LastActivity: time.Now()}}
	}
	return health
}

func (c *connectingRelays) PrepareRelayRegion(int) error { return nil }

func TestAwaitRelayRegion(t *testing.T) {
	t.Parallel()
	s := &Service{}

	ready := &connectingRelays{connectedAt: 3}
	start := time.Now()
	if health, connected := s.awaitRelayRegion(t.Context(), ready, 2); !connected || len(health.Regions) != 1 {
		t.Fatalf("awaitRelayRegion() = %+v, %v", health, connected)
	}
	if elapsed := time.Since(start); elapsed > relayPreparationWait/2 {
		t.Fatalf("a connecting region took %v", elapsed)
	}

	never := &connectingRelays{}
	start = time.Now()
	if _, connected := s.awaitRelayRegion(t.Context(), never, 2); connected {
		t.Fatal("a region that never connected was reported connected")
	}
	if elapsed := time.Since(start); elapsed < relayPreparationWait || elapsed > relayPreparationWait+time.Second {
		t.Fatalf("waiting for an unreachable region took %v", elapsed)
	}
}
