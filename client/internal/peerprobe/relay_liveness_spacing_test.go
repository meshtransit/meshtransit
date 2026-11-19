package peerprobe

import (
	"testing"
	"time"
)

// TD-CLI-55: a peer answers liveness PINGs sent a second apart even when
// the second arrives up to 250 ms early, and still answers at most a few a
// second.
func TestRelayPingAnswerSpacingAllowsJitter(t *testing.T) {
	t.Parallel()
	if margin := relayLivenessSpacing - relayPingAnswerSpacing; margin < 250*time.Millisecond {
		t.Fatalf("answer spacing leaves %s for jitter, want at least 250ms", margin)
	}
	if relayPingAnswerSpacing < 500*time.Millisecond {
		t.Fatalf("answer spacing %s lets a peer draw more than two PONGs a second", relayPingAnswerSpacing)
	}
	if relayMeasurementWait <= relayPingAnswerSpacing {
		t.Fatalf("a measurement waits %s, not past the peer's %s pacing", relayMeasurementWait, relayPingAnswerSpacing)
	}
}
