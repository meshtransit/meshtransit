package kubecluster_test

import (
	"testing"

	"meshtransit.net/core/internal/domain/kubecluster"
)

func TestKeyEventReasons(t *testing.T) {
	t.Parallel()
	for reason, stale := range map[kubecluster.KeyEventReason]bool{
		kubecluster.KeyEventRetiredMachineKey: true,
		kubecluster.KeyEventStaleNodeKey:      true,
		kubecluster.KeyEventSessionFight:      false,
		kubecluster.KeyEventReplayedHandshake: false,
	} {
		if !reason.IsKnown() || reason.StaleKey() != stale {
			t.Errorf("%s: known %t, stale %t", reason, reason.IsKnown(), reason.StaleKey())
		}
	}
	for _, reason := range []kubecluster.KeyEventReason{"", "session_replaced", "RETIRED_MACHINE_KEY"} {
		if reason.IsKnown() {
			t.Errorf("%q is known", reason)
		}
	}
	var zero kubecluster.KeyEventOutcome
	if zero.IsKnown() || !kubecluster.KeyEventRecorded.IsKnown() || !kubecluster.KeyEventNotGateway.IsKnown() {
		t.Fatal("the zero outcome must be invalid")
	}
}
