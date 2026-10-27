package kubecluster_test

import (
	"testing"

	"meshtransit.net/core/internal/domain/kubecluster"
)

func TestKeyEventReasons(t *testing.T) {
	t.Parallel()
	const (
		stale     = "kubernetes_gateway.stale_key_presented"
		contested = "kubernetes_gateway.keys_contested"
		refused   = "kubernetes_gateway.rotation_token_refused"
	)
	for reason, action := range map[kubecluster.KeyEventReason]string{
		kubecluster.KeyEventRetiredMachineKey: stale,
		kubecluster.KeyEventStaleNodeKey:      stale,
		kubecluster.KeyEventSessionFight:      contested,
		kubecluster.KeyEventReplayedHandshake: contested,
		kubecluster.KeyEventTokenMissing:      refused,
		kubecluster.KeyEventTokenMalformed:    refused,
		kubecluster.KeyEventTokenUnknownKey:   refused,
		kubecluster.KeyEventTokenSignature:    refused,
		kubecluster.KeyEventTokenExpired:      refused,
		kubecluster.KeyEventTokenAudience:     refused,
		kubecluster.KeyEventTokenIdentity:     refused,
		kubecluster.KeyEventTrustMissing:      refused,
		kubecluster.KeyEventTrustUnavailable:  refused,
	} {
		if !reason.IsKnown() || reason.StaleKey() != (action == stale) || reason.Action() != action ||
			reason.TokenRefused() != (action == refused) {
			t.Errorf("%s: known %t, stale %t, action %q", reason, reason.IsKnown(), reason.StaleKey(), reason.Action())
		}
	}
	for _, reason := range []kubecluster.KeyEventReason{"", "session_replaced", "RETIRED_MACHINE_KEY", "replayed", "token_"} {
		if reason.IsKnown() {
			t.Errorf("%q is known", reason)
		}
	}
	var zero kubecluster.KeyEventOutcome
	if zero.IsKnown() || !kubecluster.KeyEventRecorded.IsKnown() || !kubecluster.KeyEventNotGateway.IsKnown() {
		t.Fatal("the zero outcome must be invalid")
	}
}
