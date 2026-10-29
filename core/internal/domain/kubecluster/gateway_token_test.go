package kubecluster_test

import (
	"testing"

	"meshtransit.net/core/internal/domain/kubecluster"
)

func TestGatewayTokenModesAndResults(t *testing.T) {
	t.Parallel()
	for _, mode := range []kubecluster.GatewayTokenMode{
		kubecluster.GatewayTokenObserve, kubecluster.GatewayTokenRatchet, kubecluster.GatewayTokenRequired,
	} {
		if !mode.IsKnown() {
			t.Errorf("%q is not known", mode)
		}
	}
	for _, mode := range []kubecluster.GatewayTokenMode{"", "Ratchet", "enforce", "off"} {
		if mode.IsKnown() {
			t.Errorf("%q is known", mode)
		}
	}
	for _, result := range []kubecluster.GatewayTimestampResult{
		kubecluster.GatewayTimestampCommitted, kubecluster.GatewayTimestampNotCommitted,
		kubecluster.GatewayTimestampTokenRequired,
	} {
		if !result.IsKnown() {
			t.Errorf("%q is not known", result)
		}
	}
	for _, result := range []kubecluster.GatewayTimestampResult{"", "ratcheted", "COMMITTED"} {
		if result.IsKnown() {
			t.Errorf("%q is known", result)
		}
	}
}
