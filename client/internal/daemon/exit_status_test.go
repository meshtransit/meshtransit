package daemon

import (
	"testing"

	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/dnsconfig"
)

type exitStatusDataPlane struct {
	fakeDataPlane
	status dataplane.ExitNodeStatus
}

func (plane *exitStatusDataPlane) ExitNode() dataplane.ExitNodeStatus { return plane.status }

// Only a failed way out to the Internet takes the exit node's uplink down
// for relayed questions: missing rules or forwarding off leave the host's
// own sockets working (DNS design D1c §4.2, TD-CLI-72).
func TestExitNodeStatusTakesTheUplinkDownOnlyOnEgressFailure(t *testing.T) {
	t.Parallel()
	for code, down := range map[string]bool{
		dataplane.ExitCodeEgressFailed:  true,
		dataplane.ExitCodeRulesMissing:  false,
		dataplane.ExitCodeForwardingOff: false,
		"":                              false,
	} {
		plane := &exitStatusDataPlane{status: dataplane.ExitNodeStatus{
			Pool: "world", Serving: true,
			Health: &dataplane.ExitHealth{State: dataplane.SiteHealthFailed, Code: code},
		}}
		service := &Service{dataPlane: plane, exitForwarder: dnsconfig.NewExitForwarder(nil, nil)}
		service.exitNodeStatus()
		if got := service.exitForwarder.UplinkDown(); got != down {
			t.Fatalf("%q: uplink down %v, want %v", code, got, down)
		}
	}
}
