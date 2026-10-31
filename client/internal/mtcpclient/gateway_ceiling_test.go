package mtcpclient

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
)

func ceilingOf(verb string, checkedAt int64) *mtcpv1.GatewayGroupCeiling {
	return &mtcpv1.GatewayGroupCeiling{CheckedAtMs: checkedAt, Groups: []*mtcpv1.GatewayCeilingGroup{{
		Group: "view", Everywhere: &mtcpv1.GatewayCeilingScope{Measured: true, Rules: []*mtcpv1.KubernetesProfileRule{
			{Verbs: []string{verb}, ApiGroups: []string{""}, Resources: []string{"pods"}},
		}},
	}}}
}

// A gateway sends its ceiling at once, again when its content changes but
// never within a minute of the last, an unchanged one every 6 hours (a new
// checked_at_ms alone is no change), and never one that breaks §6.12.
func TestSendGroupCeilingCadence(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_800_000_000, 0)
	invalid := ceilingOf("get", 1)
	invalid.Groups[0].Everywhere = nil
	current := ceilingOf("get", 1)
	conn := &countingConn{}
	s := tokenSession(t, conn, start)
	s.ceiling = true
	run := &sessionRun{s: s, stream: &netmapStream{client: &Client{groupCeiling: func() *mtcpv1.GatewayGroupCeiling {
		return current
	}}}}
	step := func(at time.Duration, ceiling *mtcpv1.GatewayGroupCeiling, writes int) {
		t.Helper()
		current = ceiling
		if err := run.sendGroupCeiling(start.Add(at)); err != nil || conn.writes != writes {
			t.Fatalf("at %v: %d writes, %v; want %d", at, conn.writes, err, writes)
		}
	}
	step(0, ceilingOf("get", 1), 1)
	step(ceilingBeat, ceilingOf("get", 2), 1)
	step(30*time.Second, ceilingOf("list", 3), 1)
	step(ceilingBeat, ceilingOf("list", 3), 2)
	step(2*ceilingBeat, invalid, 2)
	step(3*ceilingBeat, nil, 2)
	step(ceilingBeat+ceilingResend, ceilingOf("list", 9), 3)

	// One too large to encode is not sent, and the session goes on (review
	// h4b M2).
	huge := &mtcpv1.GatewayGroupCeiling{}
	for group := range 64 {
		measured := &mtcpv1.GatewayCeilingGroup{
			Group:      fmt.Sprintf("g%02d", group),
			Everywhere: &mtcpv1.GatewayCeilingScope{Measured: true},
		}
		for rule := range 100 {
			measured.Everywhere.Rules = append(measured.Everywhere.Rules, &mtcpv1.KubernetesProfileRule{
				Verbs: []string{"get"}, ApiGroups: []string{""}, Resources: []string{fmt.Sprintf("r%060d", rule)},
			})
		}
		huge.Groups = append(huge.Groups, measured)
	}
	step(2*ceilingBeat+ceilingResend, huge, 3)

	// A session without gateway.ceiling1 sends nothing.
	s.ceiling = false
	step(7*time.Hour, ceilingOf("watch", 1), 3)

	// A failed write ends the session.
	s.ceiling, conn.err = true, errors.New("closed")
	if err := run.sendGroupCeiling(start.Add(8 * time.Hour)); err == nil {
		t.Fatal("a failed write was not reported")
	}
}

// A gateway with a ceiling source asks for gateway.ceiling1; a client that
// is not a gateway's never takes a source.
func TestGatewayAsksForCeilings(t *testing.T) {
	t.Parallel()
	core := provingCore(t, nil, answerPings)
	trust := gatewayTrust(t, core)
	client := core.gatewayClient()
	client.SetGroupCeilingSource(func() *mtcpv1.GatewayGroupCeiling { return nil })
	if err := client.ProbeGateway(t.Context(), core.origin(), trust.Material, trust.Fingerprint); err != nil {
		t.Fatal(err)
	}
	hellos, _ := core.sessions()
	if last := hellos[len(hellos)-1]; !slices.Contains(last.GetCapabilities(), gatewayCeilingCapability) {
		t.Fatalf("hello %v lacks gateway.ceiling1", last)
	}
	plain := New()
	plain.SetGroupCeilingSource(func() *mtcpv1.GatewayGroupCeiling { return nil })
	if plain.groupCeiling != nil {
		t.Fatal("meshd took a ceiling source")
	}
}
