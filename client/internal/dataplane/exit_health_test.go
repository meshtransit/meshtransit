package dataplane

import (
	"testing"

	"meshtransit.net/client/internal/netadmin"
)

func TestJudgeExit(t *testing.T) {
	t.Parallel()
	serving := ExitNodeStatus{Pool: "p", Serving: true}
	helper := netadmin.ServedHealth{Exit: netadmin.ExitServing{Serving: true, ConntrackPerConsumer: 4096, MaxConsumers: 8}}
	both := [2]bool{true, true}
	tests := []struct {
		name  string
		round exitRound
		loop  exitHealthLoop
		state string
		code  string
		ipv4  bool
		ipv6  bool
	}{
		{
			"healthy",
			exitRound{status: serving, health: helper, hasPool: both},
			exitHealthLoop{ok: both},
			SiteHealthOK, SiteCodeOK, true, true,
		},
		{
			"exit mode off",
			exitRound{status: ExitNodeStatus{Pool: "p", Refused: netadmin.ExitRefusedOff}},
			exitHealthLoop{},
			SiteHealthFailed, ExitCodeNotOffered, false, false,
		},
		{"rules missing", exitRound{status: serving, health: netadmin.ServedHealth{
			Exit:     helper.Exit,
			Problems: []string{netadmin.ProblemRulesMissing},
		}}, exitHealthLoop{}, SiteHealthFailed, ExitCodeRulesMissing, false, false},
		{
			"egress failed",
			exitRound{status: serving, health: helper, hasPool: both},
			exitHealthLoop{failures: [2]int{3, 3}},
			SiteHealthFailed, ExitCodeEgressFailed, false, false,
		},
		{
			"v4 only failed with no v6 probe",
			exitRound{status: serving, health: helper, hasPool: [2]bool{true, false}},
			exitHealthLoop{failures: [2]int{3, 0}},
			SiteHealthFailed, ExitCodeEgressFailed, false, false,
		},
		{
			"v6 failed",
			exitRound{status: serving, health: helper, hasPool: both},
			exitHealthLoop{failures: [2]int{0, 3}, ok: [2]bool{true, false}},
			SiteHealthDegraded, ExitCodeEgressV6Failed, true, false,
		},
		{
			"two failures are no failure yet",
			exitRound{status: serving, health: helper, hasPool: both},
			exitHealthLoop{failures: [2]int{2, 0}, ok: both},
			SiteHealthOK, SiteCodeOK, true, true,
		},
		{
			"conntrack high",
			exitRound{status: serving, health: netadmin.ServedHealth{
				Exit:           helper.Exit,
				ConntrackCount: 90, ConntrackMax: 100,
			}, hasPool: both},
			exitHealthLoop{ok: both},
			SiteHealthDegraded, ExitCodeConntrackHigh, true, true,
		},
		{
			"helper silent thrice",
			exitRound{status: serving, err: netadmin.ErrProtocol},
			exitHealthLoop{helperFailures: 3},
			SiteHealthFailed, ExitCodeForwardingFail, false, false,
		},
	}
	for _, test := range tests {
		health, conclusive := judgeExit(test.round, test.loop)
		if !conclusive || health.State != test.state || health.Code != test.code || health.IPv4 != test.ipv4 ||
			health.IPv6 != test.ipv6 {
			t.Errorf("%s: judgeExit() = %+v, %t", test.name, health, conclusive)
		}
	}
	// Nothing verified yet reports nothing.
	for name, test := range map[string]struct {
		round exitRound
		loop  exitHealthLoop
	}{
		"first failed round": {exitRound{status: serving, health: helper, hasPool: both}, exitHealthLoop{failures: [2]int{1, 0}}},
		"helper silent once": {exitRound{status: serving, err: netadmin.ErrProtocol}, exitHealthLoop{helperFailures: 1}},
	} {
		if health, conclusive := judgeExit(test.round, test.loop); conclusive {
			t.Errorf("%s: concluded %+v", name, health)
		}
	}
	unroutable := exitRound{status: serving, health: netadmin.ServedHealth{
		Exit:     helper.Exit,
		Problems: []string{netadmin.ProblemSelfTestUnrouted},
	}, unroutable: true, hasPool: both}
	if health, conclusive := judgeExit(unroutable, exitHealthLoop{}); !conclusive ||
		health != (ExitHealth{State: SiteHealthDegraded, Code: ExitCodeProbeUnavailable}) {
		t.Errorf("self-test unrouted = %+v, %t", health, conclusive)
	}
}
