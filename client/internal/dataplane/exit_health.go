package dataplane

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"time"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
)

const (
	// exitHealthInterval is how often an exit node judges its health, and
	// exitProbeInterval how often it probes the Internet while healthy; a
	// failing family is probed every round (exit node design §8).
	exitHealthInterval = 2 * time.Second
	exitProbeInterval  = 15 * time.Second
	// exitProbesPerFamily bounds the probes of one family in one round; the
	// pool's probes are taken in turn.
	exitProbesPerFamily = 2
)

// Exit health codes (exit node design §8).
const (
	ExitCodeNotOffered     = "exit_not_offered"
	ExitCodeForwardingFail = "forwarding_failed"
	ExitCodeEgressFailed   = "egress_failed"
	ExitCodeEgressV4Failed = "egress_v4_failed"
	ExitCodeEgressV6Failed = "egress_v6_failed"
	ExitCodeConntrackHigh  = SiteCodeConntrackHigh
	ExitCodeForwardingOff  = SiteCodeForwardingOff
	ExitCodeRulesMissing   = SiteCodeRulesMissing
	// ExitCodeProbeUnavailable: the self-test addresses are not routed into
	// the TUN, so the Internet cannot be checked.
	ExitCodeProbeUnavailable = "probe_unavailable"
)

// ExitHealth is the exit node's health of the pool it serves, as it
// measures it: a state of SiteHealth*, a code, and the address families it
// reached the Internet in (both false: not known).
type ExitHealth struct {
	State      string
	Code       string
	IPv4, IPv6 bool
}

// exitHealthLoop is the state of the exit health loop; guarded by the
// engine's lock.
type exitHealthLoop struct {
	stop chan struct{}
	// failures counts each family's probe rounds failed in a row; ok
	// whether its last round reached the Internet; probedAt when it was.
	failures       [2]int
	ok             [2]bool
	probedAt       [2]time.Time
	cursor         [2]int
	helperFailures int
}

// startExitHealthLocked runs the loop while the map has the node serve a
// pool and the helper can report.
func (e *WireGuardEngine) startExitHealthLocked() {
	checker, ok := e.opener.(servedChecker)
	if !ok || e.exitHealth.stop != nil || e.filter == nil {
		return
	}
	stop := make(chan struct{})
	e.exitHealth = exitHealthLoop{stop: stop}
	go e.runExitHealth(checker, e.filter.selfTest, stop)
}

// stopExitHealthLocked ends the loop at once.
func (e *WireGuardEngine) stopExitHealthLocked() {
	if e.exitHealth.stop != nil {
		close(e.exitHealth.stop)
	}
	e.exitHealth = exitHealthLoop{}
	e.exitStatus.Health = nil
}

func (e *WireGuardEngine) runExitHealth(checker servedChecker, tester *selfTester, stop chan struct{}) {
	ticker := time.NewTicker(exitHealthInterval)
	defer ticker.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	for {
		e.mu.Lock()
		if e.exitHealth.stop != stop {
			e.mu.Unlock()
			return
		}
		if e.device == nil || len(e.servedExit.desired.pools) == 0 {
			e.exitHealth, e.exitStatus.Health = exitHealthLoop{}, nil
			e.mu.Unlock()
			return
		}
		pool := e.servedExit.desired.pools[0]
		status := e.exitStatus
		loop := e.exitHealth
		e.mu.Unlock()

		now := time.Now()
		round := measureExit(ctx, checker, tester, pool, status, loop, now)
		e.mu.Lock()
		if e.exitHealth.stop == stop && e.device != nil && len(e.servedExit.desired.pools) != 0 &&
			e.servedExit.desired.pools[0].Ref == pool.Ref {
			e.recordExitHealthLocked(round, now)
		}
		e.mu.Unlock()
		select {
		case <-ticker.C:
		case <-stop:
			return
		}
	}
}

// exitRound is what one measurement found.
type exitRound struct {
	unroutable bool
	status     ExitNodeStatus
	health     netadmin.ServedHealth
	err        error
	probed     [2]bool
	reached    [2]bool
	cursor     [2]int
	hasPool    [2]bool
}

// measureExit asks the helper for the host's state and, when due, probes
// the Internet through the exit node's own forwarding path: TCP SYNs from
// the self-test addresses into the TUN, so they cross FORWARD and the source
// translation as consumers' packets do. An answer or a reset reached the
// Internet.
func measureExit(parent context.Context, checker servedChecker, tester *selfTester, pool networkmap.ServedExit,
	status ExitNodeStatus, loop exitHealthLoop, now time.Time,
) exitRound {
	ctx, cancel := context.WithTimeout(parent, routerHealthTimeout)
	defer cancel()
	round := exitRound{status: status, cursor: loop.cursor}
	round.health, round.err = checker.CheckServedRoutes(ctx)
	round.unroutable = round.err == nil && slices.Contains(round.health.Problems, netadmin.ProblemSelfTestUnrouted)
	if round.err != nil || !status.Serving || !round.health.Exit.Serving || round.unroutable {
		return round
	}
	families := [2][]netip.AddrPort{}
	for _, probe := range pool.Probes {
		family := 0
		if probe.Addr().Is6() {
			family = 1
		}
		families[family] = append(families[family], probe)
	}
	var mu sync.Mutex
	var wait sync.WaitGroup
	for family, probes := range families {
		round.hasPool[family] = len(probes) != 0
		due := loop.failures[family] > 0 || !loop.ok[family] || now.Sub(loop.probedAt[family]) >= exitProbeInterval
		if len(probes) == 0 || !due {
			continue
		}
		round.probed[family] = true
		start := loop.cursor[family] % len(probes)
		chosen := append(slices.Clone(probes[start:]), probes[:start]...)
		chosen = chosen[:min(len(chosen), exitProbesPerFamily)]
		round.cursor[family] = (start + len(chosen)) % len(probes)
		for _, probe := range chosen {
			wait.Go(func() {
				outcome := tester.probe(ctx, probe.Addr(), probe.Port(), routerProbeWait)
				if outcome == probeAnswered || outcome == probeRefused {
					mu.Lock()
					round.reached[family] = true
					mu.Unlock()
				}
			})
		}
	}
	wait.Wait()
	return round
}

// recordExitHealthLocked judges the exit node's health from round.
func (e *WireGuardEngine) recordExitHealthLocked(round exitRound, now time.Time) {
	loop := &e.exitHealth
	if round.err != nil {
		loop.helperFailures++
	} else {
		loop.helperFailures = 0
	}
	loop.cursor = round.cursor
	for family := range 2 {
		if !round.probed[family] {
			if !round.hasPool[family] {
				loop.failures[family], loop.ok[family] = 0, false
			}
			continue
		}
		loop.probedAt[family] = now
		if round.reached[family] {
			loop.failures[family], loop.ok[family] = 0, true
		} else {
			loop.failures[family]++
			if loop.failures[family] >= routerProbeFailures {
				loop.ok[family] = false
			}
		}
	}
	health, conclusive := judgeExit(round, *loop)
	if !conclusive {
		// Nothing verified yet: keep what was, nothing before the first
		// conclusive round.
		return
	}
	previous := e.exitStatus.Health
	e.exitStatus.Health = &health
	if e.logger != nil && (previous == nil || *previous != health) && health.State != SiteHealthOK {
		e.logger.Warn("the exit node is unhealthy", "pool", e.exitStatus.Pool, "state", health.State, "code", health.Code)
	}
}

// judgeExit decides the exit node's health: what keeps it from forwarding
// first, then the Internet unreached in a family routerProbeFailures rounds
// in a row, then connection tracking near its limit. It is not conclusive
// while a family the pool probes has neither reached the Internet nor
// failed routerProbeFailures rounds in a row, nor while the helper is
// silent fewer rounds than that.
func judgeExit(round exitRound, loop exitHealthLoop) (ExitHealth, bool) {
	failed := func(code string) (ExitHealth, bool) { return ExitHealth{State: SiteHealthFailed, Code: code}, true }
	switch {
	case round.status.Refused == netadmin.ExitRefusedOff:
		return failed(ExitCodeNotOffered)
	case round.status.Error != "" || round.status.Refused != "" || !round.status.Serving:
		return failed(ExitCodeForwardingFail)
	case round.err != nil:
		if loop.helperFailures >= routerProbeFailures {
			return failed(ExitCodeForwardingFail)
		}
		return ExitHealth{}, false
	case !round.health.Exit.Serving:
		if round.health.Exit.Refused == netadmin.ExitRefusedOff {
			return failed(ExitCodeNotOffered)
		}
		return failed(ExitCodeForwardingFail)
	case slices.Contains(round.health.Problems, netadmin.ProblemInstallFailed):
		return failed(ExitCodeForwardingFail)
	case slices.Contains(round.health.Problems, netadmin.ProblemRulesMissing):
		return failed(ExitCodeRulesMissing)
	case slices.Contains(round.health.Problems, netadmin.ProblemForwardingOff):
		return failed(ExitCodeForwardingOff)
	case round.unroutable:
		return ExitHealth{State: SiteHealthDegraded, Code: ExitCodeProbeUnavailable}, true
	}
	for family := range 2 {
		if round.hasPool[family] && !loop.ok[family] && loop.failures[family] < routerProbeFailures {
			return ExitHealth{}, false
		}
	}
	health := ExitHealth{State: SiteHealthOK, Code: SiteCodeOK, IPv4: loop.ok[0], IPv6: loop.ok[1]}
	v4Failed := round.hasPool[0] && loop.failures[0] >= routerProbeFailures
	v6Failed := round.hasPool[1] && loop.failures[1] >= routerProbeFailures
	switch {
	case v4Failed && (!round.hasPool[1] || v6Failed):
		return failed(ExitCodeEgressFailed)
	case v4Failed:
		health.State, health.Code = SiteHealthDegraded, ExitCodeEgressV4Failed
	case v6Failed:
		health.State, health.Code = SiteHealthDegraded, ExitCodeEgressV6Failed
	case round.health.ConntrackMax > 0 &&
		round.health.ConntrackCount*100 > conntrackDegradedPercent*round.health.ConntrackMax:
		health.State, health.Code = SiteHealthDegraded, ExitCodeConntrackHigh
	}
	return health, true
}
