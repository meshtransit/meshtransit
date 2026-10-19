package dataplane

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"time"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/routesettings"
)

const (
	// routerHealthInterval is how often a router measures its Sites
	// (design §6.5).
	routerHealthInterval = 2 * time.Second
	// routerProbeWait is how long one self-test waits for its answer.
	routerProbeWait = time.Second
	// routerProbeFailures is how many rounds in a row a Site's probes must
	// fail before it counts as failed.
	routerProbeFailures = 3
	// maximumProbesPerRound bounds the self-tests of one round; a router of
	// more Sites probes them in turn.
	maximumProbesPerRound = 64
	// conntrackDegradedPercent is the connection tracking use above which a
	// router warns that new flows may soon be dropped.
	conntrackDegradedPercent = 80
	routerHealthTimeout      = 5 * time.Second
)

// Site health states and codes (design §6.5).
const (
	SiteHealthOK       = "ok"
	SiteHealthDegraded = "degraded"
	SiteHealthFailed   = "failed"

	SiteCodeOK                  = "ok"
	SiteCodeForwardingFailed    = "route_forwarding_failed"
	SiteCodeRulesMissing        = netadmin.ProblemRulesMissing
	SiteCodeForwardingOff       = netadmin.ProblemForwardingOff
	SiteCodePrefixNotAdvertised = "prefix_not_advertised"
	SiteCodeNoRoute             = "no_route"
	SiteCodeForwardBlocked      = "forward_blocked"
	SiteCodeProbeFailed         = "probe_failed"
	SiteCodeConntrackHigh       = "conntrack_high"
)

// SiteHealth is one served Site's health as the router measures it.
type SiteHealth struct {
	Ref   string
	State string
	Code  string
}

// servedChecker reads the router's state from the helper.
type servedChecker interface {
	CheckServedRoutes(ctx context.Context) (netadmin.ServedHealth, error)
}

// routerHealth is the state of the health loop; guarded by the engine's
// lock.
type routerHealth struct {
	running bool
	// failures counts each Site's probe rounds failed in a row, and cause
	// what the last one found; helperFailures the rounds in a row the helper
	// did not answer.
	failures       map[string]int
	cause          map[string]string
	helperFailures int
	// last is the previous judgement, kept while the helper does not answer.
	last []SiteHealth
	// cursor is where the next round's probes start.
	cursor int
}

// probeRef names one probe of one Site.
type probeRef struct {
	site  string
	index int
}

// routerRound is what one measurement found.
type routerRound struct {
	before, after       netadmin.ServedHealth
	beforeErr, afterErr error
	outcomes            map[probeRef]probeOutcome
}

// startRouterHealthLocked runs the health loop while the node serves Sites
// and the helper can report on them.
func (e *WireGuardEngine) startRouterHealthLocked() {
	checker, ok := e.opener.(servedChecker)
	if !ok || e.routerHealth.running || e.filter == nil {
		return
	}
	e.routerHealth.running = true
	go e.runRouterHealth(checker, e.filter.selfTest)
}

func (e *WireGuardEngine) runRouterHealth(checker servedChecker, tester *selfTester) {
	ticker := time.NewTicker(routerHealthInterval)
	defer ticker.Stop()
	for {
		e.mu.Lock()
		if e.device == nil || len(e.served.desired) == 0 {
			e.routerHealth = routerHealth{}
			e.servedStatus.Health = nil
			e.mu.Unlock()
			return
		}
		sites := slices.Clone(e.served.desired)
		cursor := e.routerHealth.cursor
		e.mu.Unlock()

		round, next := measureRouter(checker, tester, sites, cursor)
		if code := netadmin.RemoteCode(round.beforeErr); code == "unsupported_request" || code == "served_routes_unavailable" {
			// An older helper cannot report: the health is unknown, not failed.
			e.mu.Lock()
			e.routerHealth.running, e.servedStatus.Health = false, nil
			e.mu.Unlock()
			if e.logger != nil {
				e.logger.Warn("the network helper cannot report subnet router health; update meshnetd")
			}
			return
		}

		e.mu.Lock()
		if e.device != nil && equalServedSites(sites, e.served.desired) {
			e.routerHealth.cursor = next
			e.recordRouterHealthLocked(sites, round)
		}
		e.mu.Unlock()
		<-ticker.C
	}
}

// measureRouter asks the helper for the router's state, sends up to
// maximumProbesPerRound self-tests from cursor on, and asks again, so the
// self-test counter tells a packet dropped on the way from one the target
// did not answer. It returns where the next round starts.
func measureRouter(checker servedChecker, tester *selfTester, sites []networkmap.ServedSite, cursor int) (routerRound, int) {
	ctx, cancel := context.WithTimeout(context.Background(), routerHealthTimeout)
	defer cancel()
	round := routerRound{outcomes: map[probeRef]probeOutcome{}}
	round.before, round.beforeErr = checker.CheckServedRoutes(ctx)
	if round.beforeErr != nil {
		return round, cursor
	}
	// Answers to self-tests that are not routed back into the TUN would
	// leave by another way: they prove nothing.
	if slices.Contains(round.before.Problems, netadmin.ProblemSelfTestUnrouted) {
		return round, cursor
	}
	all := probesOf(sites, round.before.Installed)
	if len(all) == 0 {
		return round, 0
	}
	cursor %= len(all)
	chosen := append(slices.Clone(all[cursor:]), all[:cursor]...)
	chosen = chosen[:min(len(chosen), maximumProbesPerRound)]
	var mu sync.Mutex
	var wait sync.WaitGroup
	for _, ref := range chosen {
		probe := probeOf(sites, ref)
		wait.Go(func() {
			outcome := tester.probe(ctx, probe.Address, tcpPort(probe), routerProbeWait)
			mu.Lock()
			round.outcomes[ref] = outcome
			mu.Unlock()
		})
	}
	wait.Wait()
	round.after, round.afterErr = checker.CheckServedRoutes(ctx)
	return round, (cursor + len(chosen)) % len(all)
}

func tcpPort(probe networkmap.RouteProbe) uint16 {
	if probe.TCP {
		return probe.Port
	}
	return 0
}

// probesOf lists the probes a self-test can check: those of Sites that
// translate mesh sources (the answer to a self-test address comes back
// only then), inside a prefix the router forwards into.
func probesOf(sites []networkmap.ServedSite, installed []netip.Prefix) []probeRef {
	var refs []probeRef
	for _, site := range sites {
		if !site.Masquerade {
			continue
		}
		for index, probe := range site.Probes {
			if slices.ContainsFunc(installed, func(prefix netip.Prefix) bool { return prefix.Contains(probe.Address) }) {
				refs = append(refs, probeRef{site: site.Ref, index: index})
			}
		}
	}
	return refs
}

func probeOf(sites []networkmap.ServedSite, ref probeRef) networkmap.RouteProbe {
	for _, site := range sites {
		if site.Ref == ref.site {
			return site.Probes[ref.index]
		}
	}
	return networkmap.RouteProbe{}
}

// recordRouterHealthLocked judges each Site from round and keeps the
// result, logging what changed.
func (e *WireGuardEngine) recordRouterHealthLocked(sites []networkmap.ServedSite, round routerRound) {
	health, tracked := judgeRouter(sites, round, e.routerHealth.trackedOrEmpty())
	e.routerHealth.failures, e.routerHealth.cause = tracked.failures, tracked.cause
	e.routerHealth.helperFailures, e.routerHealth.last = tracked.helperFailures, tracked.last
	previous := e.servedStatus.Health
	e.servedStatus.Health = health
	if e.logger == nil {
		return
	}
	for _, site := range health {
		index := slices.IndexFunc(previous, func(old SiteHealth) bool { return old.Ref == site.Ref })
		if index >= 0 && previous[index] == site {
			continue
		}
		if site.State == SiteHealthOK {
			if index >= 0 {
				e.logger.Info("served Site is healthy again", "site", site.Ref)
			}
			continue
		}
		e.logger.Warn("served Site is unhealthy", "site", site.Ref, "state", site.State, "code", site.Code)
	}
}

func (h routerHealth) trackedOrEmpty() routerHealth {
	if h.failures == nil {
		h.failures, h.cause = map[string]int{}, map[string]string{}
	}
	return h
}

// judgeRouter decides each Site's health: what keeps forwarding from
// working first, then probes failed routerProbeFailures rounds in a row,
// then connection tracking near its limit.
func judgeRouter(sites []networkmap.ServedSite, round routerRound, prior routerHealth) ([]SiteHealth, routerHealth) {
	tracked := routerHealth{failures: map[string]int{}, cause: map[string]string{}}
	// One unanswered check proves nothing (the helper may be busy or
	// restarting); routerProbeFailures in a row fail every Site.
	if round.beforeErr != nil {
		tracked.helperFailures = prior.helperFailures + 1
	}
	cause := probeCause(round)
	health := make([]SiteHealth, 0, len(sites))
	for _, site := range sites {
		failures, last := prior.failures[site.Ref], prior.cause[site.Ref]
		if answered, probed := siteProbed(site.Ref, round.outcomes); probed {
			switch {
			case answered:
				failures, last = 0, ""
			case cause[site.Ref] != "":
				failures, last = failures+1, cause[site.Ref]
			}
		}
		if failures > 0 {
			tracked.failures[site.Ref], tracked.cause[site.Ref] = failures, last
		}
		state, code := SiteHealthOK, SiteCodeOK
		if round.beforeErr != nil {
			// Keep the last judgement until the helper answers again.
			if tracked.helperFailures >= routerProbeFailures {
				state, code = SiteHealthFailed, SiteCodeForwardingFailed
			} else if index := slices.IndexFunc(prior.last, func(old SiteHealth) bool { return old.Ref == site.Ref }); index >= 0 {
				state, code = prior.last[index].State, prior.last[index].Code
			}
		} else if failed := hostFailure(site, round); failed != "" {
			state, code = SiteHealthFailed, failed
		} else if failures >= routerProbeFailures {
			state, code = SiteHealthFailed, last
		} else if count, maximum := round.before.ConntrackCount, round.before.ConntrackMax; maximum > 0 &&
			count*100 > conntrackDegradedPercent*maximum {
			state, code = SiteHealthDegraded, SiteCodeConntrackHigh
		}
		health = append(health, SiteHealth{Ref: site.Ref, State: state, Code: code})
	}
	tracked.last = health
	return health, tracked
}

// hostFailure is what keeps the host from forwarding into site, or "".
func hostFailure(site networkmap.ServedSite, round routerRound) string {
	problems := round.before.Problems
	switch {
	case slices.Contains(problems, netadmin.ProblemInstallFailed):
		return SiteCodeForwardingFailed
	case slices.Contains(problems, netadmin.ProblemRulesMissing):
		return SiteCodeRulesMissing
	case slices.Contains(problems, netadmin.ProblemForwardingOff):
		return SiteCodeForwardingOff
	}
	for _, prefix := range site.Prefixes {
		if slices.ContainsFunc(round.before.Installed, func(installed netip.Prefix) bool {
			return prefix.Bits() <= installed.Bits() && prefix.Contains(installed.Addr())
		}) {
			continue
		}
		index := slices.IndexFunc(round.before.Refused, func(refusal routesettings.Refusal) bool { return refusal.Prefix == prefix })
		if index >= 0 && round.before.Refused[index].Reason == SiteCodeNoRoute {
			return SiteCodeNoRoute
		}
		if index >= 0 && (round.before.Refused[index].Reason == routesettings.ReasonInstallFailed ||
			round.before.Refused[index].Reason == routesettings.ReasonFamilyUnavailable) {
			return SiteCodeForwardingFailed
		}
		return SiteCodePrefixNotAdvertised
	}
	return ""
}

// siteProbed reports whether site had probes in this round and whether any
// was answered.
func siteProbed(site string, outcomes map[probeRef]probeOutcome) (answered, probed bool) {
	for ref, outcome := range outcomes {
		if ref.site != site || outcome == probeUnsent {
			continue
		}
		probed = true
		if outcome == probeAnswered {
			answered = true
		}
	}
	return answered, probed
}

// probeCause names, for each Site whose probes were all unanswered, what
// failed. A refused TCP probe reached its host: probe_failed. A silent one
// either never left the router or got no answer: the self-test counter,
// which counts every self-test that crossed the forward path, tells them
// apart. With no counter to read, or a table installed again meanwhile,
// nothing is concluded this round.
func probeCause(round routerRound) map[string]string {
	causes := map[string]string{}
	sent, silent := 0, 0
	for _, outcome := range round.outcomes {
		if outcome != probeUnsent {
			sent++
		}
		if outcome == probeSilent {
			silent++
		}
	}
	silentCause := ""
	if round.afterErr == nil && round.before.SelfTestKnown && round.after.SelfTestKnown &&
		round.after.SelfTestPackets >= round.before.SelfTestPackets {
		crossed := int(round.after.SelfTestPackets - round.before.SelfTestPackets) //nolint:gosec // G115: bounded by the probes sent
		// Answered and refused self-tests crossed too; the rest of the
		// count are silent ones that left the router. Only all or none of
		// them is conclusive: some of each could be either Site's.
		switch left := crossed - (sent - silent); {
		case left <= 0:
			silentCause = SiteCodeForwardBlocked
		case left >= silent:
			silentCause = SiteCodeProbeFailed
		}
	}
	bySite := map[string][]probeOutcome{}
	for ref, outcome := range round.outcomes {
		if outcome != probeUnsent {
			bySite[ref.site] = append(bySite[ref.site], outcome)
		}
	}
	for site, outcomes := range bySite {
		switch {
		case slices.Contains(outcomes, probeAnswered):
		case slices.Contains(outcomes, probeRefused):
			causes[site] = SiteCodeProbeFailed
		default:
			causes[site] = silentCause
		}
	}
	return causes
}
