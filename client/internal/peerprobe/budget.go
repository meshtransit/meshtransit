package peerprobe

import (
	"net/netip"
	"time"

	"meshtransit.net/shared/key"
)

// A peer's candidates come from its Device's reports and its own disco
// messages, so a peer, or a Device lying about its endpoints, chooses where
// this node sends probes. The probe budget bounds what it can make this
// node send to addresses that never answered (mtcp-v1 §8.1, disco-v2 §4.4):
//   - each such candidate is probed with a growing interval, from
//     minCandidateBackoff up to maxCandidateBackoff, so scheduled rounds
//     move on to other candidates instead of repeating the first ones;
//   - all such probes to one peer spend a bucket of unconfirmedProbeBurst
//     tokens refilled one per probeRefill, so new endpoints every report
//     cannot bypass the backoff;
//   - while the peer has no candidate that answered, so it needs a path,
//     probes beyond the bucket spend a path-setup credit of
//     pathSetupCredit, refilled one per probeRefill too.
//
// Nothing the peer sends refills faster: a peer that answers pings has a
// confirmed candidate and gets no credit, so in the long run a node sends
// at most 2/probeRefill probes per second to a peer's unanswered
// candidates. A candidate that answered within confirmedPathLifetime is
// probed freely: that keeps a working path alive and only reaches the
// peer itself. The budget belongs to the peer's ID, not its keys, so a
// Device that reconnects with a new disco key does not start afresh.
const (
	unconfirmedProbeBurst = 24
	pathSetupCredit       = 120
	probeRefill           = 5 * time.Second
	confirmedPathLifetime = 2 * time.Minute
	minCandidateBackoff   = 3 * time.Second
	maxCandidateBackoff   = time.Minute
	// maxCandidateStates bounds the probe state kept per peer, above the
	// 32 endpoints Core sends and the candidates in use; states of
	// endpoints that are no longer candidates go first.
	maxCandidateStates = 128
)

// peerAllowance is the probe budget of one peer's Device. The registry
// keeps it by peer ID across maps, map deactivations, key changes and the
// peer leaving the map, and forgets it only once it is back to a fresh
// one's state, so nothing a peer or its Device does starts it afresh.
type peerAllowance struct {
	probes       map[netip.AddrPort]candidateProbes
	budget       probeBudget
	answeredPing time.Time
	answeredCall time.Time
	nodeKey      key.NodePublic
	discoveryKey key.DiscoPublic
}

func newPeerAllowance() *peerAllowance {
	return &peerAllowance{probes: make(map[netip.AddrPort]candidateProbes)}
}

// renew prepares the allowance for a new map generation of a peer with
// these keys: the generation cancels the probes still waiting for an
// answer, so their backoff ends, while the unanswered counts and the
// budget stay; an answer to other keys proves nothing now.
func (allowance *peerAllowance) renew(nodeKey key.NodePublic, discoveryKey key.DiscoPublic) {
	sameKeys := allowance.nodeKey == nodeKey && allowance.discoveryKey == discoveryKey
	allowance.nodeKey, allowance.discoveryKey = nodeKey, discoveryKey
	for endpoint, state := range allowance.probes {
		state.next = time.Time{}
		if !sameKeys {
			state.confirmed = time.Time{}
		}
		allowance.probes[endpoint] = state
	}
}

// fresh reports whether forgetting the allowance would change nothing: its
// budget is full again and no answer spacing is still running.
func (allowance *peerAllowance) fresh(now time.Time) bool {
	if allowance.budget.refilled.IsZero() {
		return now.Sub(allowance.answeredPing) >= directTrust && now.Sub(allowance.answeredCall) >= callMeMaybeAnswerSpacing
	}
	added := float64(now.Sub(allowance.budget.refilled)) / float64(probeRefill)
	return allowance.budget.tokens+added >= unconfirmedProbeBurst && allowance.budget.credit+added >= pathSetupCredit &&
		now.Sub(allowance.answeredPing) >= directTrust && now.Sub(allowance.answeredCall) >= callMeMaybeAnswerSpacing
}

// candidateProbes is the probe state of one candidate of a peer.
type candidateProbes struct {
	unanswered int       // probes since the last pong
	next       time.Time // no scheduled probe before
	confirmed  time.Time // the last pong from it
}

func (state candidateProbes) confirmedAt(now time.Time) bool {
	return !state.confirmed.IsZero() && now.Sub(state.confirmed) < confirmedPathLifetime && !now.Before(state.confirmed)
}

// probeBudget is a peer's allowance for probes to unconfirmed candidates.
type probeBudget struct {
	tokens   float64
	credit   float64
	refilled time.Time
}

// probeCharge is what a claimed probe spent, so a probe that was never
// sent can be refunded.
type probeCharge int

const (
	chargedNothing probeCharge = iota // a confirmed candidate
	chargedToken
	chargedCredit
)

// probeClaim is one claimed probe.
type probeClaim struct {
	endpoint netip.AddrPort
	charge   probeCharge
	previous candidateProbes
}

// due reports whether a scheduled round may probe endpoint now.
func (p *peerChannel) due(endpoint netip.AddrPort, now time.Time) bool {
	state := p.allowance.probes[endpoint]
	return state.confirmedAt(now) || !now.Before(state.next)
}

// probeOrder ranks a due candidate for a round: one that answered first,
// then by how many probes it left unanswered.
func (p *peerChannel) probeOrder(endpoint netip.AddrPort, now time.Time) int {
	state := p.allowance.probes[endpoint]
	if state.confirmedAt(now) {
		return -1
	}
	return state.unanswered
}

// claim records a probe to endpoint and reports whether the budget allows
// it. A scheduled probe also waits for the candidate's backoff; a burst
// (an answer to the peer, or a hole just opened) does not, because both
// sides probe at that moment.
func (p *peerChannel) claim(endpoint netip.AddrPort, scheduled bool, now time.Time) (probeClaim, bool) {
	state := p.allowance.probes[endpoint]
	claim := probeClaim{endpoint: endpoint, previous: state}
	if !state.confirmedAt(now) {
		if scheduled && now.Before(state.next) {
			return probeClaim{}, false
		}
		p.refill(now)
		switch {
		case p.allowance.budget.tokens >= 1:
			p.allowance.budget.tokens--
			claim.charge = chargedToken
		case p.allowance.budget.credit >= 1 && !p.hasConfirmed(now):
			p.allowance.budget.credit--
			claim.charge = chargedCredit
		default:
			return probeClaim{}, false
		}
	}
	state.unanswered++
	state.next = now.Add(candidateBackoff(state.unanswered))
	p.store(endpoint, state, now)
	return claim, true
}

// release refunds a claimed probe that was never sent.
func (p *peerChannel) release(claim probeClaim) {
	switch claim.charge {
	case chargedToken:
		p.allowance.budget.tokens = min(unconfirmedProbeBurst, p.allowance.budget.tokens+1)
	case chargedCredit:
		p.allowance.budget.credit = min(pathSetupCredit, p.allowance.budget.credit+1)
	case chargedNothing:
	}
	if state, ok := p.allowance.probes[claim.endpoint]; ok && state.unanswered == claim.previous.unanswered+1 {
		state.unanswered, state.next = claim.previous.unanswered, claim.previous.next
		p.allowance.probes[claim.endpoint] = state
	}
}

// confirm records a pong from endpoint.
func (p *peerChannel) confirm(endpoint netip.AddrPort, now time.Time) {
	p.store(endpoint, candidateProbes{confirmed: now}, now)
}

func (p *peerChannel) hasConfirmed(now time.Time) bool {
	for _, state := range p.allowance.probes {
		if state.confirmedAt(now) {
			return true
		}
	}
	return false
}

func (p *peerChannel) store(endpoint netip.AddrPort, state candidateProbes, now time.Time) {
	if _, known := p.allowance.probes[endpoint]; !known && len(p.allowance.probes) >= maxCandidateStates {
		p.pruneProbes(now)
	}
	p.allowance.probes[endpoint] = state
}

func (p *peerChannel) refill(now time.Time) {
	if p.allowance.budget.refilled.IsZero() {
		p.allowance.budget = probeBudget{tokens: unconfirmedProbeBurst, credit: pathSetupCredit, refilled: now}
		return
	}
	elapsed := now.Sub(p.allowance.budget.refilled)
	if elapsed <= 0 {
		return
	}
	added := float64(elapsed) / float64(probeRefill)
	p.allowance.budget.tokens = min(unconfirmedProbeBurst, p.allowance.budget.tokens+added)
	p.allowance.budget.credit = min(pathSetupCredit, p.allowance.budget.credit+added)
	p.allowance.budget.refilled = now
}

// pruneProbes drops the states of endpoints that are no longer candidates,
// and if that frees nothing, the unconfirmed one that may be probed first.
func (p *peerChannel) pruneProbes(now time.Time) {
	for endpoint := range p.allowance.probes {
		if !p.isCandidate(endpoint, now) {
			delete(p.allowance.probes, endpoint)
		}
	}
	if len(p.allowance.probes) < maxCandidateStates {
		return
	}
	var oldest netip.AddrPort
	var at time.Time
	found := false
	for endpoint, state := range p.allowance.probes {
		if state.confirmedAt(now) {
			continue
		}
		if !found || state.next.Before(at) {
			oldest, at, found = endpoint, state.next, true
		}
	}
	if found {
		delete(p.allowance.probes, oldest)
	}
}

// candidateBackoff is the wait after the given number of unanswered probes.
func candidateBackoff(unanswered int) time.Duration {
	delay := minCandidateBackoff
	for range unanswered - 1 {
		if delay >= maxCandidateBackoff {
			break
		}
		delay *= 2
	}
	return min(delay, maxCandidateBackoff)
}

// answerKind names what a peer sent that this node answers with probes of
// its own: a ping, or a CALL_ME_MAYBE.
type answerKind int

const (
	answerPing answerKind = iota + 1
	answerCall
)

// allowAnswer permits one answer of kind per spacing to the peer. It is
// kept on the peer, so it is bounded by the map and survives its updates.
func (p *peerChannel) allowAnswer(kind answerKind, spacing time.Duration, now time.Time) bool {
	last := &p.allowance.answeredPing
	if kind == answerCall {
		last = &p.allowance.answeredCall
	}
	if !last.IsZero() && now.Sub(*last) < spacing && !now.Before(*last) {
		return false
	}
	*last = now
	return true
}
