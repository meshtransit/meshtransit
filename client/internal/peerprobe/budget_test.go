package peerprobe

import (
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/key"
)

func budgetPeer(now time.Time) *peerChannel {
	return &peerChannel{
		peerID: 2, firstSeen: now,
		mapEndpoints: map[netip.AddrPort]struct{}{},
		learned:      map[netip.AddrPort]learnedCandidate{},
		allowance:    newPeerAllowance(),
	}
}

func budgetEndpoint(port int) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("203.0.113.40"), uint16(port)) //nolint:gosec // test ports
}

func claims(peer *peerChannel, endpoint netip.AddrPort, scheduled bool, now time.Time) bool {
	_, ok := peer.claim(endpoint, scheduled, now)
	return ok
}

func TestCandidateBackoffGrowsUntilAnAnswer(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	peer := budgetPeer(start)
	endpoint := budgetEndpoint(41641)
	now := start
	for _, wait := range []time.Duration{
		3 * time.Second, 6 * time.Second, 12 * time.Second, 24 * time.Second,
		48 * time.Second, time.Minute, time.Minute,
	} {
		if !claims(peer, endpoint, true, now) {
			t.Fatalf("a due probe at %s was refused", now.Sub(start))
		}
		if claims(peer, endpoint, true, now.Add(wait-time.Millisecond)) || peer.due(endpoint, now.Add(wait-time.Millisecond)) {
			t.Fatalf("probed again before the %s backoff", wait)
		}
		now = now.Add(wait)
	}
	// A burst does not wait for the backoff.
	if !claims(peer, endpoint, false, now.Add(-time.Second)) {
		t.Fatal("a burst waited for the backoff")
	}
	// An answer makes it a working path: probed every round, for free.
	peer.confirm(endpoint, now)
	peer.allowance.budget = probeBudget{refilled: now}
	for range 10 {
		if !claims(peer, endpoint, true, now) {
			t.Fatal("a confirmed path was throttled")
		}
	}
	// Once the answer is old, the candidate costs a token again.
	later := now.Add(confirmedPathLifetime)
	peer.allowance.budget = probeBudget{refilled: later}
	if claims(peer, endpoint, false, later) {
		t.Fatal("a path confirmed long ago is still free")
	}
}

// TestProbeBudgetBoundsWhatAPeerCanMakeUsSend plays a peer that names a new
// endpoint for every probe: it gets the bucket, then the path-setup credit
// while it has no answered candidate, then at most the long-run rate.
func TestProbeBudgetBoundsWhatAPeerCanMakeUsSend(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	peer := budgetPeer(start)
	port := 1000
	claim := func(at time.Time) bool {
		port++
		return claims(peer, budgetEndpoint(port), false, at)
	}
	sent := 0
	for claim(start) {
		sent++
	}
	if sent != unconfirmedProbeBurst+pathSetupCredit {
		t.Fatalf("a new peer got %d probes at once, want %d", sent, unconfirmedProbeBurst+pathSetupCredit)
	}
	// An hour later: at most two probes per probeRefill, whatever it does.
	sent = 0
	for second := range 3600 {
		at := start.Add(time.Duration(second+1) * time.Second)
		for claim(at) {
			sent++
		}
	}
	if limit := int(2 * time.Hour / probeRefill); sent > limit+unconfirmedProbeBurst+pathSetupCredit {
		t.Fatalf("%d probes in an hour, long-run limit %d", sent, limit)
	}
	// A peer that answers from its own address gets no credit, only tokens.
	peer.confirm(budgetEndpoint(1), start.Add(time.Hour))
	peer.allowance.budget = probeBudget{tokens: 0, credit: pathSetupCredit, refilled: start.Add(time.Hour)}
	if claim(start.Add(time.Hour)) {
		t.Fatal("a peer with an answered candidate spent the path-setup credit")
	}
}

func TestReleasedProbesAreRefunded(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	peer := budgetPeer(now)
	endpoint := budgetEndpoint(41641)
	claimed, ok := peer.claim(endpoint, true, now)
	if !ok {
		t.Fatal("first probe refused")
	}
	peer.release(claimed)
	if peer.allowance.budget.tokens != unconfirmedProbeBurst || !peer.due(endpoint, now) || peer.allowance.probes[endpoint].unanswered != 0 {
		t.Fatalf("after a refund: budget %+v, state %+v", peer.allowance.budget, peer.allowance.probes[endpoint])
	}
}

func TestProbeStatesAreBounded(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	peer := budgetPeer(now)
	for port := range 3 * maxCandidateStates {
		peer.allowance.budget = probeBudget{tokens: unconfirmedProbeBurst, refilled: now}
		claims(peer, budgetEndpoint(1000+port), false, now)
	}
	if len(peer.allowance.probes) > maxCandidateStates {
		t.Fatalf("%d probe states kept, bound %d", len(peer.allowance.probes), maxCandidateStates)
	}
}

func TestAnswersAreSpacedPerPeer(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	peer := budgetPeer(now)
	if !peer.allowAnswer(answerCall, callMeMaybeAnswerSpacing, now) ||
		peer.allowAnswer(answerCall, callMeMaybeAnswerSpacing, now.Add(callMeMaybeAnswerSpacing-time.Millisecond)) {
		t.Fatal("CALL_ME_MAYBE answers are not spaced")
	}
	if !peer.allowAnswer(answerPing, directTrust, now) {
		t.Fatal("a ping answer waited for a CALL_ME_MAYBE answer")
	}
	if !peer.allowAnswer(answerCall, callMeMaybeAnswerSpacing, now.Add(callMeMaybeAnswerSpacing)) {
		t.Fatal("a CALL_ME_MAYBE answer was refused after the spacing")
	}
}

// TestBudgetSurvivesANewDiscoKey plays a Device that reconnects with a new
// disco key to get a fresh budget: the peer ID keeps it.
func TestBudgetSurvivesANewDiscoKey(t *testing.T) {
	t.Parallel()
	_, _, registry, snapshot, generation := testRegistry(t)
	now := time.Unix(1_000, 0)
	peerID := snapshot.Peers[0].ID
	port := 2000
	for {
		port++
		if _, ok := registry.ClaimProbe(peerID, budgetEndpoint(port), false, now); !ok {
			break
		}
	}
	snapshot.Peers[0].DiscoveryKey = MapDiscoveryKey(testIdentity(t).Public())
	snapshot.Revision++
	generation.MapRevision = snapshot.Revision
	if _, err := registry.Replace(snapshot, generation, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.ClaimProbe(peerID, budgetEndpoint(port+1), false, now); ok {
		t.Fatal("a new disco key brought a fresh budget")
	}
}

// TestBudgetSurvivesMapDeactivation follows the daemon, which deactivates
// the probe runtime before activating each new map: the budget stays.
func TestBudgetSurvivesMapDeactivation(t *testing.T) {
	t.Parallel()
	runtime, _, _, _, _, snapshot, generation := testRuntime(t)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	peerID := snapshot.Peers[0].ID
	now := runtime.clock()
	port := 3000
	for {
		port++
		if _, ok := runtime.registry.ClaimProbe(peerID, budgetEndpoint(port), false, now); !ok {
			break
		}
	}
	runtime.Deactivate()
	snapshot.Revision++
	generation.MapRevision = snapshot.Revision
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatal(err)
	}
	if _, ok := runtime.registry.ClaimProbe(peerID, budgetEndpoint(port+1), false, now); ok {
		t.Fatal("a new map after a deactivation brought a fresh budget")
	}
}

// TestBudgetSurvivesLeavingTheMap removes a peer whose budget is spent and
// brings it back: it is not fresh again until it would have refilled.
func TestBudgetSurvivesLeavingTheMap(t *testing.T) {
	t.Parallel()
	_, _, registry, snapshot, generation := testRegistry(t)
	now := time.Unix(1_000, 0)
	peer := snapshot.Peers[0]
	port := 4000
	for {
		port++
		if _, ok := registry.ClaimProbe(peer.ID, budgetEndpoint(port), false, now); !ok {
			break
		}
	}
	replace := func(peers []networkmap.Node, at time.Time) {
		t.Helper()
		snapshot.Peers = peers
		snapshot.Revision++
		generation.MapRevision = snapshot.Revision
		if _, err := registry.Replace(snapshot, generation, at); err != nil {
			t.Fatal(err)
		}
	}
	replace(nil, now)
	replace([]networkmap.Node{peer}, now)
	if _, ok := registry.ClaimProbe(peer.ID, budgetEndpoint(port+1), false, now); ok {
		t.Fatal("leaving and rejoining the map brought a fresh budget")
	}
	// Once it would be full again, it may be forgotten.
	full := now.Add(time.Duration(pathSetupCredit+1) * probeRefill)
	replace(nil, full)
	registry.mu.RLock()
	_, kept := registry.allowances[peer.ID]
	registry.mu.RUnlock()
	if kept {
		t.Fatal("a refilled allowance of a peer outside the map was kept")
	}
}

func TestRenewForgetsAnswersToOtherKeys(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	allowance := newPeerAllowance()
	nodeKey, discoveryKey := key.NodePublic{1}, key.DiscoPublic{2}
	allowance.renew(nodeKey, discoveryKey)
	endpoint := budgetEndpoint(41641)
	allowance.probes[endpoint] = candidateProbes{confirmed: now, unanswered: 2, next: now.Add(time.Minute)}
	allowance.renew(nodeKey, discoveryKey)
	if state := allowance.probes[endpoint]; !state.confirmedAt(now) || !state.next.IsZero() || state.unanswered != 2 {
		t.Fatalf("same keys: %+v, want the answer kept and the wait ended", state)
	}
	allowance.renew(nodeKey, key.DiscoPublic{3})
	if state := allowance.probes[endpoint]; state.confirmedAt(now) || state.unanswered != 2 {
		t.Fatalf("new disco key: %+v, want the answer forgotten and the count kept", state)
	}
}
