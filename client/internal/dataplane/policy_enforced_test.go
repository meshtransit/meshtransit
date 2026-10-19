package dataplane

import (
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/routedigest"
)

func TestPolicyFilterDigestsTheRulesItEnforces(t *testing.T) {
	now := time.Date(2026, time.October, 9, 12, 0, 0, 0, time.UTC)
	filter := newPolicyFilter()
	filter.clock = func() time.Time { return now }
	if _, known := filter.Enforced(); known {
		t.Fatal("a filter that installed nothing reported a digest")
	}

	snapshot := testPolicySnapshot()
	second := testPolicySnapshot().Policy[0]
	second.Destinations = append([]networkmap.Destination(nil), second.Destinations...)
	second.Destinations[0].PortFrom, second.Destinations[0].PortTo = 22, 22
	snapshot.Policy = append(snapshot.Policy, second)
	want, wantGrants, err := networkmap.PolicyDigest(snapshot.Policy)
	if err != nil {
		t.Fatal(err)
	}
	filter.UpdateNetwork(snapshot)
	enforced, known := filter.Enforced()
	if !known || enforced.Digest != want || enforced.Grants != wantGrants || !enforced.AppliedAt.Equal(now) {
		t.Fatalf("enforced = %+v, want %s (%d)", enforced, want, wantGrants)
	}

	// The same rules again keep the original time they were applied.
	now = now.Add(time.Minute)
	filter.UpdateNetwork(snapshot)
	if again, _ := filter.Enforced(); again != enforced {
		t.Fatalf("unchanged rules moved the enforcement record: %+v", again)
	}

	// The drift test drops the last rule, so the digest no longer matches.
	filter.setDropLastRule(true)
	filter.UpdateNetwork(snapshot)
	drifted, _ := filter.Enforced()
	partial, _, _ := networkmap.PolicyDigest(snapshot.Policy[:1])
	if drifted.Digest != partial || drifted.Digest == want || !drifted.AppliedAt.Equal(now) {
		t.Fatalf("drifted = %+v, want the digest of the first rule only", drifted)
	}

	// Failing closed installs no rules, and the digest says so.
	filter.setDropLastRule(false)
	filter.UpdateNetwork(networkmap.Snapshot{})
	empty, _, _ := networkmap.PolicyDigest(nil)
	if closed, _ := filter.Enforced(); closed.Digest != empty {
		t.Fatalf("fail-closed digest = %s, want the empty filter %s", closed.Digest, empty)
	}
}

func TestEnforcedReportsTheEmptyRouteDigestBeforeAnyRouteIsServed(t *testing.T) {
	t.Parallel()
	filter := newPolicyFilter()
	filter.UpdateNetwork(testPolicySnapshot())
	enforced, known := filter.Enforced()
	empty, _, _ := routedigest.Compute(nil)
	if !known || enforced.RouteDigest != empty || enforced.RouteEntries != 0 {
		t.Fatalf("Enforced() = %+v, %t; want the empty set's route digest", enforced, known)
	}
}
