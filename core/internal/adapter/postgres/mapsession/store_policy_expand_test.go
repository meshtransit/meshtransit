package mapsession

import (
	"testing"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
)

// A shared read of a Device no share binds, once an inventory of its policy
// revision is cached, expands that Network policy instead of reading the
// Device's own: the policy equals what the read returned before.
func TestStoreExpandsThePolicyOfADeviceWithoutShares(t *testing.T) {
	store, transaction, identity, record := shareSkipFixture(t, false)
	first, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatalf("first Load() error = %v", err)
	}
	if countQueries(transaction.queries, loadPacketPolicySQL) != 1 {
		t.Fatalf("queries = %v, want the policy read without a cached inventory", transaction.queries)
	}
	queueDeviceRead(transaction, record)
	second, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatalf("second Load() error = %v", err)
	}
	stats := store.InventoryStats()
	if countQueries(transaction.queries, loadPacketPolicySQL) != 1 || stats.PoliciesExpanded != 1 ||
		stats.PolicyMismatches != 0 || stats.Shared != 2 {
		t.Fatalf("stats %+v, queries %v: want the second policy expanded", stats, transaction.queries)
	}
	if !second.PacketPolicy().Equal(first.PacketPolicy()) || len(second.PacketPolicy().Rules()) != 1 {
		t.Fatalf("expanded policy %+v, read policy %+v", second.PacketPolicy(), first.PacketPolicy())
	}
	if len(second.AuthorizedPeers()) != len(first.AuthorizedPeers()) {
		t.Fatalf("authorized peers %d, want %d", len(second.AuthorizedPeers()), len(first.AuthorizedPeers()))
	}
}

// One in policyShadowInterval reads that could expand the policy reads it
// as well and compares.
func TestStoreKeepsShadowPolicyChecks(t *testing.T) {
	store, transaction, identity, record := shareSkipFixture(t, false)
	if _, err := store.Load(t.Context(), identity); err != nil {
		t.Fatal(err)
	}
	for range policyShadowInterval {
		queueDeviceRead(transaction, record)
		if _, err := store.Load(t.Context(), identity); err != nil {
			t.Fatal(err)
		}
	}
	stats := store.InventoryStats()
	if reads := countQueries(transaction.queries, loadPacketPolicySQL); reads != 2 ||
		stats.PolicyShadowChecks != 1 || stats.PoliciesExpanded != policyShadowInterval-1 || stats.PolicyMismatches != 0 {
		t.Fatalf("stats %+v, %d policy reads: want one shadow check in %d", stats, reads, policyShadowInterval)
	}
}

// A Device a share binds keeps its own policy read: its map has direct
// projections the Network policy does not describe.
func TestStoreReadsThePolicyOfADeviceWithShares(t *testing.T) {
	store, transaction, identity, record := shareSkipFixtureBinding(t, false, []int64{701})
	store.options.EnableDeviceAliases = true
	transaction.keyedReaders = true
	if _, err := store.Load(t.Context(), identity); err != nil {
		t.Fatal(err)
	}
	queueDeviceRead(transaction, record)
	if _, err := store.Load(t.Context(), identity); err != nil {
		t.Fatalf("second Load() error = %v", err)
	}
	if reads := countQueries(transaction.queries, loadPacketPolicySQL); reads != 2 ||
		store.InventoryStats().PoliciesExpanded != 0 {
		t.Fatalf("%d policy reads, stats %+v: want the Device's own read", reads, store.InventoryStats())
	}
}

// The policy is deferred only for the cached policy revision, and completed
// only with an inventory of the read's policy revision.
func TestStoreDefersThePolicyOnlyForItsRevision(t *testing.T) {
	store, _, identity, record := shareSkipFixture(t, false)
	if _, err := store.Load(t.Context(), identity); err != nil {
		t.Fatal(err)
	}
	cached, found := store.inventories.peek(sharedTestScope(t))
	if !found || !cached.policy.IsValid() {
		t.Fatal("no cached inventory with a policy")
	}
	revision := cached.policy.Revision()
	if store.deferPolicy(cached, revision+1) {
		t.Fatal("deferred the policy of another revision")
	}
	placeholder, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: sharedTestScope(t), Revision: revision + 1, Rules: []policy.Rule{},
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := record.snapshot(testWorkspaceID, testNetworkID, 2, nil, placeholder,
		store.relayDirectory(sharedTestScope(t).NetworkID()))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.withExpandedPolicy(cached, snapshotRead{snapshot: snapshot, readAt: record.readAt,
		policyDeferred: true}); ok || err != nil {
		t.Fatalf("completed a read of policy revision %d with an inventory of %d: ok=%t err=%v",
			revision+1, revision, ok, err)
	}
}

func sharedTestScope(t *testing.T) network.Scope {
	t.Helper()
	scope, err := scopeFromText(testWorkspaceID, testNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
