package mapsession

import (
	"testing"
	"time"

	"meshtransit.net/core/internal/control"
)

var inventoryReadAt = time.Date(2026, time.September, 14, 4, 0, 0, 0, time.UTC)

// selfCandidateRecord is the authenticated Device as the inventory lists it.
func selfCandidateRecord(record snapshotRecord) peerCandidateRecord {
	return peerCandidateRecord{
		numericNodeID: record.numericNodeID, numericOwnerID: record.numericOwnerID, nodeID: record.nodeID,
		ownerID: "01890f00-0000-7000-8000-000000000011", hostname: record.hostname,
		machineKey: record.machineKey, nodeKey: record.nodeKey, sessionGeneration: record.sessionGeneration,
		createdAt: record.createdAt, keyExpiry: record.keyExpiry, addresses: record.addresses,
		dnsLabel: record.dnsLabel,
	}
}

// sharedStoreFixture is a store with SharedInventory whose fake transaction
// serves one Device read followed by one inventory read.
func sharedStoreFixture(t *testing.T, inventoryRevision int64, listSelf bool) (*Store, *fakeTransaction, control.AuthenticatedNode) {
	t.Helper()
	store, _, transaction, _, identity := validStoreFixture(t)
	record := validSnapshotRecord(t, identity)
	record.readAt = inventoryReadAt
	inventory := []peerCandidateRecord{validPeerCandidateRecord(2), validPeerCandidateRecord(3)}
	if listSelf {
		inventory = append(inventory, selfCandidateRecord(record))
	}
	transaction.rows = []databaseRow{
		scopeRow{workspaceID: testWorkspaceID, networkID: testNetworkID, recoveryEpoch: 2},
		internalScopeRow{workspaceID: 101, networkID: 201},
		snapshotRow{record: record},
		// the inventory read, in its own transaction
		internalScopeRow{workspaceID: 101, networkID: 201},
		inventoryRevisionRow{revision: inventoryRevision, readAt: inventoryReadAt},
		networkHeaderRow{},
		networkSharingRow{},
	}
	transaction.inventoryRows = []*peerCandidateRows{{records: inventory}}
	store.options.SharedInventory = true
	store.options.InventoryStatementTimeout = 30 * time.Second
	store.options.InventoryMaxAge = 30 * time.Second
	store.inventories = newInventoryCache(store.options.InventoryMaxAge)
	return store, transaction, identity
}

func countQueries(queries []string, query string) int {
	count := 0
	for _, candidate := range queries {
		if candidate == query {
			count++
		}
	}
	return count
}

func TestStoreSharesOneInventoryReadPerRevision(t *testing.T) {
	store, transaction, identity := sharedStoreFixture(t, 7, true)
	first, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatalf("first Load() error = %v", err)
	}
	if countQueries(transaction.queries, loadPeerCandidatesSQL) != 0 ||
		countQueries(transaction.queries, loadNetworkDevicesSQL) != 1 {
		t.Fatalf("queries = %v, want one inventory read and no candidate read", transaction.queries)
	}
	candidates := first.PeerCandidates()
	if len(candidates) != 2 {
		t.Fatalf("PeerCandidates() = %d, want the two other Devices", len(candidates))
	}
	for _, candidate := range candidates {
		if candidate.NodeID() == first.NodeID() {
			t.Fatal("self listed among its candidates")
		}
	}
	if len(first.AuthorizedPeers()) != 1 || first.AuthorizedPeers()[0].NodeID().String() != testPeerNodeID {
		t.Fatalf("AuthorizedPeers() = %+v", first.AuthorizedPeers())
	}

	// A second read of the same revision uses the cached inventory.
	record := validSnapshotRecord(t, identity)
	record.readAt = inventoryReadAt.Add(time.Second)
	transaction.rows = []databaseRow{
		scopeRow{workspaceID: testWorkspaceID, networkID: testNetworkID, recoveryEpoch: 2},
		internalScopeRow{workspaceID: 101, networkID: 201},
		snapshotRow{record: record},
	}
	before := countQueries(transaction.queries, loadNetworkDevicesSQL)
	second, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatalf("second Load() error = %v", err)
	}
	if countQueries(transaction.queries, loadNetworkDevicesSQL) != before || len(second.PeerCandidates()) != 2 {
		t.Fatal("the second read of one revision read the inventory again")
	}
}

// TestStoreUsesALaterInventory: the Network moved on between the Device
// read (revision 7) and the inventory read (8); the later inventory, which
// lists the Device unchanged under the same policy, answers without a
// direct candidate read.
func TestStoreUsesALaterInventory(t *testing.T) {
	store, transaction, identity := sharedStoreFixture(t, 8, true)
	snapshot, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	stats := store.InventoryStats()
	if countQueries(transaction.queries, loadPeerCandidatesSQL) != 0 || len(snapshot.AuthorizedPeers()) != 1 ||
		stats.Shared != 1 || stats.Direct != 0 {
		t.Fatalf("queries = %v, stats %+v, want the later inventory", transaction.queries, stats)
	}
}

// TestStoreReadsCandidatesWhenTheInventoryIsOlder: an inventory older than
// the Device read never answers it; the Device reads its candidates.
func TestStoreReadsCandidatesWhenTheInventoryIsOlder(t *testing.T) {
	store, transaction, identity := sharedStoreFixture(t, 6, true)
	// the direct re-read: a fresh Device transaction with its candidate read
	transaction.rows = append(transaction.rows,
		scopeRow{workspaceID: testWorkspaceID, networkID: testNetworkID, recoveryEpoch: 2},
		internalScopeRow{workspaceID: 101, networkID: 201},
		snapshotRow{record: validSnapshotRecord(t, identity)},
	)
	if _, err := store.Load(t.Context(), identity); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if countQueries(transaction.queries, loadPeerCandidatesSQL) != 1 {
		t.Fatalf("queries = %v, want the direct candidate read", transaction.queries)
	}
}

func TestStoreReadsCandidatesWhenTheInventoryOmitsSelf(t *testing.T) {
	store, transaction, identity := sharedStoreFixture(t, 7, false)
	transaction.rows = append(transaction.rows,
		scopeRow{workspaceID: testWorkspaceID, networkID: testNetworkID, recoveryEpoch: 2},
		internalScopeRow{workspaceID: 101, networkID: 201},
		snapshotRow{record: validSnapshotRecord(t, identity)},
	)
	if _, err := store.Load(t.Context(), identity); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if countQueries(transaction.queries, loadPeerCandidatesSQL) != 1 {
		t.Fatalf("queries = %v, want the direct candidate read", transaction.queries)
	}
}

func TestInventoryUsableOnlyForItsRevisionAndWindow(t *testing.T) {
	t.Parallel()
	store, _, _ := sharedStoreFixture(t, 7, true)
	store.database.(*fakeDatabase).transaction.rows = []databaseRow{
		internalScopeRow{workspaceID: 101, networkID: 201},
		inventoryRevisionRow{revision: 7, readAt: inventoryReadAt},
		networkHeaderRow{},
		networkSharingRow{},
	}
	scope, err := scopeFromText(testWorkspaceID, testNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID, cachedInventory{})
	if err != nil {
		t.Fatalf("readInventory() error = %v", err)
	}
	for name, test := range map[string]struct {
		revision int64
		now      time.Time
		want     bool
	}{
		"same revision":         {7, inventoryReadAt.Add(time.Second), true},
		"older revision asked":  {6, inventoryReadAt.Add(time.Second), true},
		"newer revision asked":  {8, inventoryReadAt.Add(time.Second), false},
		"older than the window": {7, inventoryReadAt.Add(31 * time.Second), false},
		"read just after now":   {7, inventoryReadAt.Add(-time.Second), true},
		"read long after now":   {7, inventoryReadAt.Add(-31 * time.Second), false},
		"after a Device expiry": {7, cached.expiresAt, false},
	} {
		if got := cached.usableAt(test.revision, test.now, 30*time.Second); got != test.want {
			t.Errorf("%s: usableAt() = %t, want %t", name, got, test.want)
		}
	}
}

// Shadow phase: a Network policy that disagrees with the Device's own
// policy read is never used; the Device is read directly and counted.
func TestStoreReadsDirectlyWhenTheNetworkPolicyDisagrees(t *testing.T) {
	store, transaction, identity := sharedStoreFixture(t, 7, true)
	transaction.noNetworkRules = true
	transaction.rows = append(transaction.rows,
		scopeRow{workspaceID: testWorkspaceID, networkID: testNetworkID, recoveryEpoch: 2},
		internalScopeRow{workspaceID: 101, networkID: 201},
		snapshotRow{record: validSnapshotRecord(t, identity)},
	)
	snapshot, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	stats := store.InventoryStats()
	if stats.PolicyMismatches != 1 || stats.Shared != 0 || stats.Direct != 1 || len(snapshot.PacketPolicy().Rules()) != 1 {
		t.Fatalf("stats = %+v, rules = %d; want one mismatch read directly", stats, len(snapshot.PacketPolicy().Rules()))
	}
}
