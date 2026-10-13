package mapsession

import (
	"testing"

	"meshtransit.net/core/internal/control"
)

// shareSkipFixture is a shared-inventory store whose database tells whether
// the Network holds legacy direct endpoints (schema 154), with the rows of
// a first Load: the Device read and an inventory of revision 7 in which no
// share binds the Device and, unless direct, no direct endpoint exists.
func shareSkipFixture(t *testing.T, direct bool) (*Store, *fakeTransaction, control.AuthenticatedNode, snapshotRecord) {
	t.Helper()
	store, transaction, identity := sharedStoreFixture(t, 7, true)
	transaction.directEndpointReader = true
	record := validSnapshotRecord(t, identity)
	record.readAt = inventoryReadAt
	transaction.rows = []databaseRow{
		scopeRow{workspaceID: testWorkspaceID, networkID: testNetworkID, recoveryEpoch: 2},
		internalScopeRow{workspaceID: 101, networkID: 201},
		snapshotRow{record: record},
		internalScopeRow{workspaceID: 101, networkID: 201},
		inventoryRevisionRow{revision: 7, readAt: inventoryReadAt},
		networkHeaderRow{},
		networkSharingRow{},
		directEndpointsRow{present: direct},
	}
	return store, transaction, identity, record
}

func queueDeviceRead(transaction *fakeTransaction, record snapshotRecord) {
	transaction.rows = append(transaction.rows,
		scopeRow{workspaceID: testWorkspaceID, networkID: testNetworkID, recoveryEpoch: 2},
		internalScopeRow{workspaceID: 101, networkID: 201},
		snapshotRow{record: record},
	)
}

func TestStoreSkipsShareReadersForADeviceWithoutShares(t *testing.T) {
	store, transaction, identity, record := shareSkipFixture(t, false)
	if _, err := store.Load(t.Context(), identity); err != nil {
		t.Fatalf("first Load() error = %v", err)
	}
	if countQueries(transaction.queries, loadDirectEdgesSQL) != 1 {
		t.Fatalf("queries = %v, want the share readers on the first read (no inventory yet)", transaction.queries)
	}
	queueDeviceRead(transaction, record)
	snapshot, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatalf("second Load() error = %v", err)
	}
	stats := store.InventoryStats()
	if countQueries(transaction.queries, loadDirectEdgesSQL) != 1 || stats.SharesSkipped != 1 || stats.ShareRechecks != 0 ||
		stats.Shared != 2 || len(snapshot.PeerCandidates()) != 2 {
		t.Fatalf("stats %+v, queries %v: want the second read without share readers", stats, transaction.queries)
	}
}

func TestStoreKeepsShareReadersWhileDirectEndpointsRemain(t *testing.T) {
	store, transaction, identity, record := shareSkipFixture(t, true)
	if _, err := store.Load(t.Context(), identity); err != nil {
		t.Fatal(err)
	}
	queueDeviceRead(transaction, record)
	if _, err := store.Load(t.Context(), identity); err != nil {
		t.Fatal(err)
	}
	if countQueries(transaction.queries, loadDirectEdgesSQL) != 2 || store.InventoryStats().SharesSkipped != 0 {
		t.Fatalf("a Network with direct endpoints skipped the share readers: %v", transaction.queries)
	}
}

// TestStoreRereadsADeviceWhoseInventoryShowsAShare: the cached inventory
// (revision 7) shows no share, so the read of revision 8 skips the share
// readers; the inventory of revision 8 it is completed with shows a share
// binding the Device, so the Device is read again with its shares.
func TestStoreRereadsADeviceWhoseInventoryShowsAShare(t *testing.T) {
	store, transaction, identity, record := shareSkipFixture(t, false)
	if _, err := store.Load(t.Context(), identity); err != nil {
		t.Fatal(err)
	}
	newer := record
	newer.networkRevision = 8
	queueDeviceRead(transaction, newer)
	transaction.rows = append(transaction.rows,
		internalScopeRow{workspaceID: 101, networkID: 201},
		inventoryRevisionRow{revision: 8, readAt: inventoryReadAt},
		networkHeaderRow{},
		networkSharingRow{devices: []int64{record.numericNodeID}},
		directEndpointsRow{present: false},
	)
	transaction.inventoryRows = append(transaction.inventoryRows, &peerCandidateRows{records: []peerCandidateRecord{
		validPeerCandidateRecord(2), validPeerCandidateRecord(3), selfCandidateRecord(newer)}})
	queueDeviceRead(transaction, newer) // the direct re-read
	if _, err := store.Load(t.Context(), identity); err != nil {
		t.Fatalf("second Load() error = %v", err)
	}
	stats := store.InventoryStats()
	if stats.SharesSkipped != 1 || stats.ShareRechecks != 1 || stats.Direct != 1 ||
		countQueries(transaction.queries, loadDirectEdgesSQL) != 2 {
		t.Fatalf("stats %+v, queries %v: want the Device read again with its shares", stats, transaction.queries)
	}
}
