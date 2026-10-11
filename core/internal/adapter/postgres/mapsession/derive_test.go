package mapsession

import (
	"reflect"
	"testing"
	"time"
)

// liveStoreFixture is sharedStoreFixture with every time around now, so the
// view is fresh for Derive.
func liveStoreFixture(t *testing.T) (*Store, *fakeTransaction, snapshotRecord) {
	t.Helper()
	store, transaction, identity := sharedStoreFixture(t, 7, true)
	now := time.Now().UTC().Truncate(time.Millisecond)
	record := validSnapshotRecord(t, identity)
	record.createdAt, record.keyExpiry, record.readAt = now.Add(-time.Hour), now.Add(24*time.Hour), now
	peers := []peerCandidateRecord{validPeerCandidateRecord(2), validPeerCandidateRecord(3), selfCandidateRecord(record)}
	for index := range peers[:2] {
		peers[index].createdAt, peers[index].keyExpiry = now.Add(-time.Hour), now.Add(24*time.Hour)
	}
	transaction.rows = []databaseRow{
		scopeRow{workspaceID: testWorkspaceID, networkID: testNetworkID, recoveryEpoch: 2},
		internalScopeRow{workspaceID: 101, networkID: 201},
		snapshotRow{record: record},
		internalScopeRow{workspaceID: 101, networkID: 201},
		inventoryRevisionRow{revision: 7, readAt: now},
		networkHeaderRow{},
	}
	transaction.inventoryRows = []*peerCandidateRows{{records: peers}}
	transaction.policyExpiry = now.Add(24 * time.Hour)
	return store, transaction, record
}

func TestDeriveRefreshesFromTheSharedViewWithoutReading(t *testing.T) {
	store, transaction, record := liveStoreFixture(t)
	identity := validIdentity(t)
	loaded, err := store.Load(t.Context(), identity)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if store.InventoryStats().Shared != 1 {
		t.Fatalf("stats = %+v, want a shared load", store.InventoryStats())
	}
	queries := len(transaction.queries)
	derived, found, err := store.Derive(t.Context(), loaded, record.networkRevision)
	if err != nil || !found {
		t.Fatalf("Derive() = %t, %v", found, err)
	}
	if len(transaction.queries) != queries {
		t.Fatalf("Derive() ran %v", transaction.queries[queries:])
	}
	if derived.NetworkRevision() != loaded.NetworkRevision() || derived.RecoveryEpoch() != loaded.RecoveryEpoch() ||
		derived.NetworkName() != loaded.NetworkName() || derived.Hostname() != loaded.Hostname() ||
		!derived.KeyExpiry().Equal(loaded.KeyExpiry()) || !derived.PacketPolicy().Equal(loaded.PacketPolicy()) ||
		!reflect.DeepEqual(derived.PeerCandidates(), loaded.PeerCandidates()) ||
		!reflect.DeepEqual(derived.AuthorizedPeers(), loaded.AuthorizedPeers()) ||
		!reflect.DeepEqual(derived.Addresses(), loaded.Addresses()) {
		t.Fatalf("derived snapshot differs from the loaded one")
	}
	if store.InventoryStats().Derived != 1 {
		t.Fatalf("stats = %+v, want one derived", store.InventoryStats())
	}
}

func TestDeriveDeclinesWhatTheViewCannotAnswer(t *testing.T) {
	store, _, record := liveStoreFixture(t)
	loaded, err := store.Load(t.Context(), validIdentity(t))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// A newer revision than the view holds, with no newer view readable.
	if _, found, _ := store.Derive(t.Context(), loaded, record.networkRevision+1); found {
		t.Fatal("Derive() answered a revision the view does not reach")
	}
	store.inventories = nil // as with SharedInventory off
	if _, found, err := store.Derive(t.Context(), loaded, 0); found || err != nil {
		t.Fatalf("Derive() without a shared view = %t, %v", found, err)
	}
}
