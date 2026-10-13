package mapsession

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

// changeTrackingStore is a store whose database tracks inventory changes
// (schema 153), with its fake transaction and the Network's scope.
func changeTrackingStore(t *testing.T) (*Store, *fakeTransaction, network.Scope) {
	t.Helper()
	store, _, _ := sharedStoreFixture(t, 7, true)
	transaction := store.database.(*fakeDatabase).transaction
	transaction.inventoryChanges = true
	transaction.rows, transaction.inventoryRows = nil, nil
	scope, err := scopeFromText(testWorkspaceID, testNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	return store, transaction, scope
}

// queueInventoryRead queues the rows of one inventory read at revision and
// change counter head; header false leaves the Network unable to serve maps.
func queueInventoryRead(transaction *fakeTransaction, revision, head int64, header bool) {
	var headerRow databaseRow = networkHeaderRow{}
	if !header {
		headerRow = errorRow{err: pgx.ErrNoRows}
	}
	transaction.rows = append(transaction.rows,
		internalScopeRow{workspaceID: 101, networkID: 201},
		inventoryRevisionRow{revision: revision, readAt: inventoryReadAt},
		headerRow,
		networkSharingRow{},
		changeHeadRow{head: head},
	)
}

func inventoryNodeIDs(t *testing.T, cached cachedInventory, markers ...byte) {
	t.Helper()
	if cached.inventory.Len() != len(markers) {
		t.Fatalf("inventory lists %d Devices, want %d", cached.inventory.Len(), len(markers))
	}
	for _, marker := range markers {
		nodeID, err := node.ParseID(validPeerCandidateRecord(marker).nodeID)
		if err != nil {
			t.Fatal(err)
		}
		if _, found := cached.inventory.Device(nodeID); !found {
			t.Fatalf("Device %d is not listed", marker)
		}
	}
}

func TestInventoryAppliesTheDevicesChangedSinceTheCachedRead(t *testing.T) {
	t.Parallel()
	store, transaction, scope := changeTrackingStore(t)
	queueInventoryRead(transaction, 7, 10, true)
	transaction.inventoryRows = []*peerCandidateRows{{records: []peerCandidateRecord{
		validPeerCandidateRecord(2), validPeerCandidateRecord(3)}}}
	first, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID, cachedInventory{})
	if err != nil {
		t.Fatalf("first readInventory() error = %v", err)
	}
	if first.changeSeq != 10 || first.fullReadAt.IsZero() {
		t.Fatalf("first read: change counter %d, full read at %v", first.changeSeq, first.fullReadAt)
	}
	queueInventoryRead(transaction, 8, 12, true)
	transaction.changeRows = []*inventoryChangeRows{{changes: []inventoryChange{
		{seq: 11, record: validPeerCandidateRecord(4)},
		{seq: 12, removed: validPeerCandidateRecord(2).numericNodeID},
	}}}
	second, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID, first)
	if err != nil {
		t.Fatalf("second readInventory() error = %v", err)
	}
	inventoryNodeIDs(t, second, 3, 4)
	if countQueries(transaction.queries, loadNetworkDevicesSQL) != 1 ||
		countQueries(transaction.queries, loadNetworkDeviceChangesSQL) != 1 {
		t.Fatalf("queries = %v, want one whole read and one change read", transaction.queries)
	}
	if second.changeSeq != 12 || !second.fullReadAt.Equal(first.fullReadAt) || second.revision != 8 ||
		store.InventoryStats().ChangeReads != 1 {
		t.Fatalf("second read: counter %d, revision %d, change reads %d", second.changeSeq, second.revision,
			store.InventoryStats().ChangeReads)
	}
	// Nothing changed since: no change read, and the very same inventory.
	queueInventoryRead(transaction, 9, 12, true)
	third, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID, second)
	if err != nil || !third.inventory.Same(second.inventory) ||
		countQueries(transaction.queries, loadNetworkDeviceChangesSQL) != 1 {
		t.Fatalf("an unchanged Network was read again or rebuilt (err %v)", err)
	}
}

func TestInventoryIsReadWholeWhenChangesCannotApply(t *testing.T) {
	t.Parallel()
	tooMany := make([]inventoryChange, maximumInventoryChanges+1)
	for index := range tooMany {
		tooMany[index] = inventoryChange{seq: 11, removed: int64(100_000 + index)}
	}
	for name, test := range map[string]struct {
		untracked bool
		head      int64
		header    bool
		changes   []inventoryChange
		stale     bool
	}{
		"untracked database":     {untracked: true, head: 11, header: true},
		"counter went back":      {head: 9, header: true},
		"network stopped":        {head: 11, header: false},
		"too many changes":       {head: 11, header: true, changes: tooMany},
		"whole read is too old":  {head: 11, header: true, stale: true},
		"change makes duplicate": {head: 11, header: true, changes: duplicateKeyChange()},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, transaction, scope := changeTrackingStore(t)
			queueInventoryRead(transaction, 7, 10, true)
			transaction.inventoryRows = []*peerCandidateRows{
				{records: []peerCandidateRecord{validPeerCandidateRecord(2), validPeerCandidateRecord(3)}},
				{records: []peerCandidateRecord{validPeerCandidateRecord(3)}},
			}
			first, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID, cachedInventory{})
			if err != nil {
				t.Fatal(err)
			}
			if test.stale {
				first.fullReadAt = time.Now().Add(-inventoryFullReadInterval)
			}
			transaction.inventoryChanges = !test.untracked
			if test.untracked {
				transaction.rows = append(transaction.rows,
					internalScopeRow{workspaceID: 101, networkID: 201},
					inventoryRevisionRow{revision: 8, readAt: inventoryReadAt},
					networkHeaderRow{}, networkSharingRow{})
			} else {
				queueInventoryRead(transaction, 8, test.head, test.header)
			}
			if test.changes != nil {
				transaction.changeRows = []*inventoryChangeRows{{changes: test.changes}}
			}
			second, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID, first)
			if err != nil {
				t.Fatalf("readInventory() error = %v", err)
			}
			inventoryNodeIDs(t, second, 3)
			if countQueries(transaction.queries, loadNetworkDevicesSQL) != 2 || store.InventoryStats().ChangeReads != 0 {
				t.Fatalf("queries = %v, want the Network read whole again", transaction.queries)
			}
			if test.untracked && second.changeSeq != -1 {
				t.Fatalf("an untracked read kept change counter %d", second.changeSeq)
			}
		})
	}
}

// duplicateKeyChange lists a new Device with Device 3's node key, which no
// inventory can hold.
func duplicateKeyChange() []inventoryChange {
	duplicate := validPeerCandidateRecord(4)
	duplicate.nodeKey = validPeerCandidateRecord(3).nodeKey
	return []inventoryChange{{seq: 11, record: duplicate}}
}

func TestInventoryRejectsAChangeOutsideTheSnapshot(t *testing.T) {
	t.Parallel()
	store, transaction, scope := changeTrackingStore(t)
	queueInventoryRead(transaction, 7, 10, true)
	transaction.inventoryRows = []*peerCandidateRows{{records: []peerCandidateRecord{validPeerCandidateRecord(2)}}}
	first, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID, cachedInventory{})
	if err != nil {
		t.Fatal(err)
	}
	for _, seq := range []int64{10, 12} { // not after the cached counter, or past this snapshot's head
		queueInventoryRead(transaction, 8, 11, true)
		transaction.changeRows = []*inventoryChangeRows{{changes: []inventoryChange{{seq: seq, record: validPeerCandidateRecord(4)}}}}
		if _, err := store.readInventory(t.Context(), scope, testWorkspaceID, testNetworkID, first); err == nil {
			t.Fatalf("a change numbered %d was accepted", seq)
		}
	}
}
