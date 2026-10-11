package mapsession

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
)

func testInventory(t *testing.T) appmapsession.NetworkInventory {
	t.Helper()
	scope, err := scopeFromText(testWorkspaceID, testNetworkID)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := appmapsession.NewNetworkInventory(scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	return inventory
}

func TestInventoryCacheReadsOncePerRevisionAcrossConcurrentCallers(t *testing.T) {
	t.Parallel()
	cache := newInventoryCache(30 * time.Second)
	scope, _ := scopeFromText(testWorkspaceID, testNetworkID)
	inventory := testInventory(t)
	var reads atomic.Int32
	release := make(chan struct{})
	read := func(context.Context) (cachedInventory, error) {
		reads.Add(1)
		<-release
		return cachedInventory{revision: 7, readAt: inventoryReadAt, inventory: inventory}, nil
	}
	var wait sync.WaitGroup
	results := make(chan bool, 64)
	for range 64 {
		wait.Go(func() {
			_, found, err := cache.get(t.Context(), scope, 7, inventoryReadAt.Add(time.Second), read)
			results <- found && err == nil
		})
	}
	time.Sleep(20 * time.Millisecond) // let callers pile up behind the reader
	close(release)
	wait.Wait()
	close(results)
	for found := range results {
		if !found {
			t.Fatal("a caller got no inventory")
		}
	}
	if got := reads.Load(); got != 1 {
		t.Fatalf("inventory reads = %d, want 1", got)
	}
}

func TestInventoryCacheNeverServesAnotherRevision(t *testing.T) {
	t.Parallel()
	cache := newInventoryCache(30 * time.Second)
	scope, _ := scopeFromText(testWorkspaceID, testNetworkID)
	inventory := testInventory(t)
	newer := func(context.Context) (cachedInventory, error) {
		return cachedInventory{revision: 9, readAt: inventoryReadAt, inventory: inventory}, nil
	}
	if _, found, err := cache.get(t.Context(), scope, 7, inventoryReadAt, newer); found || err != nil {
		t.Fatalf("a read of revision 7 got revision 9: found=%t err=%v", found, err)
	}
	failing := func(context.Context) (cachedInventory, error) { return cachedInventory{}, errors.New("down") }
	if _, found, _ := cache.get(t.Context(), scope, 7, inventoryReadAt, failing); found {
		t.Fatal("an older revision was served from the cache")
	}
	if _, found, err := cache.get(t.Context(), scope, 9, inventoryReadAt.Add(time.Second), failing); !found || err != nil {
		t.Fatalf("the cached revision 9 was not served: found=%t err=%v", found, err)
	}
}
