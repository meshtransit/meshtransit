package mapsession

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
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

// TestInventoryCacheServesTheRevisionOrALaterOne: a read of revision 7 may
// be answered by the inventory of 9 (the Network moved on); an inventory
// older than the read is never served.
func TestInventoryCacheServesTheRevisionOrALaterOne(t *testing.T) {
	t.Parallel()
	cache := newInventoryCache(30 * time.Second)
	scope, _ := scopeFromText(testWorkspaceID, testNetworkID)
	inventory := testInventory(t)
	newer := func(context.Context) (cachedInventory, error) {
		return cachedInventory{revision: 9, readAt: inventoryReadAt, inventory: inventory}, nil
	}
	if cached, found, err := cache.get(t.Context(), scope, 7, inventoryReadAt, newer); !found || err != nil || cached.revision != 9 {
		t.Fatalf("a read of revision 7 did not get the later 9: found=%t err=%v", found, err)
	}
	failing := func(context.Context) (cachedInventory, error) { return cachedInventory{}, errors.New("down") }
	if cached, found, err := cache.get(t.Context(), scope, 9, inventoryReadAt.Add(time.Second), failing); !found || err != nil ||
		cached.revision != 9 {
		t.Fatalf("the cached revision 9 was not served: found=%t err=%v", found, err)
	}
	if _, found, _ := cache.get(t.Context(), scope, 10, inventoryReadAt.Add(time.Second), failing); found {
		t.Fatal("an older inventory (9) was served for a read of 10")
	}
}

func TestKeepIdenticalReusesAnUnchangedReread(t *testing.T) {
	t.Parallel()
	scope, _ := scopeFromText(testWorkspaceID, testNetworkID)
	policyOf := func() appmapsession.NetworkPolicy {
		policy, err := appmapsession.NewNetworkPolicy(appmapsession.NetworkPolicyParams{Scope: scope, Revision: 1})
		if err != nil {
			t.Fatal(err)
		}
		return policy
	}
	previous := cachedInventory{revision: 7, readAt: inventoryReadAt, inventory: testInventory(t), policy: policyOf(),
		serveable: true, recoveryEpoch: 2}
	reread := previous
	reread.readAt = inventoryReadAt.Add(30 * time.Second)
	reread.inventory, reread.policy = testInventory(t), policyOf()
	kept := keepIdentical(previous, reread)
	if !kept.inventory.Same(previous.inventory) || !kept.readAt.Equal(reread.readAt) {
		t.Fatal("an identical reread did not keep the previous objects with its new read time")
	}
	moved := reread
	moved.revision = 8
	if keepIdentical(previous, moved).inventory.Same(previous.inventory) {
		t.Fatal("a new revision kept the previous inventory")
	}
	suspended := reread
	suspended.serveable = false
	if keepIdentical(previous, suspended).inventory.Same(previous.inventory) {
		t.Fatal("a Network that stopped serving kept the previous view")
	}
}

// TestInventoryCacheCallerJoinsTheNextReadAfterAStaleOne: B (revision 7)
// waits on a read of 5 begun before 7 existed; whether B then reads itself or
// joins C's next read, it gets an inventory of 7 or later, never falls back
// to its own Network read beside C's, and the Network is read twice in all.
func TestInventoryCacheCallerJoinsTheNextReadAfterAStaleOne(t *testing.T) {
	t.Parallel()
	for range 50 {
		synctest.Test(t, func(t *testing.T) {
			cache := newInventoryCache(30 * time.Second)
			scope, _ := scopeFromText(testWorkspaceID, testNetworkID)
			inventory := testInventory(t)
			var reads atomic.Int32
			reader := func(revision int64, release <-chan struct{}) inventoryReader {
				return func(context.Context) (cachedInventory, error) {
					reads.Add(1)
					<-release
					return cachedInventory{revision: revision, readAt: inventoryReadAt, inventory: inventory}, nil
				}
			}
			stale, next := make(chan struct{}), make(chan struct{})
			go func() { _, _, _ = cache.get(t.Context(), scope, 5, inventoryReadAt, reader(5, stale)) }()
			synctest.Wait()
			got := make(chan cachedInventory, 2)
			for _, revision := range []int64{7, 6} {
				go func() {
					cached, found, err := cache.get(t.Context(), scope, revision, inventoryReadAt, reader(9, next))
					if !found || err != nil {
						t.Errorf("a read of revision %d found no inventory: found=%t err=%v", revision, found, err)
					}
					got <- cached
				}()
			}
			synctest.Wait()
			close(stale)
			synctest.Wait() // one of B and C reads, the other waits on it
			close(next)
			for range 2 {
				if cached := <-got; cached.revision != 9 {
					t.Fatalf("got revision %d, want the next read (9)", cached.revision)
				}
			}
			if n := reads.Load(); n != 2 {
				t.Fatalf("inventory reads = %d, want 2", n)
			}
		})
	}
}
