package mapsession

import (
	"context"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

// hubStoreFixture is Redis: one value per Node, answered per exact
// generation.
type hubStoreFixture struct {
	mu     sync.Mutex
	values map[node.ID]Connectivity
	reads  [][]ConnectivityKey
}

func (store *hubStoreFixture) LoadConnectivity(_ context.Context, keys []ConnectivityKey) ([]Connectivity, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.reads = append(store.reads, slices.Clone(keys))
	values := make([]Connectivity, len(keys))
	for index, key := range keys {
		if stored, found := store.values[key.nodeID]; found && stored.key == key {
			values[index] = stored
		} else {
			values[index] = Connectivity{key: key}
		}
	}
	return values, nil
}

func (store *hubStoreFixture) put(value Connectivity) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.values[value.key.nodeID] = value
}

func (store *hubStoreFixture) readCount() (int, int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	keys := 0
	for _, read := range store.reads {
		keys += len(read)
	}
	return len(store.reads), keys
}

// hubWatcherFixture is the process feed: one buffered mailbox per Network.
type hubWatcherFixture struct {
	mu       sync.Mutex
	channels map[network.ID]chan ConnectivityChanged
	releases int
}

func (watcher *hubWatcherFixture) WatchNetwork(id network.ID) (<-chan ConnectivityChanged, func(), error) {
	return watcher.WatchNetworkBuffered(id, 1)
}

func (watcher *hubWatcherFixture) WatchNetworkBuffered(id network.ID, capacity int) (<-chan ConnectivityChanged, func(), error) {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()
	updates := make(chan ConnectivityChanged, capacity)
	watcher.channels[id] = updates
	return updates, func() {
		watcher.mu.Lock()
		defer watcher.mu.Unlock()
		watcher.releases++
	}, nil
}

func (watcher *hubWatcherFixture) send(t *testing.T, change ConnectivityChanged) {
	t.Helper()
	watcher.mu.Lock()
	updates := watcher.channels[change.NetworkID()]
	watcher.mu.Unlock()
	updates <- change
}

func newHubFixture(t *testing.T) (*ConnectivityHub, *hubStoreFixture, *hubWatcherFixture, network.ID) {
	t.Helper()
	store := &hubStoreFixture{values: make(map[node.ID]Connectivity)}
	watcher := &hubWatcherFixture{channels: make(map[network.ID]chan ConnectivityChanged)}
	hub, err := NewConnectivityHub(store, watcher, ConnectivityHubOptions{
		ResyncInterval: 30 * time.Second, ReadTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewConnectivityHub() error = %v", err)
	}
	return hub, store, watcher, snapshotFixture(t).Scope().NetworkID()
}

func hubKey(t testing.TB, index uint64, generation int64) ConnectivityKey {
	t.Helper()
	key, err := NewConnectivityKey(connectivityMapNodeID(t, index), generation)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func hubWake(t *testing.T, networkID network.ID, key ConnectivityKey) ConnectivityChanged {
	t.Helper()
	change, err := NewConnectivityChanged(networkID, key.nodeID, key.generation, ConnectivityChangePresence)
	if err != nil {
		t.Fatal(err)
	}
	return change
}

func TestConnectivityHubReadsAWakeupOncePerReplica(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub, store, watcher, networkID := newHubFixture(t)
		first, releaseFirst, err := hub.WatchNetwork(networkID)
		if err != nil {
			t.Fatal(err)
		}
		second, releaseSecond, err := hub.WatchNetwork(networkID)
		if err != nil {
			t.Fatal(err)
		}
		keys := []ConnectivityKey{hubKey(t, 1, 1), hubKey(t, 2, 1), hubKey(t, 3, 1)}
		before, err := hub.view(t.Context(), networkID, keys)
		if err != nil || before.table == nil {
			t.Fatalf("view() = %+v, %v", before, err)
		}

		store.put(connectivityMapValue(t, keys[1].nodeID, 1, true))
		watcher.send(t, hubWake(t, networkID, keys[1]))
		synctest.Wait()

		if reads, readKeys := store.readCount(); reads != 2 || readKeys != 4 {
			t.Fatalf("Redis reads = %d (%d keys), want the view's 3 keys then the woken Node once", reads, readKeys)
		}
		for name, updates := range map[string]<-chan ConnectivityChanged{"first": first, "second": second} {
			wake := <-updates
			if !wake.batched || wake.NetworkID() != networkID {
				t.Fatalf("%s stream wake = %+v", name, wake)
			}
		}
		after, err := hub.view(t.Context(), networkID, keys)
		if err != nil {
			t.Fatal(err)
		}
		if !after.lookup(keys[1]).Online() || before.lookup(keys[1]).Online() {
			t.Fatal("the new version must show the change and the old one must not")
		}
		changed, ok := before.changesTo(after)
		if !ok || !slices.Equal(changed, []node.ID{keys[1].nodeID}) {
			t.Fatalf("changesTo() = %v, %t", changed, ok)
		}
		if reads, _ := store.readCount(); reads != 2 {
			t.Fatalf("a view the table can answer read Redis again (%d reads)", reads)
		}

		releaseFirst()
		releaseSecond()
		synctest.Wait()
		if watcher.releases != 1 || hub.Stats().Networks != 0 {
			t.Fatalf("releases = %d, networks = %d after the last stream left", watcher.releases, hub.Stats().Networks)
		}
	})
}

func TestConnectivityHubAnswersGenerationsAsRedisWould(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub, store, _, networkID := newHubFixture(t)
		_, release, err := hub.WatchNetwork(networkID)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		store.put(connectivityMapValue(t, connectivityMapNodeID(t, 1), 2, true))
		current, err := hub.view(t.Context(), networkID, []ConnectivityKey{hubKey(t, 1, 2)})
		if err != nil {
			t.Fatal(err)
		}
		// An older generation is offline without endpoints, read nothing.
		if value := current.lookup(hubKey(t, 1, 1)); value.Online() || value.Key() != hubKey(t, 1, 1) {
			t.Fatalf("older generation = %+v", value)
		}
		if missing := missingConnectivity(current, []ConnectivityKey{hubKey(t, 1, 1)}); len(missing) != 0 {
			t.Fatalf("older generation counted as missing: %v", missing)
		}
		// A newer generation than the table holds is read.
		if missing := missingConnectivity(current, []ConnectivityKey{hubKey(t, 1, 3)}); len(missing) != 1 {
			t.Fatalf("newer generation not read: %v", missing)
		}
	})
}

func TestConnectivityHubDoesNotLetAnOpenReadReplaceNewerState(t *testing.T) {
	hub, _, _, networkID := newHubFixture(t)
	_, release, err := hub.WatchNetwork(networkID)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	table := hub.networks[networkID]
	online := connectivityMapValue(t, connectivityMapNodeID(t, 1), 1, true)
	offline := connectivityMapValue(t, connectivityMapNodeID(t, 1), 1, false)
	table.apply([]Connectivity{online}, true)
	if version := table.apply([]Connectivity{offline}, false); !version.lookup(online.key).Online() {
		t.Fatal("a fill-only apply replaced a stored value")
	}
	if version := table.apply([]Connectivity{offline}, true); version.lookup(online.key).Online() {
		t.Fatal("the worker's apply did not replace the stored value")
	}
}

func TestConnectivityHubResyncRepairsALostWakeup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub, store, _, networkID := newHubFixture(t)
		updates, release, err := hub.WatchNetwork(networkID)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		key := hubKey(t, 1, 1)
		if _, err := hub.view(t.Context(), networkID, []ConnectivityKey{key}); err != nil {
			t.Fatal(err)
		}
		store.put(connectivityMapValue(t, key.nodeID, 1, true)) // no wakeup
		time.Sleep(31 * time.Second)
		synctest.Wait()
		if wake := <-updates; !wake.batched {
			t.Fatalf("resync wake = %+v", wake)
		}
		current, _ := hub.view(t.Context(), networkID, []ConnectivityKey{key})
		if !current.lookup(key).Online() {
			t.Fatal("resync did not repair the table")
		}
	})
}

func TestConnectivityHubEndsStreamsWhenTheFeedEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub, _, watcher, networkID := newHubFixture(t)
		updates, release, err := hub.WatchNetwork(networkID)
		if err != nil {
			t.Fatal(err)
		}
		watcher.mu.Lock()
		close(watcher.channels[networkID])
		watcher.mu.Unlock()
		synctest.Wait()
		if _, open := <-updates; open {
			t.Fatal("stream mailbox stayed open after the feed ended")
		}
		release()
		if watcher.releases != 1 {
			t.Fatalf("releases = %d", watcher.releases)
		}
	})
}

func TestChangeRingReportsWhatAReaderMissed(t *testing.T) {
	t.Parallel()

	var ring changeRing
	first, second := connectivityMapNodeID(t, 1), connectivityMapNodeID(t, 2)
	ring.append(1, []node.ID{second, first})
	ring.append(2, []node.ID{first})
	if changed, ok := ring.since(0); !ok || !slices.Equal(changed, []node.ID{first, second}) {
		t.Fatalf("since(0) = %v, %t", changed, ok)
	}
	if changed, ok := ring.since(1); !ok || !slices.Equal(changed, []node.ID{first}) {
		t.Fatalf("since(1) = %v, %t", changed, ok)
	}
	if changed, ok := ring.since(2); !ok || len(changed) != 0 {
		t.Fatalf("since(2) = %v, %t", changed, ok)
	}
	for seq := uint64(3); seq < 3+connectivityChangeLog; seq++ {
		ring.append(seq, []node.ID{second})
	}
	if _, ok := ring.since(1); ok {
		t.Fatal("since() claimed changes the ring no longer holds")
	}
}
