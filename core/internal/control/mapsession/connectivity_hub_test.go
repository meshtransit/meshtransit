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
	if version, _ := table.apply([]Connectivity{offline}, false); !version.lookup(online.key).Online() {
		t.Fatal("a fill-only apply replaced a stored value")
	}
	if version, _ := table.apply([]Connectivity{offline}, true); version.lookup(online.key).Online() {
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

// A map with few peers compares self and its peers directly: the change
// log (read under the table's lock) is only for maps with many peers.
func TestConnectivityCandidatesReadTheLogOnlyForManyPeers(t *testing.T) {
	t.Parallel()
	self, unrelated := hubKey(t, 1, 1).nodeID, hubKey(t, 900, 1).nodeID
	table := &networkConnectivity{}
	table.log.append(2, []node.ID{unrelated})
	from := &connectivityVersion{table: table, seq: 1}
	to := &connectivityVersion{table: table, seq: 2}
	current := Snapshot{nodeID: self, sharedConnectivity: from}
	mapWith := func(peers int) Snapshot {
		authorized := make([]PeerCandidate, 0, peers)
		for index := range peers {
			authorized = append(authorized, PeerCandidate{nodeID: hubKey(t, uint64(2+index), 1).nodeID})
		}
		slices.SortFunc(authorized, func(left, right PeerCandidate) int { return compareNodeIDs(left.nodeID, right.nodeID) })
		return Snapshot{nodeID: self, authorized: authorized, sharedConnectivity: to}
	}

	small := mapWith(1)
	want := []node.ID{self, small.authorized[0].nodeID}
	slices.SortFunc(want, compareNodeIDs)
	if got := connectivityCandidates(current, small); !slices.Equal(got, want) {
		t.Fatalf("small map candidates = %v, want self and its peer %v", got, want)
	}
	if got := connectivityCandidates(current, mapWith(directConnectivityPeers)); !slices.Equal(got, []node.ID{unrelated}) {
		t.Fatalf("large map candidates = %v, want the change log %v", got, []node.ID{unrelated})
	}
	if got := connectivityCandidates(Snapshot{nodeID: self, sharedConnectivity: to}, small); len(got) != 0 {
		t.Fatalf("one version against itself = %v, want none", got)
	}
}

// A stream is woken only for changes of the Nodes it is interested in; a
// repair (resync) wakes every stream.
func TestConnectivityHubWakesOnlyInterestedStreams(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hub, store, watcher, networkID := newHubFixture(t)
		keys := []ConnectivityKey{hubKey(t, 1, 1), hubKey(t, 2, 1), hubKey(t, 3, 1)}
		peerOfTwo, releasePeerOfTwo, _, err := hub.WatchNetworkInterest(networkID,
			ConnectivityOf([]node.ID{keys[0].nodeID, keys[1].nodeID}))
		if err != nil {
			t.Fatal(err)
		}
		defer releasePeerOfTwo()
		peerOfThree, releasePeerOfThree, setPeerOfThree, err := hub.WatchNetworkInterest(networkID,
			ConnectivityOf([]node.ID{keys[2].nodeID}))
		if err != nil {
			t.Fatal(err)
		}
		defer releasePeerOfThree()
		everything, releaseEverything, err := hub.WatchNetwork(networkID)
		if err != nil {
			t.Fatal(err)
		}
		defer releaseEverything()
		if _, err := hub.view(t.Context(), networkID, keys); err != nil {
			t.Fatal(err)
		}

		store.put(connectivityMapValue(t, keys[1].nodeID, 1, true))
		watcher.send(t, hubWake(t, networkID, keys[1]))
		synctest.Wait()
		if !woken(peerOfTwo) || woken(peerOfThree) || !woken(everything) {
			t.Fatal("a change of Node 2 must wake the stream interested in it and the one watching everything only")
		}

		// A wakeup that changes nothing wakes nobody.
		watcher.send(t, hubWake(t, networkID, keys[1]))
		synctest.Wait()
		if woken(peerOfTwo) || woken(peerOfThree) || woken(everything) {
			t.Fatal("an unchanged Node woke a stream")
		}

		// After its interest moves to Node 2, the second stream is woken for it.
		setPeerOfThree(ConnectivityOf([]node.ID{keys[1].nodeID}))
		store.put(connectivityMapValue(t, keys[1].nodeID, 1, false))
		watcher.send(t, hubWake(t, networkID, keys[1]))
		synctest.Wait()
		if !woken(peerOfTwo) || !woken(peerOfThree) || !woken(everything) {
			t.Fatal("a stream whose interest moved to Node 2 was not woken for it")
		}
	})
}

func woken(updates <-chan ConnectivityChanged) bool {
	select {
	case <-updates:
		return true
	default:
		return false
	}
}

func TestConnectivityInterestWants(t *testing.T) {
	t.Parallel()
	one, two, three := hubKey(t, 1, 1).nodeID, hubKey(t, 2, 1).nodeID, hubKey(t, 3, 1).nodeID
	interest := ConnectivityOf([]node.ID{three, one, one})
	for name, test := range map[string]struct {
		changed []node.ID
		want    bool
	}{
		"named":       {changed: ConnectivityOf([]node.ID{two, three}).nodes, want: true},
		"not named":   {changed: []node.ID{two}, want: false},
		"none":        {changed: []node.ID{}, want: false},
		"unknown set": {changed: nil, want: true},
	} {
		if got := interest.wants(test.changed); got != test.want {
			t.Errorf("%s: wants() = %t, want %t", name, got, test.want)
		}
	}
	if !AllConnectivity().wants([]node.ID{two}) || !interest.Equal(ConnectivityOf([]node.ID{one, three})) {
		t.Fatal("every-Node interest or Equal")
	}
}
