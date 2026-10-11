package mapsession

import (
	"encoding/binary"
	"testing"

	"meshtransit.net/core/internal/domain/node"
)

func connectivityMapNodeID(t testing.TB, index uint64) node.ID {
	t.Helper()
	var raw [16]byte
	binary.BigEndian.PutUint64(raw[8:], index)
	raw[6], raw[8] = 0x70, 0x80|raw[8]&0x3f
	id, err := node.NewID(raw)
	if err != nil {
		t.Fatalf("node.NewID(%d) error = %v", index, err)
	}
	return id
}

func connectivityMapValue(t testing.TB, id node.ID, generation int64, online bool) Connectivity {
	t.Helper()
	key, err := NewConnectivityKey(id, generation)
	if err != nil {
		t.Fatal(err)
	}
	value, err := NewConnectivity(ConnectivityParams{Key: key, Online: online})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestConnectivityMapIsPersistent(t *testing.T) {
	t.Parallel()

	const count = 5000
	var empty connectivityMap
	maps := make([]connectivityMap, 0, count+1)
	current := empty
	maps = append(maps, current)
	for index := uint64(1); index <= count; index++ {
		current = current.set(connectivityMapValue(t, connectivityMapNodeID(t, index), 1, false))
		maps = append(maps, current)
	}
	if current.len() != count {
		t.Fatalf("len() = %d, want %d", current.len(), count)
	}
	// Every earlier version still holds exactly its own entries.
	for _, version := range []uint64{0, 1, 17, 1024, count} {
		for index := uint64(1); index <= count; index++ {
			_, found := maps[version].get(connectivityMapNodeID(t, index))
			if found != (index <= version) {
				t.Fatalf("version %d get(%d) found = %t", version, index, found)
			}
		}
	}

	// Replacing a value leaves the previous version unchanged.
	id := connectivityMapNodeID(t, 42)
	updated := current.set(connectivityMapValue(t, id, 2, true))
	if updated.len() != count {
		t.Fatalf("replacement changed len to %d", updated.len())
	}
	if value, _ := updated.get(id); value.Key().Generation() != 2 || !value.Online() {
		t.Fatalf("updated value = %+v", value)
	}
	if value, _ := current.get(id); value.Key().Generation() != 1 || value.Online() {
		t.Fatalf("previous version changed: %+v", value)
	}

	seen := 0
	updated.each(func(Connectivity) { seen++ })
	if seen != count {
		t.Fatalf("each() visited %d, want %d", seen, count)
	}
}

func TestConnectivityMapKeepsFullHashCollisions(t *testing.T) {
	t.Parallel()

	first := connectivityMapValue(t, connectivityMapNodeID(t, 1), 1, false)
	second := connectivityMapValue(t, connectivityMapNodeID(t, 2), 1, true)
	var values connectivityMap
	// Force both into one leaf, as a full 64-bit collision would.
	values.root = values.root.insert(7, 0, first)
	values.root = values.root.insert(7, 0, second)
	values.size = 2
	if got, found := values.root.lookup(7, first.Key().NodeID()); !found || got.Online() {
		t.Fatalf("first = %+v, %t", got, found)
	}
	if got, found := values.root.lookup(7, second.Key().NodeID()); !found || !got.Online() {
		t.Fatalf("second = %+v, %t", got, found)
	}
}

func BenchmarkConnectivityMapSet(b *testing.B) {
	var values connectivityMap
	ids := make([]node.ID, 100_000)
	for index := range ids {
		ids[index] = connectivityMapNodeID(b, uint64(index+1))
		values = values.set(connectivityMapValue(b, ids[index], 1, false))
	}
	update := connectivityMapValue(b, ids[777], 1, true)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = values.set(update)
	}
}

func BenchmarkConnectivityMapGet(b *testing.B) {
	var values connectivityMap
	ids := make([]node.ID, 100_000)
	for index := range ids {
		ids[index] = connectivityMapNodeID(b, uint64(index+1))
		values = values.set(connectivityMapValue(b, ids[index], 1, false))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := range b.N {
		_, _ = values.get(ids[iteration%len(ids)])
	}
}
