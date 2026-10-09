//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	redisadapter "github.com/meshtransit/meshtransit/core/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/core/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
)

// assertRedisDeliveryRecords qualifies the delivery Lua scripts against real
// Redis: records never move backwards, touches keep only the same session,
// and loads report presence together with the record.
func assertRedisDeliveryRecords(ctx context.Context, t *testing.T, client *redisadapter.Client) {
	t.Helper()
	nodeID, err := node.ParseID("01890f00-0000-7000-8000-000000013401")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := node.ParseID("01890f00-0000-7000-8000-000000013402")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Millisecond)
	record := func(generation, revision int64, deliveredAt time.Time) {
		t.Helper()
		if err := client.RecordDelivery(ctx, mapsession.Delivery{NodeID: nodeID, SessionGeneration: generation,
			NetworkRevision: revision, PolicyRevision: 2, DeliveredAt: deliveredAt}); err != nil {
			t.Fatalf("RecordDelivery(%d,%d) error = %v", generation, revision, err)
		}
	}
	load := func() (seenRevision, seenGeneration int64, seenAt time.Time, known, online bool) {
		t.Helper()
		observations, err := client.LoadObservations(ctx, []node.ID{nodeID, fresh})
		if err != nil || len(observations) != 2 {
			t.Fatalf("LoadObservations() = %v, %v", observations, err)
		}
		if observations[1].Known || observations[1].Online {
			t.Fatal("an unseen Device reported a delivery")
		}
		first := observations[0]
		return first.NetworkRevision, first.SessionGeneration, first.SeenAt, first.Known, first.Online
	}

	record(3, 10, at)
	record(3, 9, at.Add(time.Second))  // older revision, same session: ignored
	record(2, 50, at.Add(time.Second)) // older session: ignored
	if revision, generation, _, known, online := load(); !known || online || revision != 10 || generation != 3 {
		t.Fatalf("after stale records: revision %d generation %d known %t online %t", revision, generation, known, online)
	}
	record(4, 1, at.Add(2*time.Second)) // a new session may start lower
	if revision, generation, _, _, _ := load(); revision != 1 || generation != 4 {
		t.Fatalf("new session record = revision %d generation %d", revision, generation)
	}
	if err := client.TouchDelivery(ctx, nodeID, 3, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, seenAt, _, _ := load(); !seenAt.Equal(at.Add(2 * time.Second)) {
		t.Fatalf("a touch from an old session moved seen time to %s", seenAt)
	}
	if err := client.TouchDelivery(ctx, nodeID, 4, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, _, seenAt, _, _ := load(); !seenAt.Equal(at.Add(time.Minute)) {
		t.Fatalf("touch on the current session = %s", seenAt)
	}
}
