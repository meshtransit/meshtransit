//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/shared/policydigest"
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
		if err := client.RecordDelivery(ctx, mapsession.Delivery{NodeID: nodeID, NodeKey: integrationNodeKey,
			MachineFingerprint: integrationMachine, SessionGeneration: generation,
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
	assertRedisEnforcementRecords(ctx, t, client, nodeID, at.Add(time.Hour))
}

var (
	integrationNodeKey = node.Key{0x13, 0x40}
	integrationMachine = [32]byte{0x13, 0x41}
)

// assertRedisEnforcementRecords qualifies R1-69: a report is kept only for
// the session that owns the record, and a new session clears it.
func assertRedisEnforcementRecords(ctx context.Context, t *testing.T, client *redisadapter.Client,
	nodeID node.ID, at time.Time) {
	t.Helper()
	digest, _, err := policydigest.Compute(nil)
	if err != nil {
		t.Fatal(err)
	}
	filter, err := mapsession.NewFilterDigest(digest, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RecordDelivery(ctx, mapsession.Delivery{NodeID: nodeID, NodeKey: integrationNodeKey,
		MachineFingerprint: integrationMachine, SessionGeneration: 4,
		NetworkRevision: 2, PolicyRevision: 2, DeliveredAt: at, Filter: filter}); err != nil {
		t.Fatal(err)
	}
	report := func(machine [32]byte) bool {
		t.Helper()
		stored, err := client.RecordEnforcement(ctx, mapsession.Enforcement{NodeKey: integrationNodeKey,
			MachineFingerprint: machine, Filter: filter, AppliedAt: at, ReportedAt: at.Add(time.Second)})
		if err != nil {
			t.Fatalf("RecordEnforcement() error = %v", err)
		}
		return stored
	}
	load := func() distribution.Observation {
		t.Helper()
		observations, err := client.LoadObservations(ctx, []node.ID{nodeID})
		if err != nil || len(observations) != 1 {
			t.Fatalf("LoadObservations() = %v, %v", observations, err)
		}
		return observations[0]
	}
	if report([32]byte{0x99}) {
		t.Fatal("a report from another machine was stored")
	}
	if !report(integrationMachine) {
		t.Fatal("a report from the current session was refused")
	}
	observation := load()
	if observation.Filter.Digest != digest || observation.Enforced.Digest != digest ||
		!observation.ReportedAt.Equal(at.Add(time.Second)) ||
		distribution.ClassifyEnforcement(observation, at) != distribution.EnforcementEnforced {
		t.Fatalf("enforced observation = %+v", observation)
	}
	if err := client.RecordDelivery(ctx, mapsession.Delivery{NodeID: nodeID, NodeKey: integrationNodeKey,
		MachineFingerprint: integrationMachine, SessionGeneration: 4,
		NetworkRevision: 3, PolicyRevision: 2, DeliveredAt: at.Add(time.Second), Filter: filter}); err != nil {
		t.Fatal(err)
	}
	if load().Enforced.Digest != digest {
		t.Fatal("a delivery in the same session dropped its report")
	}
	if err := client.RecordDelivery(ctx, mapsession.Delivery{NodeID: nodeID, NodeKey: integrationNodeKey,
		MachineFingerprint: integrationMachine, SessionGeneration: 5,
		NetworkRevision: 1, PolicyRevision: 2, DeliveredAt: at.Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	if observation := load(); !observation.Filter.IsZero() || !observation.Enforced.IsZero() ||
		!observation.ReportedAt.IsZero() {
		t.Fatalf("a new session kept the previous report: %+v", observation)
	}
}
