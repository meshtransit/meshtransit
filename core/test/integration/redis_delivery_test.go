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
	routes, err := mapsession.NewRouteDigest(digest, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RecordDelivery(ctx, mapsession.Delivery{NodeID: nodeID, NodeKey: integrationNodeKey,
		MachineFingerprint: integrationMachine, SessionGeneration: 4,
		NetworkRevision: 2, PolicyRevision: 2, DeliveredAt: at, Filter: filter, Routes: routes}); err != nil {
		t.Fatal(err)
	}
	report := func(machine [32]byte) bool {
		t.Helper()
		stored, err := client.RecordEnforcement(ctx, mapsession.Enforcement{NodeKey: integrationNodeKey,
			MachineFingerprint: machine, Filter: filter, Routes: routes, AppliedAt: at, ReportedAt: at.Add(time.Second)})
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
		distribution.ClassifyEnforcement(observation, at) != distribution.EnforcementEnforced ||
		distribution.ClassifyRouteEnforcement(observation, at) != distribution.EnforcementEnforced ||
		observation.Routes.Entries != 2 {
		t.Fatalf("enforced observation = %+v", observation)
	}
	// A router's Site health is kept for its current session.
	health := mapsession.RouteHealth{NodeKey: integrationNodeKey, MachineFingerprint: integrationMachine,
		ReportedAt: at.Add(2 * time.Second), Sites: []mapsession.SiteHealth{
			{Ref: "prod", State: mapsession.RouteHealthFailed, Code: "forward_blocked"},
		}}
	// A report that newly holds a failed Site wakes the Site election worker
	// once; the same report again does not.
	wakeups, err := client.SubscribeSiteHealthFailed(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wakeups.Close() }()
	if stored, err := client.RecordRouteHealth(ctx, health); err != nil || !stored {
		t.Fatalf("RecordRouteHealth() = %t, %v", stored, err)
	}
	receiveCtx, cancelReceive := context.WithTimeout(ctx, 3*time.Second)
	if err := wakeups.Receive(receiveCtx); err != nil {
		t.Fatalf("no wakeup for a failed Site: %v", err)
	}
	cancelReceive()
	if stored, err := client.RecordRouteHealth(ctx, health); err != nil || !stored {
		t.Fatalf("repeated RecordRouteHealth() = %t, %v", stored, err)
	}
	quietCtx, cancelQuiet := context.WithTimeout(ctx, 300*time.Millisecond)
	if err := wakeups.Receive(quietCtx); err == nil {
		t.Fatal("an unchanged failed report woke the worker again")
	}
	cancelQuiet()
	if current, ok := distribution.CurrentRouteHealth(load(), at.Add(3*time.Second)); !ok || len(current) != 1 ||
		current[0] != (distribution.SiteHealth{Ref: "prod", State: "failed", Code: "forward_blocked"}) {
		t.Fatalf("route health = %+v, %t", current, ok)
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
		!observation.ReportedAt.IsZero() || !observation.Routes.IsZero() || !observation.EnforcedRoutes.IsZero() ||
		observation.RouteHealth != nil || !observation.RouteHealthAt.IsZero() {
		t.Fatalf("a new session kept the previous report: %+v", observation)
	}
	// A node's Site routers are kept for its session and counted per Site;
	// a Site it no longer reports drops out of that Site's count.
	router, _ := node.ParseID("01890f00-0000-7000-8000-000000000402")
	selection := mapsession.RouteSelection{NodeKey: integrationNodeKey, MachineFingerprint: integrationMachine,
		ReportedAt: time.Now(), Sites: []mapsession.SiteSelection{
			{Ref: "prod", Router: router, Reason: mapsession.RouteSelectionLocalFailover},
			{Ref: "uat", Router: router, Reason: mapsession.RouteSelectionPrimary},
		}}
	if stored, err := client.RecordRouteSelection(ctx, selection); err != nil || !stored {
		t.Fatalf("RecordRouteSelection() = %t, %v", stored, err)
	}
	if current, ok := distribution.CurrentRouteSelection(load(), time.Now()); !ok || len(current) != 2 ||
		current[0] != (distribution.SiteRouter{Ref: "prod", Router: router.String(), Via: distribution.ViaLocalFailover}) {
		t.Fatalf("route selection = %+v, %t", current, ok)
	}
	uses, err := client.CountSiteRouters(ctx, "uat", time.Now())
	if err != nil || uses[router.String()] != (distribution.RouterUse{Clients: 1}) {
		t.Fatalf("uat routers = %+v, %v", uses, err)
	}
	selection.Sites = selection.Sites[:1]
	if stored, err := client.RecordRouteSelection(ctx, selection); err != nil || !stored {
		t.Fatalf("RecordRouteSelection(fewer) = %t, %v", stored, err)
	}
	if uses, err := client.CountSiteRouters(ctx, "uat", time.Now()); err != nil || len(uses) != 0 {
		t.Fatalf("uat routers after the node stopped reporting it = %+v, %v", uses, err)
	}
	if uses, err := client.CountSiteRouters(ctx, "prod", time.Now()); err != nil ||
		uses[router.String()] != (distribution.RouterUse{Clients: 1, LocalFailover: 1}) {
		t.Fatalf("prod routers = %+v, %v", uses, err)
	}
	health.ReportedAt = at.Add(3 * time.Second)
	other := health
	other.NodeKey = node.Key{0x77}
	if stored, err := client.RecordRouteHealth(ctx, other); err != nil || stored {
		t.Fatalf("health of a node key without a session = %t, %v", stored, err)
	}
}
