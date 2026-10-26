//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// assertRedisGatewayPresence runs the Kubernetes gateway's presence scripts
// against Redis as Core's ACL user (K1a1 plan §16.12): a take over a live
// holder marks the keys contested whatever the replica or generation, a
// handoff take does not count towards a fight, release and handoff touch
// only their own holder, and the contest outlives the presence.
func assertRedisGatewayPresence(ctx context.Context, t *testing.T, client *redisadapter.Client) {
	t.Helper()
	const window = 1500 * time.Millisecond
	machine := [32]byte{0x52, 0xb}

	nodeID := gatewayPresenceNodeID(t, "01890f70-0000-7000-8000-000000000801")
	first := gatewayPresenceLease(t, nodeID, 2, "control-a", machine)
	assertGatewayAcquire(ctx, t, client, first, window, true, false)
	assertGatewayRotation(ctx, t, client, first, mapsession.GatewayRotationHeld)
	other := gatewayPresenceLease(t, nodeID, 2, "control-a", machine)
	assertGatewayRotation(ctx, t, client, other, mapsession.GatewayRotationNotHeld)

	// Another replica takes the live lease: contested everywhere.
	second := gatewayPresenceLease(t, nodeID, 2, "control-b", machine)
	assertGatewayAcquire(ctx, t, client, second, window, true, false)
	assertGatewayRotation(ctx, t, client, second, mapsession.GatewayRotationContested)
	assertGatewayRenew(ctx, t, client, first, false)
	assertGatewayRenew(ctx, t, client, second, true)
	assertGatewayRelease(ctx, t, client, first, false)
	assertGatewayHandoff(ctx, t, client, first, false)
	assertGatewayRelease(ctx, t, client, second, true)
	assertGatewayRenew(ctx, t, client, second, false)

	// A fresh lease after a release is no take, but the contest stays until
	// it ends.
	third := gatewayPresenceLease(t, nodeID, 2, "control-a", machine)
	assertGatewayAcquire(ctx, t, client, third, window, true, false)
	assertGatewayRotation(ctx, t, client, third, mapsession.GatewayRotationContested)
	time.Sleep(window + 200*time.Millisecond)
	assertGatewayRotation(ctx, t, client, third, mapsession.GatewayRotationHeld)

	// The same replica, after Core ended a stream and left its lease, and a
	// newer generation over a live lease: both contested.
	sameReplica := gatewayPresenceLease(t, nodeID, 2, "control-a", machine)
	assertGatewayAcquire(ctx, t, client, sameReplica, window, true, false)
	assertGatewayRotation(ctx, t, client, sameReplica, mapsession.GatewayRotationContested)
	time.Sleep(window + 200*time.Millisecond)
	// This is the third take of a live holder here within five minutes.
	newer := gatewayPresenceLease(t, nodeID, 3, "control-b", machine)
	assertGatewayAcquire(ctx, t, client, newer, window, true, true)
	assertGatewayRotation(ctx, t, client, newer, mapsession.GatewayRotationContested)
	older := gatewayPresenceLease(t, nodeID, 2, "control-a", machine)
	assertGatewayAcquire(ctx, t, client, older, window, false, false)

	// The third take of live holders within the window is a fight, once.
	fightID := gatewayPresenceNodeID(t, "01890f70-0000-7000-8000-000000000802")
	fightMachine := [32]byte{0x52, 0xc}
	replicas := []string{"control-a", "control-b", "control-a", "control-b", "control-a"}
	for index, replica := range replicas {
		lease := gatewayPresenceLease(t, fightID, 5, replica, fightMachine)
		assertGatewayAcquire(ctx, t, client, lease, time.Minute, true, index == 3)
	}

	// Takes after Core handed the lease off (Shutdown, Shed) never fight.
	handoffID := gatewayPresenceNodeID(t, "01890f70-0000-7000-8000-000000000803")
	handoffMachine := [32]byte{0x52, 0xd}
	previous := gatewayPresenceLease(t, handoffID, 1, "control-a", handoffMachine)
	assertGatewayAcquire(ctx, t, client, previous, time.Minute, true, false)
	for index := range 4 {
		assertGatewayHandoff(ctx, t, client, previous, true)
		replica := []string{"control-b", "control-c"}[index%2]
		next := gatewayPresenceLease(t, handoffID, 1, replica, handoffMachine)
		assertGatewayAcquire(ctx, t, client, next, time.Minute, true, false)
		// A handoff take still contests: Core cannot tell who comes back.
		assertGatewayRotation(ctx, t, client, next, mapsession.GatewayRotationContested)
		previous = next
	}
}

func gatewayPresenceNodeID(t *testing.T, value string) node.ID {
	t.Helper()
	parsed, err := publicid.Parse(value)
	if err != nil {
		t.Fatalf("parse gateway Node ID: %v", err)
	}
	nodeID, err := node.NewID(parsed.Bytes())
	if err != nil {
		t.Fatalf("construct gateway Node ID: %v", err)
	}
	return nodeID
}

func gatewayPresenceLease(t *testing.T, nodeID node.ID, generation int64, replica string,
	machine [32]byte) node.PresenceLease {
	t.Helper()
	holder, err := node.NewPresenceHolder()
	if err != nil {
		t.Fatal(err)
	}
	lease, err := integrationPresenceLease(t, nodeID, generation, replica).WithGateway(holder, machine)
	if err != nil {
		t.Fatalf("gateway presence lease: %v", err)
	}
	return lease
}

func assertGatewayAcquire(ctx context.Context, t *testing.T, client *redisadapter.Client, lease node.PresenceLease,
	window time.Duration, claimed, fight bool) {
	t.Helper()
	claim, err := client.AcquireGatewayPresence(ctx, redisIntegrationScope(t), lease, window)
	if err != nil {
		t.Fatalf("AcquireGatewayPresence() error = %v", err)
	}
	if claim.Claimed != claimed || claim.Fight != fight {
		t.Fatalf("AcquireGatewayPresence() = %+v, want claimed %t fight %t", claim, claimed, fight)
	}
}

func assertGatewayRenew(ctx context.Context, t *testing.T, client *redisadapter.Client, lease node.PresenceLease,
	want bool) {
	t.Helper()
	renewed, err := client.RenewGatewayPresence(ctx, lease)
	if err != nil || renewed != want {
		t.Fatalf("RenewGatewayPresence() = (%t, %v), want %t", renewed, err, want)
	}
}

func assertGatewayRelease(ctx context.Context, t *testing.T, client *redisadapter.Client, lease node.PresenceLease,
	want bool) {
	t.Helper()
	released, err := client.ReleaseGatewayPresence(ctx, redisIntegrationScope(t), lease)
	if err != nil || released != want {
		t.Fatalf("ReleaseGatewayPresence() = (%t, %v), want %t", released, err, want)
	}
}

func assertGatewayHandoff(ctx context.Context, t *testing.T, client *redisadapter.Client, lease node.PresenceLease,
	want bool) {
	t.Helper()
	marked, err := client.HandOffGatewayPresence(ctx, lease)
	if err != nil || marked != want {
		t.Fatalf("HandOffGatewayPresence() = (%t, %v), want %t", marked, err, want)
	}
}

func assertGatewayRotation(ctx context.Context, t *testing.T, client *redisadapter.Client, lease node.PresenceLease,
	want mapsession.GatewayRotationState) {
	t.Helper()
	state, err := client.CheckGatewayRotation(ctx, lease)
	if err != nil || state != want {
		t.Fatalf("CheckGatewayRotation() = (%v, %v), want %v", state, err, want)
	}
}
