//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	redisadapter "github.com/meshtransit/meshtransit/core/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

func assertRedisPresenceLeaseFencing(
	ctx context.Context,
	t *testing.T,
	client *redisadapter.Client,
) {
	t.Helper()
	nodeIDValue, err := publicid.Parse("01890f70-0000-7000-8000-000000000701")
	if err != nil {
		t.Fatalf("parse presence Node ID: %v", err)
	}
	nodeID, err := node.NewID(nodeIDValue.Bytes())
	if err != nil {
		t.Fatalf("construct presence Node ID: %v", err)
	}

	ownerGenerationTwo := integrationPresenceLease(t, nodeID, 2, "control-a")
	staleOwner := integrationPresenceLease(t, nodeID, 1, "control-b")
	foreignSameGeneration := integrationPresenceLease(t, nodeID, 2, "control-b")
	newOwner := integrationPresenceLease(t, nodeID, 3, "control-a")

	assertPresenceAcquire(ctx, t, client, ownerGenerationTwo, true)
	assertPresenceRenew(ctx, t, client, ownerGenerationTwo, true)
	assertPresenceAcquire(ctx, t, client, staleOwner, false)
	assertPresenceAcquire(ctx, t, client, foreignSameGeneration, true)
	assertPresenceRenew(ctx, t, client, ownerGenerationTwo, false)
	assertPresenceRenew(ctx, t, client, foreignSameGeneration, true)
	assertPresenceAcquire(ctx, t, client, newOwner, true)
	assertPresenceRenew(ctx, t, client, foreignSameGeneration, false)
	assertPresenceRenew(ctx, t, client, newOwner, true)
	assertPresenceRelease(ctx, t, client, ownerGenerationTwo, false)
	assertPresenceRelease(ctx, t, client, newOwner, true)
	assertPresenceRelease(ctx, t, client, newOwner, false)
}

func integrationPresenceLease(
	t *testing.T,
	nodeID node.ID,
	generation int64,
	replicaID string,
) node.PresenceLease {
	t.Helper()
	lease, err := node.NewPresenceLease(nodeID, generation, replicaID, 30*time.Second)
	if err != nil {
		t.Fatalf("construct integration presence lease: %v", err)
	}
	return lease
}

func assertPresenceAcquire(
	ctx context.Context,
	t *testing.T,
	client *redisadapter.Client,
	lease node.PresenceLease,
	want bool,
) {
	t.Helper()
	acquired, err := client.AcquirePresence(ctx, redisIntegrationScope(t), lease)
	if err != nil {
		t.Fatalf("Redis AcquirePresence() error = %v", err)
	}
	if acquired != want {
		t.Fatalf("Redis AcquirePresence() = %t, want %t", acquired, want)
	}
}

func assertPresenceRenew(
	ctx context.Context,
	t *testing.T,
	client *redisadapter.Client,
	lease node.PresenceLease,
	want bool,
) {
	t.Helper()
	renewed, err := client.RenewPresence(ctx, lease)
	if err != nil {
		t.Fatalf("Redis RenewPresence() error = %v", err)
	}
	if renewed != want {
		t.Fatalf("Redis RenewPresence() = %t, want %t", renewed, want)
	}
}

func assertPresenceRelease(
	ctx context.Context,
	t *testing.T,
	client *redisadapter.Client,
	lease node.PresenceLease,
	want bool,
) {
	t.Helper()
	released, err := client.ReleasePresence(ctx, redisIntegrationScope(t), lease)
	if err != nil {
		t.Fatalf("Redis ReleasePresence() error = %v", err)
	}
	if released != want {
		t.Fatalf("Redis ReleasePresence() = %t, want %t", released, want)
	}
}

func redisIntegrationScope(t testing.TB) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID("01890f70-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatalf("parse Redis integration Workspace ID: %v", err)
	}
	networkID, err := network.ParseID("01890f70-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatalf("parse Redis integration Network ID: %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("construct Redis integration scope: %v", err)
	}
	return scope
}
