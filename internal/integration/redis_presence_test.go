//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	redisadapter "github.com/meshtransit/meshtransit/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
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
	newOwner := integrationPresenceLease(t, nodeID, 3, "control-b")

	assertPresenceClaim(ctx, t, client, ownerGenerationTwo, true)
	assertPresenceClaim(ctx, t, client, staleOwner, false)
	assertPresenceClaim(ctx, t, client, foreignSameGeneration, false)
	assertPresenceClaim(ctx, t, client, ownerGenerationTwo, true)
	assertPresenceClaim(ctx, t, client, newOwner, true)
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

func assertPresenceClaim(
	ctx context.Context,
	t *testing.T,
	client *redisadapter.Client,
	lease node.PresenceLease,
	want bool,
) {
	t.Helper()
	claimed, err := client.ClaimPresence(ctx, redisIntegrationScope(t), lease)
	if err != nil {
		t.Fatalf("Redis ClaimPresence() error = %v", err)
	}
	if claimed != want {
		t.Fatalf("Redis ClaimPresence() = %t, want %t", claimed, want)
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
