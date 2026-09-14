//go:build integration

package integration

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	redisadapter "github.com/meshtransit/meshtransit/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/internal/node"
)

func assertRedisEndpointObservationFencing(
	ctx context.Context,
	t *testing.T,
	client *redisadapter.Client,
) {
	t.Helper()
	nodeID, err := node.ParseID("01890f70-0000-7000-8000-000000000702")
	if err != nil {
		t.Fatalf("parse endpoint-observation Node ID: %v", err)
	}
	generationTwo := integrationEndpointObservation(t, nodeID, 2, "192.0.2.10:41641")
	if accepted, err := client.ObserveEndpoints(ctx, generationTwo); err != nil || !accepted {
		t.Fatalf("Redis ObserveEndpoints(generation 2) = (%t, %v), want accepted", accepted, err)
	}
	set, found, err := client.LoadEndpoints(ctx, nodeID, 2)
	if err != nil || !found || set.DiscoveryKey() != generationTwo.Set().DiscoveryKey() ||
		!slices.Equal(set.Endpoints(), generationTwo.Set().Endpoints()) {
		t.Fatalf("Redis LoadEndpoints(generation 2) = (%+v, %t, %v), want exact set", set, found, err)
	}
	if _, found, err := client.LoadEndpoints(ctx, nodeID, 1); err != nil || found {
		t.Fatalf("Redis LoadEndpoints(stale generation) = (_, %t, %v), want miss", found, err)
	}

	newOwner := integrationPresenceLease(t, nodeID, 3, "control-b")
	assertPresenceClaim(ctx, t, client, newOwner, true)
	if accepted, err := client.ObserveEndpoints(ctx, generationTwo); err != nil || accepted {
		t.Fatalf("Redis ObserveEndpoints(stale generation) = (%t, %v), want rejection", accepted, err)
	}
	generationThree := integrationEndpointObservation(t, nodeID, 3, "198.51.100.20:41641")
	if accepted, err := client.ObserveEndpoints(ctx, generationThree); err != nil || !accepted {
		t.Fatalf("Redis ObserveEndpoints(generation 3) = (%t, %v), want accepted", accepted, err)
	}
	set, found, err = client.LoadEndpoints(ctx, nodeID, 3)
	if err != nil || !found || !slices.Equal(set.Endpoints(), generationThree.Set().Endpoints()) {
		t.Fatalf("Redis LoadEndpoints(generation 3) = (%+v, %t, %v), want replacement", set, found, err)
	}
	assertPresenceRelease(ctx, t, client, newOwner, true)
	if _, found, err := client.LoadEndpoints(ctx, nodeID, 3); err != nil || found {
		t.Fatalf("Redis LoadEndpoints(released generation) = (_, %t, %v), want miss", found, err)
	}
}

func integrationEndpointObservation(
	t *testing.T,
	nodeID node.ID,
	generation int64,
	address string,
) node.EndpointObservation {
	t.Helper()
	discoveryKey, err := node.NewDiscoveryKey([32]byte{1})
	if err != nil {
		t.Fatalf("construct integration discovery key: %v", err)
	}
	endpoint, err := node.NewEndpoint(
		netip.MustParseAddrPort(address),
		node.EndpointSourceSTUN,
	)
	if err != nil {
		t.Fatalf("construct integration endpoint: %v", err)
	}
	set, err := node.NewEndpointSet(discoveryKey, []node.Endpoint{endpoint})
	if err != nil {
		t.Fatalf("construct integration endpoint set: %v", err)
	}
	observation, err := node.NewEndpointObservation(nodeID, generation, set, 30*time.Second)
	if err != nil {
		t.Fatalf("construct integration endpoint observation: %v", err)
	}
	return observation
}
