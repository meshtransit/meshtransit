//go:build integration

package integration

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	redisadapter "github.com/meshtransit/meshtransit/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/internal/control/mapsession"
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
	scope := redisIntegrationScope(t)
	subscription, err := client.SubscribeConnectivityChanged(ctx)
	if err != nil {
		t.Fatalf("Redis SubscribeConnectivityChanged() error = %v", err)
	}
	defer func() {
		if err := subscription.Close(); err != nil {
			t.Errorf("Redis ConnectivitySubscription.Close() error = %v", err)
		}
	}()
	if accepted, err := client.ObserveEndpoints(ctx, scope, generationTwo); err != nil || !accepted {
		t.Fatalf("Redis ObserveEndpoints(generation 2) = (%t, %v), want accepted", accepted, err)
	}
	received, err := subscription.Receive(ctx)
	if err != nil || received.NetworkID() != scope.NetworkID() ||
		received.Key().NodeID() != nodeID || received.Key().Generation() != 2 ||
		received.Kind() != mapsession.ConnectivityChangeEndpoints {
		t.Fatalf("Redis connectivity wakeup = (%+v, %v), want exact endpoint change", received, err)
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
	assertPresenceAcquire(ctx, t, client, newOwner, true)
	if accepted, err := client.ObserveEndpoints(ctx, scope, generationTwo); err != nil || accepted {
		t.Fatalf("Redis ObserveEndpoints(stale generation) = (%t, %v), want rejection", accepted, err)
	}
	generationThree := integrationEndpointObservation(t, nodeID, 3, "198.51.100.20:41641")
	if accepted, err := client.ObserveEndpoints(ctx, scope, generationThree); err != nil || !accepted {
		t.Fatalf("Redis ObserveEndpoints(generation 3) = (%t, %v), want accepted", accepted, err)
	}
	connectivityKey, err := mapsession.NewConnectivityKey(nodeID, 3)
	if err != nil {
		t.Fatalf("construct integration connectivity key: %v", err)
	}
	connectivity, err := client.LoadConnectivity(
		ctx,
		[]mapsession.ConnectivityKey{connectivityKey},
	)
	if err != nil || len(connectivity) != 1 || !connectivity[0].Online() {
		t.Fatalf("Redis LoadConnectivity(online) = (%+v, %v)", connectivity, err)
	}
	projected, present := connectivity[0].EndpointSet()
	if !present || !projected.Equal(generationThree.Set()) {
		t.Fatalf("Redis connectivity endpoint set = (%+v, %t), want generation 3", projected, present)
	}
	preferredRelay, preferredRelayPresent := connectivity[0].PreferredRelay()
	if !preferredRelayPresent || preferredRelay != 3 {
		t.Fatalf(
			"Redis connectivity preferred relay = (%d, %t), want (3, true)",
			preferredRelay,
			preferredRelayPresent,
		)
	}
	set, found, err = client.LoadEndpoints(ctx, nodeID, 3)
	if err != nil || !found || !slices.Equal(set.Endpoints(), generationThree.Set().Endpoints()) {
		t.Fatalf("Redis LoadEndpoints(generation 3) = (%+v, %t, %v), want replacement", set, found, err)
	}
	assertPresenceRelease(ctx, t, client, newOwner, true)
	if _, found, err := client.LoadEndpoints(ctx, nodeID, 3); err != nil || found {
		t.Fatalf("Redis LoadEndpoints(released generation) = (_, %t, %v), want miss", found, err)
	}
	connectivity, err = client.LoadConnectivity(
		ctx,
		[]mapsession.ConnectivityKey{connectivityKey},
	)
	if err != nil || len(connectivity) != 1 || connectivity[0].Online() {
		t.Fatalf("Redis LoadConnectivity(released) = (%+v, %v), want offline", connectivity, err)
	}
	if _, present := connectivity[0].EndpointSet(); present {
		t.Fatal("Redis released connectivity retained endpoint set")
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
	observation, err = observation.WithPreferredRelay(3)
	if err != nil {
		t.Fatalf("attach integration preferred relay: %v", err)
	}
	return observation
}
