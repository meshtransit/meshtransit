//go:build integration

package integration

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
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
	if accepted, _, err := client.ObserveEndpoints(ctx, scope, generationTwo, 5*time.Second); err != nil || !accepted {
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
	if accepted, _, err := client.ObserveEndpoints(ctx, scope, generationTwo, 5*time.Second); err != nil || accepted {
		t.Fatalf("Redis ObserveEndpoints(stale generation) = (%t, %v), want rejection", accepted, err)
	}
	generationThree := integrationEndpointObservation(t, nodeID, 3, "198.51.100.20:41641")
	if accepted, _, err := client.ObserveEndpoints(ctx, scope, generationThree, 5*time.Second); err != nil || !accepted {
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

// endpointObservationWith is integrationEndpointObservation with a chosen
// disco key.
func endpointObservationWith(t *testing.T, nodeID node.ID, generation int64, address string,
	disco byte) node.EndpointObservation {
	t.Helper()
	discoveryKey, err := node.NewDiscoveryKey([32]byte{disco})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := node.NewEndpoint(netip.MustParseAddrPort(address), node.EndpointSourceSTUN)
	if err != nil {
		t.Fatal(err)
	}
	set, err := node.NewEndpointSet(discoveryKey, []node.Endpoint{endpoint})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := node.NewEndpointObservation(nodeID, generation, set, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

// assertRedisEndpointAnnouncementPacing qualifies H4 against real Redis: a
// Device's peers are told of at most one endpoint change per interval, the
// latest change is always stored and announced once the interval ends, and
// a new disco key or generation is announced at once.
func assertRedisEndpointAnnouncementPacing(ctx context.Context, t *testing.T, client *redisadapter.Client) {
	t.Helper()
	const interval = time.Second
	nodeID, err := node.ParseID("01890f70-0000-7000-8000-000000000703")
	if err != nil {
		t.Fatal(err)
	}
	scope := redisIntegrationScope(t)
	subscription, err := client.SubscribeConnectivityChanged(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := subscription.Close(); err != nil {
			t.Errorf("ConnectivitySubscription.Close() error = %v", err)
		}
	}()
	// One reader for the whole check: cancelling a Pub/Sub read makes the
	// client reconnect on the next one and lose what was published between.
	readCtx, stopReading := context.WithCancel(ctx)
	received := make(chan mapsession.ConnectivityChanged, 16)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			change, err := subscription.Receive(readCtx)
			if err != nil {
				return
			}
			if change.Key().NodeID() == nodeID {
				received <- change
			}
		}
	}()
	defer func() {
		// A Pub/Sub read only ends on its deadline or when the connection
		// closes, so close it before waiting for the reader.
		stopReading()
		if err := subscription.Close(); err != nil {
			t.Errorf("ConnectivitySubscription.Close() error = %v", err)
		}
		<-readerDone
	}()
	announced := func(label string) {
		t.Helper()
		select {
		case <-received:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: no announcement", label)
		}
	}
	silent := func(label string) {
		t.Helper()
		select {
		case change := <-received:
			t.Fatalf("%s: unexpected announcement %+v", label, change)
		case <-time.After(300 * time.Millisecond):
		}
	}
	observe := func(observation node.EndpointObservation) mapsession.EndpointAnnouncement {
		t.Helper()
		accepted, announcement, err := client.ObserveEndpoints(ctx, scope, observation, interval)
		if err != nil || !accepted {
			t.Fatalf("ObserveEndpoints() = (%t, %+v, %v)", accepted, announcement, err)
		}
		return announcement
	}
	stored := func(observation node.EndpointObservation) {
		t.Helper()
		set, found, err := client.LoadEndpoints(ctx, nodeID, observation.Generation())
		if err != nil || !found || !set.Equal(observation.Set()) {
			t.Fatalf("stored endpoints = (%+v, %t, %v), want the latest", set, found, err)
		}
	}

	first := endpointObservationWith(t, nodeID, 4, "192.0.2.21:41641", 1)
	if observe(first).Deferred {
		t.Fatal("the first change of a quiet Device was deferred")
	}
	announced("first change")
	second := endpointObservationWith(t, nodeID, 4, "192.0.2.22:41641", 1)
	third := endpointObservationWith(t, nodeID, 4, "192.0.2.23:41641", 1)
	for _, next := range []node.EndpointObservation{second, third} {
		announcement := observe(next)
		if !announcement.Deferred || announcement.RetryAfter <= 0 || announcement.RetryAfter > interval {
			t.Fatalf("a change within the interval was not deferred: %+v", announcement)
		}
		stored(next) // never dropped
	}
	silent("deferred changes")
	flush, err := client.FlushEndpoints(ctx, scope, nodeID, 4, interval)
	if err != nil || !flush.Deferred {
		t.Fatalf("an early flush = (%+v, %v), want deferred", flush, err)
	}
	silent("early flush")
	// Wait as long as Redis says, then flush: the latest change, once.
	for flush.Deferred {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(flush.RetryAfter):
		}
		if flush, err = client.FlushEndpoints(ctx, scope, nodeID, 4, interval); err != nil {
			t.Fatal(err)
		}
	}
	announced("flush")
	stored(third)
	if flush, err = client.FlushEndpoints(ctx, scope, nodeID, 4, interval); err != nil || flush.Deferred {
		t.Fatalf("a flush with nothing pending = (%+v, %v)", flush, err)
	}
	if announcement := observe(third); announcement.Deferred {
		t.Fatalf("an unchanged report was deferred: %+v", announcement)
	}
	silent("nothing pending and nothing changed")

	// A new disco key is announced at once, three times a minute.
	if observe(endpointObservationWith(t, nodeID, 4, "192.0.2.23:41641", 2)).Deferred {
		t.Fatal("a new disco key within the interval was deferred")
	}
	announced("new disco key")
	if announcement := observe(endpointObservationWith(t, nodeID, 4, "192.0.2.23:41641", 3)); !announcement.Deferred {
		t.Fatal("a second new disco key within its spacing was announced at once")
	}
	silent("disco spacing")
	// A new generation starts its own history.
	if observe(endpointObservationWith(t, nodeID, 5, "192.0.2.24:41641", 3)).Deferred {
		t.Fatal("a new generation was deferred")
	}
	announced("new generation")
}
