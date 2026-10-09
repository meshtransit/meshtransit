package redis

import (
	"context"
	"errors"
	"testing"

	redisclient "github.com/redis/go-redis/v9"

	"meshtransit.net/core/internal/control/mapsession"
)

func TestConnectivityWakeupRoundTrip(t *testing.T) {
	t.Parallel()

	scope := testNetworkScope(t)
	observation := testEndpointObservation(t, 7)
	payload, err := encodeConnectivityWakeup(
		scope,
		observation.NodeID(),
		observation.Generation(),
		mapsession.ConnectivityChangeEndpoints,
	)
	if err != nil {
		t.Fatalf("encodeConnectivityWakeup() error = %v", err)
	}
	change, err := decodeConnectivityWakeup(payload)
	if err != nil {
		t.Fatalf("decodeConnectivityWakeup() error = %v", err)
	}
	if change.NetworkID() != scope.NetworkID() ||
		change.Key().NodeID() != observation.NodeID() ||
		change.Key().Generation() != observation.Generation() ||
		change.Kind() != mapsession.ConnectivityChangeEndpoints {
		t.Fatalf("connectivity wakeup = %+v, want exact scope and generation", change)
	}
}

func TestConnectivityWakeupRejectsMalformedPayload(t *testing.T) {
	t.Parallel()

	for _, payload := range [][]byte{
		nil,
		[]byte(`{"version":2}`),
		[]byte(`{"version":1,"network_public_id":"01890f00-0000-7000-8000-000000000201","node_public_id":"01890f00-0000-7000-8000-000000000701","generation":1,"extra":true}`),
		[]byte(`{"version":1,"network_public_id":"01890f00-0000-7000-8000-000000000201","node_public_id":"01890f00-0000-7000-8000-000000000701","generation":0}`),
	} {
		if _, err := decodeConnectivityWakeup(payload); !errors.Is(err, ErrInvalidConnectivityWakeup) {
			t.Fatalf("decodeConnectivityWakeup(%q) error = %v", payload, err)
		}
	}
}

func TestClientSubscribesAndReceivesConnectivityWakeup(t *testing.T) {
	t.Parallel()

	scope := testNetworkScope(t)
	observation := testEndpointObservation(t, 7)
	payload, err := encodeConnectivityWakeup(
		scope,
		observation.NodeID(),
		observation.Generation(),
		mapsession.ConnectivityChangeEndpoints,
	)
	if err != nil {
		t.Fatalf("encodeConnectivityWakeup() error = %v", err)
	}
	transport := &fakeMessageSubscription{message: &redisclient.Message{
		Channel: connectivityChangedChannel,
		Payload: string(payload),
	}}
	var channel string
	client := &Client{subscribe: func(_ context.Context, got string) (messageSubscription, error) {
		channel = got
		return transport, nil
	}}
	subscription, err := client.SubscribeConnectivityChanged(t.Context())
	if err != nil {
		t.Fatalf("SubscribeConnectivityChanged() error = %v", err)
	}
	change, err := subscription.Receive(t.Context())
	if err != nil {
		t.Fatalf("ConnectivitySubscription.Receive() error = %v", err)
	}
	if channel != connectivityChangedChannel || change.NetworkID() != scope.NetworkID() ||
		change.Key().NodeID() != observation.NodeID() {
		t.Fatalf("subscription = channel %q change %+v", channel, change)
	}
	if err := subscription.Close(); err != nil {
		t.Fatalf("ConnectivitySubscription.Close() error = %v", err)
	}
}
