package redis

import (
	"context"
	"errors"
	"testing"

	redisclient "github.com/redis/go-redis/v9"
)

func TestDeviceAliasClaimedHintRoundTrip(t *testing.T) {
	t.Parallel()
	var channel, payload string
	client := &Client{publish: func(_ context.Context, got string, body []byte) error {
		channel, payload = got, string(body)
		return nil
	}}
	if err := client.PublishDeviceAliasClaimed(t.Context()); err != nil {
		t.Fatal(err)
	}
	if channel != "meshtransit:v1:wakeup:device_alias_claimed" || payload != `{"version":1}` {
		t.Fatalf("published %q on %q", payload, channel)
	}
	var subscribed string
	client.subscribe = func(_ context.Context, got string) (messageSubscription, error) {
		subscribed = got
		return &fakeMessageSubscription{message: &redisclient.Message{Channel: channel, Payload: payload}}, nil
	}
	subscription, err := client.SubscribeDeviceAliasClaimed(t.Context())
	if err != nil || subscribed != channel {
		t.Fatalf("SubscribeDeviceAliasClaimed() = %v on %q", err, subscribed)
	}
	if err := subscription.Receive(t.Context()); err != nil {
		t.Fatalf("Receive() error = %v", err)
	}
	if err := subscription.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceAliasClaimedHintRejectsForeignMessages(t *testing.T) {
	t.Parallel()
	for _, message := range []*redisclient.Message{
		nil,
		{Channel: "meshtransit:v1:wakeup:site_health_failed", Payload: `{"version":1}`},
		{Channel: "meshtransit:v1:wakeup:device_alias_claimed", Payload: `{"version":2}`},
		{Channel: "meshtransit:v1:wakeup:device_alias_claimed", Payload: `{"version":1,"device":"x"}`},
	} {
		client := &Client{subscribe: func(context.Context, string) (messageSubscription, error) {
			return &fakeMessageSubscription{message: message}, nil
		}}
		subscription, err := client.SubscribeDeviceAliasClaimed(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := subscription.Receive(t.Context()); !errors.Is(err, ErrInvalidDeviceAliasWakeup) {
			t.Errorf("Receive(%+v) error = %v, want ErrInvalidDeviceAliasWakeup", message, err)
		}
	}
}

func TestDeviceAliasClaimedHintReportsTransportFailures(t *testing.T) {
	t.Parallel()
	failure := errors.New("connection reset")
	client := &Client{
		publish: func(context.Context, string, []byte) error { return failure },
		subscribe: func(context.Context, string) (messageSubscription, error) {
			return &fakeMessageSubscription{receiveErr: failure}, nil
		},
	}
	if err := client.PublishDeviceAliasClaimed(t.Context()); !errors.Is(err, ErrDeviceAliasWakeup) {
		t.Fatalf("PublishDeviceAliasClaimed() error = %v", err)
	}
	subscription, err := client.SubscribeDeviceAliasClaimed(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := subscription.Receive(t.Context()); !errors.Is(err, ErrDeviceAliasWakeup) ||
		errors.Is(err, ErrInvalidDeviceAliasWakeup) {
		t.Fatalf("Receive() error = %v, want a transport failure", err)
	}
}
