package redis

import (
	"context"
	"errors"
	"testing"

	redisclient "github.com/redis/go-redis/v9"

	"meshtransit.net/core/internal/domain/publicid"
)

func TestKubeCertHintsRoundTrip(t *testing.T) {
	t.Parallel()
	request, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	published := map[string]string{}
	client := &Client{publish: func(_ context.Context, channel string, payload []byte) error {
		published[channel] = string(payload)
		return nil
	}}
	if err := client.PublishKubeCertQueued(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := client.PublishKubeCertSettled(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	if err := client.PublishKubeCertSettled(t.Context(), publicid.ID{}); !errors.Is(err, ErrInvalidKubeCertWakeup) {
		t.Fatalf("a zero request was published: %v", err)
	}
	for channel, kind := range map[string]string{
		kubeCertQueuedChannel: kubeCertWakeupKindQueued, kubeCertSettledChannel: kubeCertWakeupKindSettled,
	} {
		transport := &fakeMessageSubscription{message: &redisclient.Message{Channel: channel,
			Payload: published[channel]}}
		var subscribed string
		client.subscribe = func(_ context.Context, got string) (messageSubscription, error) {
			subscribed = got
			return transport, nil
		}
		subscribe := client.SubscribeKubeCertQueued
		if kind == kubeCertWakeupKindSettled {
			subscribe = client.SubscribeKubeCertSettled
		}
		subscription, err := subscribe(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		got, err := subscription.Receive(t.Context())
		want := publicid.ID{}
		if kind == kubeCertWakeupKindSettled {
			want = request
		}
		if err != nil || got != want || subscribed != channel {
			t.Fatalf("%s: Receive() = %v, %v on %q", kind, got, err, subscribed)
		}
		if err := subscription.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestKubeCertHintsRejectMalformedPayload(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ payload, kind string }{
		{"", kubeCertWakeupKindQueued},
		{`{"version":2,"kind":"queued"}`, kubeCertWakeupKindQueued},
		{`{"version":1,"kind":"settled","request":"01890f00-0000-7000-8000-000000000201"}`, kubeCertWakeupKindQueued},
		{`{"version":1,"kind":"queued","request":"01890f00-0000-7000-8000-000000000201"}`, kubeCertWakeupKindQueued},
		{`{"version":1,"kind":"settled"}`, kubeCertWakeupKindSettled},
		{`{"version":1,"kind":"settled","request":"not-an-id"}`, kubeCertWakeupKindSettled},
		{`{"version":1,"kind":"settled","request":"01890f00-0000-7000-8000-000000000201","extra":1}`,
			kubeCertWakeupKindSettled},
	} {
		if _, err := decodeKubeCertWakeup([]byte(test.payload), test.kind); !errors.Is(err,
			ErrInvalidKubeCertWakeup) {
			t.Errorf("decodeKubeCertWakeup(%q) error = %v", test.payload, err)
		}
	}
}
