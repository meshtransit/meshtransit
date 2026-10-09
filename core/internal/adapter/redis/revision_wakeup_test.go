package redis

import (
	"context"
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/network"
)

const testNetworkPublicID = "01890f00-0000-7000-8000-000000000201"

func TestRevisionWakeupPayloadIsStrictAndBounded(t *testing.T) {
	t.Parallel()

	wakeup, err := network.NewRevisionAdvanced(testNetworkPublicID, 42)
	if err != nil {
		t.Fatalf("network.NewRevisionAdvanced() error = %v", err)
	}
	payload, err := encodeRevisionWakeup(wakeup)
	if err != nil {
		t.Fatalf("encodeRevisionWakeup() error = %v", err)
	}
	if len(payload) == 0 || len(payload) > maxRevisionWakeupPayloadBytes {
		t.Fatalf("encoded payload length = %d, want 1..%d", len(payload), maxRevisionWakeupPayloadBytes)
	}
	decoded, err := decodeRevisionWakeup(payload)
	if err != nil {
		t.Fatalf("decodeRevisionWakeup() error = %v", err)
	}
	if decoded != wakeup {
		t.Fatalf("decodeRevisionWakeup() = %+v, want %+v", decoded, wakeup)
	}

	invalidPayloads := []struct {
		name    string
		payload []byte
	}{
		{name: "empty", payload: nil},
		{name: "unknown field", payload: []byte(`{"network_public_id":"01890f00-0000-7000-8000-000000000201","revision":42,"token":"secret"}`)},
		{name: "trailing value", payload: append(append([]byte{}, payload...), []byte(` {}`)...)},
		{name: "oversized", payload: make([]byte, maxRevisionWakeupPayloadBytes+1)},
		{name: "invalid revision", payload: []byte(`{"network_public_id":"01890f00-0000-7000-8000-000000000201","revision":0}`)},
	}
	for _, test := range invalidPayloads {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := decodeRevisionWakeup(test.payload); !errors.Is(err, ErrInvalidRevisionWakeup) {
				t.Fatalf("decodeRevisionWakeup() error = %v, want ErrInvalidRevisionWakeup", err)
			}
		})
	}
}

func TestClientPublishesNetworkRevisionAdvanced(t *testing.T) {
	t.Parallel()

	wakeup, err := network.NewRevisionAdvanced(testNetworkPublicID, 42)
	if err != nil {
		t.Fatalf("network.NewRevisionAdvanced() error = %v", err)
	}
	ctx := t.Context()
	var gotContext context.Context
	var gotChannel string
	var gotPayload []byte
	client := &Client{
		publish: func(callContext context.Context, channel string, payload []byte) error {
			gotContext = callContext
			gotChannel = channel
			gotPayload = append([]byte(nil), payload...)
			return nil
		},
	}

	if err := client.PublishNetworkRevisionAdvanced(ctx, wakeup); err != nil {
		t.Fatalf("PublishNetworkRevisionAdvanced() error = %v", err)
	}
	if gotContext != ctx {
		t.Fatal("PublishNetworkRevisionAdvanced() did not propagate context")
	}
	if gotChannel != networkRevisionAdvancedChannel {
		t.Fatalf("publish channel = %q, want %q", gotChannel, networkRevisionAdvancedChannel)
	}
	decoded, err := decodeRevisionWakeup(gotPayload)
	if err != nil {
		t.Fatalf("decode published revision wakeup: %v", err)
	}
	if decoded != wakeup {
		t.Fatalf("published wakeup = %+v, want %+v", decoded, wakeup)
	}
}

func TestClientPublishNetworkRevisionAdvancedReturnsSafeErrors(t *testing.T) {
	t.Parallel()

	wakeup, err := network.NewRevisionAdvanced(testNetworkPublicID, 42)
	if err != nil {
		t.Fatalf("network.NewRevisionAdvanced() error = %v", err)
	}
	publishErr := errors.New("redis unavailable")
	client := &Client{
		publish: func(context.Context, string, []byte) error { return publishErr },
	}
	if err := client.PublishNetworkRevisionAdvanced(t.Context(), wakeup); !errors.Is(err, publishErr) ||
		!errors.Is(err, ErrPublishRevisionWakeup) {
		t.Fatalf("PublishNetworkRevisionAdvanced() error = %v, want classified publish error", err)
	}
	var nilContext context.Context
	if err := client.PublishNetworkRevisionAdvanced(nilContext, wakeup); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("PublishNetworkRevisionAdvanced(nil) error = %v, want ErrInvalidOptions", err)
	}
	if err := (*Client)(nil).PublishNetworkRevisionAdvanced(t.Context(), wakeup); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("nil Client PublishNetworkRevisionAdvanced() error = %v, want ErrInvalidOptions", err)
	}
}
