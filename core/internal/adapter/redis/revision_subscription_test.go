package redis

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	redisclient "github.com/redis/go-redis/v9"
)

func TestClientSubscribesAndReceivesNetworkRevisionAdvanced(t *testing.T) {
	t.Parallel()

	wakeup, err := network.NewRevisionAdvanced(testNetworkPublicID, 42)
	if err != nil {
		t.Fatalf("network.NewRevisionAdvanced() error = %v", err)
	}
	payload, err := encodeRevisionWakeup(wakeup)
	if err != nil {
		t.Fatalf("encodeRevisionWakeup() error = %v", err)
	}
	transport := &fakeMessageSubscription{
		message: &redisclient.Message{
			Channel: networkRevisionAdvancedChannel,
			Payload: string(payload),
		},
	}
	ctx := t.Context()
	var gotSubscribeContext context.Context
	var gotChannel string
	client := &Client{
		subscribe: func(callContext context.Context, channel string) (messageSubscription, error) {
			gotSubscribeContext = callContext
			gotChannel = channel
			return transport, nil
		},
	}

	subscription, err := client.SubscribeNetworkRevisionAdvanced(ctx)
	if err != nil {
		t.Fatalf("SubscribeNetworkRevisionAdvanced() error = %v", err)
	}
	if gotSubscribeContext != ctx || gotChannel != networkRevisionAdvancedChannel {
		t.Fatalf("subscribe input = (%v, %q), want propagated context and %q", gotSubscribeContext, gotChannel, networkRevisionAdvancedChannel)
	}
	got, err := subscription.Receive(ctx)
	if err != nil {
		t.Fatalf("RevisionSubscription.Receive() error = %v", err)
	}
	if got != wakeup {
		t.Fatalf("RevisionSubscription.Receive() = %+v, want %+v", got, wakeup)
	}
	if transport.receiveContext != ctx {
		t.Fatal("RevisionSubscription.Receive() did not propagate context")
	}
}

func TestRevisionSubscriptionRejectsUnexpectedInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport *fakeMessageSubscription
		wantErr   error
	}{
		{
			name: "receive failure",
			transport: &fakeMessageSubscription{
				receiveErr: errors.New("connection closed"),
			},
			wantErr: ErrReceiveRevisionWakeup,
		},
		{
			name: "wrong channel",
			transport: &fakeMessageSubscription{
				message: &redisclient.Message{Channel: "other", Payload: `{}`},
			},
			wantErr: ErrInvalidRevisionWakeup,
		},
		{
			name: "invalid payload",
			transport: &fakeMessageSubscription{
				message: &redisclient.Message{Channel: networkRevisionAdvancedChannel, Payload: `{}`},
			},
			wantErr: ErrInvalidRevisionWakeup,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			subscription := newRevisionSubscription(test.transport, nil)
			if _, err := subscription.Receive(t.Context()); !errors.Is(err, test.wantErr) {
				t.Fatalf("RevisionSubscription.Receive() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestClientSubscribeNetworkRevisionAdvancedClassifiesFailure(t *testing.T) {
	t.Parallel()

	subscribeErr := errors.New("redis unavailable")
	client := &Client{
		subscribe: func(context.Context, string) (messageSubscription, error) {
			return nil, subscribeErr
		},
	}
	if _, err := client.SubscribeNetworkRevisionAdvanced(t.Context()); !errors.Is(err, subscribeErr) ||
		!errors.Is(err, ErrSubscribeRevisionWakeup) {
		t.Fatalf("SubscribeNetworkRevisionAdvanced() error = %v, want classified subscribe error", err)
	}
	var nilContext context.Context
	if _, err := client.SubscribeNetworkRevisionAdvanced(nilContext); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("SubscribeNetworkRevisionAdvanced(nil) error = %v, want ErrInvalidOptions", err)
	}
}

func TestClientSubscribeNetworkRevisionAdvancedRejectsNilTransport(t *testing.T) {
	t.Parallel()

	metrics := newRedisMetrics(1, nil)
	client := &Client{
		subscribe: func(context.Context, string) (messageSubscription, error) {
			return nil, nil
		},
		metrics: metrics,
	}
	if _, err := client.SubscribeNetworkRevisionAdvanced(t.Context()); !errors.Is(
		err,
		ErrSubscribeRevisionWakeup,
	) {
		t.Fatalf("SubscribeNetworkRevisionAdvanced() error = %v, want ErrSubscribeRevisionWakeup", err)
	}

	body := gatherRedisMetrics(t, metrics)
	if !strings.Contains(
		body,
		`meshtransit_redis_commands_total{operation="subscribe",result="error"} 1`,
	) {
		t.Fatalf("metrics did not classify nil transport as an error: %s", body)
	}
}

func TestRevisionSubscriptionConcurrentCloseRunsOnce(t *testing.T) {
	t.Parallel()

	var closeCalls atomic.Int32
	transport := &fakeMessageSubscription{
		closeFunc: func() error {
			closeCalls.Add(1)
			return nil
		},
	}
	metrics := newRedisMetrics(1, nil)
	metrics.subscriptionOpened()
	subscription := newRevisionSubscription(transport, metrics)
	start := make(chan struct{})
	var callers sync.WaitGroup
	for range 32 {
		callers.Go(func() {
			<-start
			if err := subscription.Close(); err != nil {
				t.Errorf("RevisionSubscription.Close() error = %v", err)
			}
		})
	}
	close(start)
	callers.Wait()
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("close calls = %d, want 1", got)
	}
	if body := gatherRedisMetrics(t, metrics); !strings.Contains(
		body,
		`meshtransit_redis_subscriptions_active 0`,
	) {
		t.Fatalf("metrics did not release concurrently closed subscription: %s", body)
	}
}

func TestRevisionSubscriptionCloseFailureRemainsObservable(t *testing.T) {
	t.Parallel()

	closeErr := errors.New("close failed")
	metrics := newRedisMetrics(1, nil)
	metrics.subscriptionOpened()
	subscription := newRevisionSubscription(&fakeMessageSubscription{
		closeFunc: func() error { return closeErr },
	}, metrics)

	if err := subscription.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("RevisionSubscription.Close() error = %v, want close failure", err)
	}
	if body := gatherRedisMetrics(t, metrics); !strings.Contains(
		body,
		`meshtransit_redis_subscriptions_active 1`,
	) {
		t.Fatalf("metrics hid a subscription with uncertain close state: %s", body)
	}
}

type fakeMessageSubscription struct {
	message        *redisclient.Message
	receiveErr     error
	receiveContext context.Context
	closeFunc      func() error
}

func (subscription *fakeMessageSubscription) ReceiveMessage(ctx context.Context) (*redisclient.Message, error) {
	subscription.receiveContext = ctx
	return subscription.message, subscription.receiveErr
}

func (subscription *fakeMessageSubscription) Close() error {
	if subscription.closeFunc == nil {
		return nil
	}
	return subscription.closeFunc()
}
