package redis

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/meshtransit/meshtransit/internal/network"
	redisclient "github.com/redis/go-redis/v9"
)

var (
	// ErrSubscribeRevisionWakeup classifies subscription establishment failure.
	ErrSubscribeRevisionWakeup = errors.New("redis: subscribe revision wakeup")
	// ErrReceiveRevisionWakeup classifies transport failure while receiving.
	ErrReceiveRevisionWakeup = errors.New("redis: receive revision wakeup")
)

type messageSubscription interface {
	ReceiveMessage(context.Context) (*redisclient.Message, error)
	Close() error
}

// RevisionSubscription is a synchronous, caller-driven Redis subscription.
// It starts no goroutine; the caller owns its receive loop and cancellation.
type RevisionSubscription struct {
	transport messageSubscription
	metrics   *redisMetrics

	closeOnce sync.Once
	closeErr  error
}

// SubscribeNetworkRevisionAdvanced establishes the versioned wakeup channel.
func (client *Client) SubscribeNetworkRevisionAdvanced(ctx context.Context) (*RevisionSubscription, error) {
	if ctx == nil || client == nil || client.subscribe == nil {
		return nil, ErrInvalidOptions
	}
	startedAt := time.Now()
	transport, err := client.subscribe(ctx, networkRevisionAdvancedChannel)
	if err != nil {
		client.metrics.observeCommand(redisCommandSubscribe, startedAt, err)
		return nil, errors.Join(ErrSubscribeRevisionWakeup, err)
	}
	if transport == nil {
		client.metrics.observeCommand(redisCommandSubscribe, startedAt, ErrSubscribeRevisionWakeup)
		return nil, ErrSubscribeRevisionWakeup
	}
	client.metrics.observeCommand(redisCommandSubscribe, startedAt, nil)
	client.metrics.subscriptionOpened()
	return newRevisionSubscription(transport, client.metrics), nil
}

func newRevisionSubscription(
	transport messageSubscription,
	metrics *redisMetrics,
) *RevisionSubscription {
	return &RevisionSubscription{transport: transport, metrics: metrics}
}

// Receive waits for one wakeup or caller cancellation and validates the exact
// channel and bounded payload before returning it.
func (subscription *RevisionSubscription) Receive(ctx context.Context) (network.RevisionAdvanced, error) {
	if ctx == nil || subscription == nil || subscription.transport == nil {
		return network.RevisionAdvanced{}, ErrInvalidOptions
	}
	startedAt := time.Now()
	message, err := subscription.transport.ReceiveMessage(ctx)
	subscription.metrics.observeCommand(redisCommandReceive, startedAt, err)
	if err != nil {
		return network.RevisionAdvanced{}, errors.Join(ErrReceiveRevisionWakeup, err)
	}
	if message == nil || message.Channel != networkRevisionAdvancedChannel {
		return network.RevisionAdvanced{}, ErrInvalidRevisionWakeup
	}
	return decodeRevisionWakeup([]byte(message.Payload))
}

// Close releases the dedicated Pub/Sub connection exactly once.
func (subscription *RevisionSubscription) Close() error {
	if subscription == nil || subscription.transport == nil {
		return ErrInvalidOptions
	}
	subscription.closeOnce.Do(func() {
		subscription.closeErr = subscription.transport.Close()
		if subscription.closeErr == nil {
			subscription.metrics.subscriptionClosed()
		}
	})
	return subscription.closeErr
}
