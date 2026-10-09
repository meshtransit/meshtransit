package redis

import (
	"context"
	"errors"
	"sync"
	"time"

	"meshtransit.net/core/internal/control/mapsession"
)

// ConnectivitySubscription is a synchronous, caller-driven Redis
// subscription. It starts no goroutine.
type ConnectivitySubscription struct {
	transport messageSubscription
	metrics   *redisMetrics

	closeOnce sync.Once
	closeErr  error
}

// Receive waits for one validated connectivity wakeup or caller cancellation.
func (subscription *ConnectivitySubscription) Receive(
	ctx context.Context,
) (mapsession.ConnectivityChanged, error) {
	if ctx == nil || subscription == nil || subscription.transport == nil {
		return mapsession.ConnectivityChanged{}, ErrInvalidOptions
	}
	startedAt := time.Now()
	message, err := subscription.transport.ReceiveMessage(ctx)
	subscription.metrics.observeCommand(redisCommandReceive, startedAt, err)
	if err != nil {
		return mapsession.ConnectivityChanged{}, errors.Join(ErrReceiveConnectivityWakeup, err)
	}
	if message == nil || message.Channel != connectivityChangedChannel {
		return mapsession.ConnectivityChanged{}, ErrInvalidConnectivityWakeup
	}
	return decodeConnectivityWakeup([]byte(message.Payload))
}

// Close releases the dedicated Pub/Sub connection exactly once.
func (subscription *ConnectivitySubscription) Close() error {
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
