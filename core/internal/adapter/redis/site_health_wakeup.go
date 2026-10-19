package redis

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	// siteHealthFailedChannel carries no identifier: it only tells the Site
	// election worker to judge every Site now instead of at its next pass.
	siteHealthFailedChannel = "meshtransit:v1:wakeup:site_health_failed"
	siteHealthFailedPayload = `{"version":1}`
)

var (
	// ErrSubscribeSiteHealthWakeup classifies subscription establishment failure.
	ErrSubscribeSiteHealthWakeup = errors.New("redis: subscribe Site health wakeup")
	// ErrReceiveSiteHealthWakeup classifies transport failure or a foreign message.
	ErrReceiveSiteHealthWakeup = errors.New("redis: receive Site health wakeup")
)

// SiteHealthSubscription is a synchronous, caller-driven Redis
// subscription to failed Site health. It starts no goroutine.
type SiteHealthSubscription struct {
	transport messageSubscription
	metrics   *redisMetrics

	closeOnce sync.Once
	closeErr  error
}

// SubscribeSiteHealthFailed establishes the wakeup channel.
func (client *Client) SubscribeSiteHealthFailed(ctx context.Context) (*SiteHealthSubscription, error) {
	if ctx == nil || client == nil || client.subscribe == nil {
		return nil, ErrInvalidOptions
	}
	startedAt := time.Now()
	transport, err := client.subscribe(ctx, siteHealthFailedChannel)
	if err == nil && transport == nil {
		err = ErrSubscribeSiteHealthWakeup
	}
	client.metrics.observeCommand(redisCommandSubscribe, startedAt, err)
	if err != nil {
		return nil, errors.Join(ErrSubscribeSiteHealthWakeup, err)
	}
	client.metrics.subscriptionOpened()
	return &SiteHealthSubscription{transport: transport, metrics: client.metrics}, nil
}

// Receive waits for one wakeup or caller cancellation.
func (subscription *SiteHealthSubscription) Receive(ctx context.Context) error {
	if ctx == nil || subscription == nil || subscription.transport == nil {
		return ErrInvalidOptions
	}
	startedAt := time.Now()
	message, err := subscription.transport.ReceiveMessage(ctx)
	subscription.metrics.observeCommand(redisCommandReceive, startedAt, err)
	if err != nil {
		return errors.Join(ErrReceiveSiteHealthWakeup, err)
	}
	if message == nil || message.Channel != siteHealthFailedChannel || message.Payload != siteHealthFailedPayload {
		return ErrReceiveSiteHealthWakeup
	}
	return nil
}

// Close releases the dedicated Pub/Sub connection exactly once.
func (subscription *SiteHealthSubscription) Close() error {
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
