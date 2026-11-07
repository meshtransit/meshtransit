package redis

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	// deviceAliasClaimedChannel carries no identifier: it only tells the
	// Device alias workers that a client claimed aliases, so alias work may
	// be waiting (docs/performance-logic-plan.md §8, L1b). Best effort: the
	// workers still sweep at least every idle interval.
	deviceAliasClaimedChannel = "meshtransit:v1:wakeup:device_alias_claimed"
	deviceAliasClaimedPayload = `{"version":1}`
)

var (
	// ErrInvalidDeviceAliasWakeup reports a foreign or malformed message.
	ErrInvalidDeviceAliasWakeup = errors.New("redis: invalid Device alias wakeup")
	// ErrDeviceAliasWakeup classifies a failed publish, subscription or
	// receive.
	ErrDeviceAliasWakeup = errors.New("redis: Device alias wakeup")
)

// PublishDeviceAliasClaimed tells the Device alias workers a client claimed
// aliases.
func (client *Client) PublishDeviceAliasClaimed(ctx context.Context) error {
	if ctx == nil || client == nil || client.publish == nil {
		return ErrInvalidOptions
	}
	startedAt := time.Now()
	err := client.publish(ctx, deviceAliasClaimedChannel, []byte(deviceAliasClaimedPayload))
	client.metrics.observeCommand(redisCommandPublish, startedAt, err)
	if err != nil {
		return errors.Join(ErrDeviceAliasWakeup, err)
	}
	return nil
}

// DeviceAliasSubscription receives Device alias claim hints. It starts no
// goroutine.
type DeviceAliasSubscription struct {
	transport messageSubscription
	metrics   *redisMetrics

	closeOnce sync.Once
	closeErr  error
}

// SubscribeDeviceAliasClaimed subscribes a Device alias worker to claims.
func (client *Client) SubscribeDeviceAliasClaimed(ctx context.Context) (*DeviceAliasSubscription, error) {
	if ctx == nil || client == nil || client.subscribe == nil {
		return nil, ErrInvalidOptions
	}
	startedAt := time.Now()
	transport, err := client.subscribe(ctx, deviceAliasClaimedChannel)
	if err == nil && transport == nil {
		err = ErrDeviceAliasWakeup
	}
	client.metrics.observeCommand(redisCommandSubscribe, startedAt, err)
	if err != nil {
		return nil, errors.Join(ErrDeviceAliasWakeup, err)
	}
	client.metrics.subscriptionOpened()
	return &DeviceAliasSubscription{transport: transport, metrics: client.metrics}, nil
}

// Receive waits for one claim hint or caller cancellation. A foreign or
// malformed message is ErrInvalidDeviceAliasWakeup; the subscription still
// works.
func (subscription *DeviceAliasSubscription) Receive(ctx context.Context) error {
	if ctx == nil || subscription == nil || subscription.transport == nil {
		return ErrInvalidOptions
	}
	startedAt := time.Now()
	message, err := subscription.transport.ReceiveMessage(ctx)
	subscription.metrics.observeCommand(redisCommandReceive, startedAt, err)
	if err != nil {
		return errors.Join(ErrDeviceAliasWakeup, err)
	}
	if message == nil || message.Channel != deviceAliasClaimedChannel || message.Payload != deviceAliasClaimedPayload {
		return ErrInvalidDeviceAliasWakeup
	}
	return nil
}

// Close releases the dedicated Pub/Sub connection exactly once.
func (subscription *DeviceAliasSubscription) Close() error {
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
