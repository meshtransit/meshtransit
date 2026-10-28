package redis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
)

// Kubernetes gateway certificate hints (a3 §14 R-H3): control tells the
// signing workers a request was queued, and the worker that settled a
// request tells control which one, so neither polls the database at speed.
// Both are best effort; the worker still looks at the queue every 250 ms
// and control reads a waiting request back at least every second.
const (
	kubeCertQueuedChannel     = "meshtransit:v1:wakeup:kube_cert_queued"
	kubeCertSettledChannel    = "meshtransit:v1:wakeup:kube_cert_settled"
	kubeCertWakeupVersion     = 1
	maxKubeCertWakeupPayload  = 128
	kubeCertWakeupKindQueued  = "queued"
	kubeCertWakeupKindSettled = "settled"
)

var (
	// ErrInvalidKubeCertWakeup reports a malformed or unsupported hint.
	ErrInvalidKubeCertWakeup = errors.New("redis: invalid Kubernetes certificate wakeup")
	// ErrKubeCertWakeup classifies a failed publish, subscription or
	// receive.
	ErrKubeCertWakeup = errors.New("redis: Kubernetes certificate wakeup")
)

type kubeCertWakeupPayload struct {
	Version int    `json:"version"`
	Kind    string `json:"kind"`
	Request string `json:"request,omitempty"`
}

// PublishKubeCertQueued tells the signing workers a request waits.
func (client *Client) PublishKubeCertQueued(ctx context.Context) error {
	return client.publishKubeCert(ctx, kubeCertQueuedChannel,
		kubeCertWakeupPayload{Version: kubeCertWakeupVersion, Kind: kubeCertWakeupKindQueued})
}

// PublishKubeCertSettled tells control a request was issued or refused.
func (client *Client) PublishKubeCertSettled(ctx context.Context, request publicid.ID) error {
	if !request.IsValid() {
		return ErrInvalidKubeCertWakeup
	}
	return client.publishKubeCert(ctx, kubeCertSettledChannel, kubeCertWakeupPayload{
		Version: kubeCertWakeupVersion, Kind: kubeCertWakeupKindSettled, Request: request.String(),
	})
}

func (client *Client) publishKubeCert(ctx context.Context, channel string, wire kubeCertWakeupPayload) error {
	if ctx == nil || client == nil || client.publish == nil {
		return ErrInvalidOptions
	}
	payload, err := json.Marshal(wire)
	if err != nil || len(payload) > maxKubeCertWakeupPayload {
		return ErrInvalidKubeCertWakeup
	}
	startedAt := time.Now()
	err = client.publish(ctx, channel, payload)
	client.metrics.observeCommand(redisCommandPublish, startedAt, err)
	if err != nil {
		return errors.Join(ErrKubeCertWakeup, err)
	}
	return nil
}

// KubeCertSubscription receives one kind of Kubernetes certificate hint. It
// starts no goroutine.
type KubeCertSubscription struct {
	transport messageSubscription
	metrics   *redisMetrics
	channel   string
	kind      string

	closeOnce sync.Once
	closeErr  error
}

// SubscribeKubeCertQueued subscribes a signing worker to queued requests.
func (client *Client) SubscribeKubeCertQueued(ctx context.Context) (*KubeCertSubscription, error) {
	return client.subscribeKubeCert(ctx, kubeCertQueuedChannel, kubeCertWakeupKindQueued)
}

// SubscribeKubeCertSettled subscribes control to settled requests.
func (client *Client) SubscribeKubeCertSettled(ctx context.Context) (*KubeCertSubscription, error) {
	return client.subscribeKubeCert(ctx, kubeCertSettledChannel, kubeCertWakeupKindSettled)
}

func (client *Client) subscribeKubeCert(ctx context.Context, channel, kind string) (*KubeCertSubscription,
	error,
) {
	if ctx == nil || client == nil || client.subscribe == nil {
		return nil, ErrInvalidOptions
	}
	startedAt := time.Now()
	transport, err := client.subscribe(ctx, channel)
	if err == nil && transport == nil {
		err = ErrKubeCertWakeup
	}
	client.metrics.observeCommand(redisCommandSubscribe, startedAt, err)
	if err != nil {
		return nil, errors.Join(ErrKubeCertWakeup, err)
	}
	client.metrics.subscriptionOpened()
	return &KubeCertSubscription{transport: transport, metrics: client.metrics, channel: channel, kind: kind}, nil
}

// Receive waits for one hint: the request settled, or the zero ID for a
// queued request.
func (subscription *KubeCertSubscription) Receive(ctx context.Context) (publicid.ID, error) {
	if ctx == nil || subscription == nil || subscription.transport == nil {
		return publicid.ID{}, ErrInvalidOptions
	}
	startedAt := time.Now()
	message, err := subscription.transport.ReceiveMessage(ctx)
	subscription.metrics.observeCommand(redisCommandReceive, startedAt, err)
	if err != nil {
		return publicid.ID{}, errors.Join(ErrKubeCertWakeup, err)
	}
	if message == nil || message.Channel != subscription.channel {
		return publicid.ID{}, ErrInvalidKubeCertWakeup
	}
	return decodeKubeCertWakeup([]byte(message.Payload), subscription.kind)
}

// Close releases the dedicated Pub/Sub connection exactly once.
func (subscription *KubeCertSubscription) Close() error {
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

func decodeKubeCertWakeup(payload []byte, kind string) (publicid.ID, error) {
	if len(payload) == 0 || len(payload) > maxKubeCertWakeupPayload {
		return publicid.ID{}, ErrInvalidKubeCertWakeup
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire kubeCertWakeupPayload
	if err := decoder.Decode(&wire); err != nil {
		return publicid.ID{}, ErrInvalidKubeCertWakeup
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || wire.Version != kubeCertWakeupVersion ||
		wire.Kind != kind {
		return publicid.ID{}, ErrInvalidKubeCertWakeup
	}
	if kind == kubeCertWakeupKindQueued {
		if wire.Request != "" {
			return publicid.ID{}, ErrInvalidKubeCertWakeup
		}
		return publicid.ID{}, nil
	}
	request, err := publicid.Parse(wire.Request)
	if err != nil {
		return publicid.ID{}, ErrInvalidKubeCertWakeup
	}
	return request, nil
}
