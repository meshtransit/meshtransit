package redis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"meshtransit.net/core/internal/domain/network"
)

const (
	networkRevisionAdvancedChannel = "meshtransit:v1:wakeup:network_revision_advanced"
	revisionWakeupVersion          = 1
	maxRevisionWakeupPayloadBytes  = 256
)

var (
	// ErrInvalidRevisionWakeup indicates a malformed or unsupported wakeup.
	ErrInvalidRevisionWakeup = errors.New("redis: invalid revision wakeup")
	// ErrPublishRevisionWakeup classifies a failed best-effort publish.
	ErrPublishRevisionWakeup = errors.New("redis: publish revision wakeup")
)

// PublishNetworkRevisionAdvanced emits a best-effort low-latency hint. Durable
// state and delivery intent must already be committed before this method runs.
func (client *Client) PublishNetworkRevisionAdvanced(
	ctx context.Context,
	revision network.RevisionAdvanced,
) error {
	if ctx == nil || client == nil || client.publish == nil {
		return ErrInvalidOptions
	}
	payload, err := encodeRevisionWakeup(revision)
	if err != nil {
		return err
	}
	startedAt := time.Now()
	err = client.publish(ctx, networkRevisionAdvancedChannel, payload)
	client.metrics.observeCommand(redisCommandPublish, startedAt, err)
	if err != nil {
		return errors.Join(ErrPublishRevisionWakeup, err)
	}
	return nil
}

type revisionWakeupPayload struct {
	Version         int    `json:"version"`
	NetworkPublicID string `json:"network_public_id"`
	Revision        int64  `json:"revision"`
}

func encodeRevisionWakeup(revision network.RevisionAdvanced) ([]byte, error) {
	if !revision.IsValid() {
		return nil, ErrInvalidRevisionWakeup
	}
	payload, err := json.Marshal(revisionWakeupPayload{
		Version:         revisionWakeupVersion,
		NetworkPublicID: revision.NetworkPublicID(),
		Revision:        revision.Number(),
	})
	if err != nil || len(payload) > maxRevisionWakeupPayloadBytes {
		return nil, ErrInvalidRevisionWakeup
	}
	return payload, nil
}

func decodeRevisionWakeup(payload []byte) (network.RevisionAdvanced, error) {
	if len(payload) == 0 || len(payload) > maxRevisionWakeupPayloadBytes {
		return network.RevisionAdvanced{}, ErrInvalidRevisionWakeup
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var value revisionWakeupPayload
	if err := decoder.Decode(&value); err != nil {
		return network.RevisionAdvanced{}, ErrInvalidRevisionWakeup
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return network.RevisionAdvanced{}, ErrInvalidRevisionWakeup
	}
	if value.Version != revisionWakeupVersion {
		return network.RevisionAdvanced{}, ErrInvalidRevisionWakeup
	}
	revision, err := network.NewRevisionAdvanced(value.NetworkPublicID, value.Revision)
	if err != nil {
		return network.RevisionAdvanced{}, ErrInvalidRevisionWakeup
	}
	return revision, nil
}
