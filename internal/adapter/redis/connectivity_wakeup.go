package redis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
)

const (
	connectivityChangedChannel   = "meshtransit:v1:wakeup:connectivity_changed"
	connectivityWakeupVersion    = 1
	maxConnectivityWakeupPayload = 256
)

var (
	// ErrInvalidConnectivityWakeup reports a malformed or unsupported hint.
	ErrInvalidConnectivityWakeup = errors.New("redis: invalid connectivity wakeup")
	// ErrSubscribeConnectivityWakeup classifies subscription establishment failure.
	ErrSubscribeConnectivityWakeup = errors.New("redis: subscribe connectivity wakeup")
	// ErrReceiveConnectivityWakeup classifies transport failure while receiving.
	ErrReceiveConnectivityWakeup = errors.New("redis: receive connectivity wakeup")
)

type connectivityWakeupPayload struct {
	Version         int    `json:"version"`
	NetworkPublicID string `json:"network_public_id"`
	NodePublicID    string `json:"node_public_id"`
	Generation      int64  `json:"generation"`
	Kind            string `json:"kind"`
}

func encodeConnectivityWakeup(
	scope network.Scope,
	nodeID node.ID,
	generation int64,
	kind mapsession.ConnectivityChangeKind,
) ([]byte, error) {
	change, err := mapsession.NewConnectivityChanged(
		scope.NetworkID(),
		nodeID,
		generation,
		kind,
	)
	if err != nil || !scope.IsValid() {
		return nil, ErrInvalidConnectivityWakeup
	}
	payload, err := json.Marshal(connectivityWakeupPayload{
		Version:         connectivityWakeupVersion,
		NetworkPublicID: change.NetworkID().String(),
		NodePublicID:    change.Key().NodeID().String(),
		Generation:      change.Key().Generation(),
		Kind:            connectivityChangeKindName(change.Kind()),
	})
	if err != nil || len(payload) == 0 || len(payload) > maxConnectivityWakeupPayload {
		clear(payload)
		return nil, ErrInvalidConnectivityWakeup
	}
	return payload, nil
}

func decodeConnectivityWakeup(payload []byte) (mapsession.ConnectivityChanged, error) {
	if len(payload) == 0 || len(payload) > maxConnectivityWakeupPayload {
		return mapsession.ConnectivityChanged{}, ErrInvalidConnectivityWakeup
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire connectivityWakeupPayload
	if err := decoder.Decode(&wire); err != nil {
		return mapsession.ConnectivityChanged{}, ErrInvalidConnectivityWakeup
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) ||
		wire.Version != connectivityWakeupVersion {
		return mapsession.ConnectivityChanged{}, ErrInvalidConnectivityWakeup
	}
	networkID, err := network.ParseID(wire.NetworkPublicID)
	if err != nil {
		return mapsession.ConnectivityChanged{}, ErrInvalidConnectivityWakeup
	}
	nodeID, err := node.ParseID(wire.NodePublicID)
	if err != nil {
		return mapsession.ConnectivityChanged{}, ErrInvalidConnectivityWakeup
	}
	change, err := mapsession.NewConnectivityChanged(
		networkID,
		nodeID,
		wire.Generation,
		parseConnectivityChangeKind(wire.Kind),
	)
	if err != nil {
		return mapsession.ConnectivityChanged{}, ErrInvalidConnectivityWakeup
	}
	return change, nil
}

func connectivityChangeKindName(kind mapsession.ConnectivityChangeKind) string {
	switch kind {
	case mapsession.ConnectivityChangeEndpoints:
		return "endpoints"
	case mapsession.ConnectivityChangePresence:
		return "presence"
	default:
		return ""
	}
}

func parseConnectivityChangeKind(value string) mapsession.ConnectivityChangeKind {
	switch value {
	case "endpoints":
		return mapsession.ConnectivityChangeEndpoints
	case "presence":
		return mapsession.ConnectivityChangePresence
	default:
		return mapsession.ConnectivityChangeUnknown
	}
}

// SubscribeConnectivityChanged establishes the versioned transient wakeup channel.
func (client *Client) SubscribeConnectivityChanged(
	ctx context.Context,
) (*ConnectivitySubscription, error) {
	if ctx == nil || client == nil || client.subscribe == nil {
		return nil, ErrInvalidOptions
	}
	startedAt := time.Now()
	transport, err := client.subscribe(ctx, connectivityChangedChannel)
	if err != nil {
		client.metrics.observeCommand(redisCommandSubscribe, startedAt, err)
		return nil, errors.Join(ErrSubscribeConnectivityWakeup, err)
	}
	if transport == nil {
		client.metrics.observeCommand(
			redisCommandSubscribe,
			startedAt,
			ErrSubscribeConnectivityWakeup,
		)
		return nil, ErrSubscribeConnectivityWakeup
	}
	client.metrics.observeCommand(redisCommandSubscribe, startedAt, nil)
	client.metrics.subscriptionOpened()
	return &ConnectivitySubscription{transport: transport, metrics: client.metrics}, nil
}
