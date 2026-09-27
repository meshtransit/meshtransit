package main

import (
	"context"
	"errors"
	"time"

	redisadapter "github.com/meshtransit/meshtransit/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/network/revisionfeed"
)

var errInvalidRevisionFeedComposition = errors.New("invalid network revision feed composition")

func composeRevisionFeed(
	controlConfig config.ControlConfig,
	redisClient *redisadapter.Client,
) (*revisionfeed.Feed, *revisionfeed.Telemetry, error) {
	if redisClient == nil {
		return nil, nil, errInvalidRevisionFeedComposition
	}
	maxWatchers := controlConfig.MaxSessions * int(controlConfig.MaxStreamsPerSession)
	return newRevisionFeed(
		maxWatchers,
		controlConfig.Map.CoordinationTimeout,
		func(ctx context.Context) (revisionfeed.Subscription, error) {
			return redisClient.SubscribeNetworkRevisionAdvanced(ctx)
		},
	)
}

func newRevisionFeed(
	maxWatchers int,
	subscribeTimeout time.Duration,
	subscribe revisionfeed.SubscribeFunc,
) (*revisionfeed.Feed, *revisionfeed.Telemetry, error) {
	telemetry := revisionfeed.NewTelemetry()
	feed, err := revisionfeed.New(
		revisionfeed.Options{
			MaxWatchers:      maxWatchers,
			SubscribeTimeout: subscribeTimeout,
			ReconnectInitial: feedReconnectInitial,
			ReconnectMaximum: feedReconnectMaximum,
		},
		subscribe,
		telemetry,
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidRevisionFeedComposition, err)
	}
	return feed, telemetry, nil
}
