package main

import (
	"context"
	"errors"
	"time"

	redisadapter "github.com/meshtransit/meshtransit/core/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/core/internal/control/connectivityfeed"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

var errInvalidConnectivityFeedComposition = errors.New("invalid connectivity feed composition")

func composeConnectivityFeed(
	controlConfig config.ControlConfig,
	redisClient *redisadapter.Client,
) (*connectivityfeed.Feed, *connectivityfeed.Telemetry, error) {
	if redisClient == nil {
		return nil, nil, errInvalidConnectivityFeedComposition
	}
	maxWatchers := controlConfig.MaxSessions * int(controlConfig.MaxStreamsPerSession)
	return newConnectivityFeed(
		maxWatchers,
		controlConfig.Map.CoordinationTimeout,
		func(ctx context.Context) (connectivityfeed.Subscription, error) {
			return redisClient.SubscribeConnectivityChanged(ctx)
		},
	)
}

func newConnectivityFeed(
	maxWatchers int,
	subscribeTimeout time.Duration,
	subscribe connectivityfeed.SubscribeFunc,
) (*connectivityfeed.Feed, *connectivityfeed.Telemetry, error) {
	telemetry := connectivityfeed.NewTelemetry()
	feed, err := connectivityfeed.New(
		connectivityfeed.Options{
			MaxWatchers:      maxWatchers,
			SubscribeTimeout: subscribeTimeout,
			ReconnectInitial: feedReconnectInitial,
			ReconnectMaximum: feedReconnectMaximum,
		},
		subscribe,
		telemetry,
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidConnectivityFeedComposition, err)
	}
	return feed, telemetry, nil
}
