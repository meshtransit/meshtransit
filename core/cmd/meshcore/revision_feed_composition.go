package main

import (
	"context"
	"errors"
	"time"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/domain/network/revisionfeed"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidRevisionFeedComposition = errors.New("invalid network revision feed composition")

// mapWatchersPerSession is the feed watchers one MTCP session may hold: its
// map stream watches its own Network and every Network it imports Devices
// from, and a reconnecting node briefly holds the old and the new stream.
// It keeps the budget the control process had before MTCP (8 per session).
const mapWatchersPerSession = 8

// mapStreamWatchers bounds the watchers of the revision and connectivity
// feeds.
func mapStreamWatchers(controlConfig config.ControlConfig) int {
	return controlConfig.MaxSessions * mapWatchersPerSession
}

func composeRevisionFeed(
	controlConfig config.ControlConfig,
	redisClient *redisadapter.Client,
) (*revisionfeed.Feed, *revisionfeed.Telemetry, error) {
	if redisClient == nil {
		return nil, nil, errInvalidRevisionFeedComposition
	}
	maxWatchers := mapStreamWatchers(controlConfig)
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
