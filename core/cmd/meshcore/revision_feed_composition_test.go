package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/revisionfeed"
	"meshtransit.net/core/internal/platform/config"
)

func TestRevisionFeedCompositionValidatesDependencies(t *testing.T) {
	t.Parallel()

	if feed, telemetry, err := composeRevisionFeed(config.ControlConfig{}, nil); !errors.Is(
		err,
		errInvalidRevisionFeedComposition,
	) || feed != nil || telemetry != nil {
		t.Fatalf("composeRevisionFeed(nil) = (%v, %v, %v), want composition error", feed, telemetry, err)
	}
	if feed, telemetry, err := newRevisionFeed(1, time.Second, nil); !errors.Is(
		err,
		errInvalidRevisionFeedComposition,
	) || feed != nil || telemetry != nil {
		t.Fatalf("newRevisionFeed(nil) = (%v, %v, %v), want composition error", feed, telemetry, err)
	}

	feed, telemetry, err := newRevisionFeed(
		1,
		time.Second,
		func(context.Context) (revisionfeed.Subscription, error) {
			return revisionSubscriptionFixture{}, nil
		},
	)
	if err != nil || feed == nil || telemetry == nil {
		t.Fatalf("newRevisionFeed() = (%v, %v, %v), want complete composition", feed, telemetry, err)
	}
}

type revisionSubscriptionFixture struct{}

func (revisionSubscriptionFixture) Receive(
	context.Context,
) (network.RevisionAdvanced, error) {
	return network.RevisionAdvanced{}, errors.New("composition fixture must not be called")
}

func (revisionSubscriptionFixture) Close() error { return nil }
