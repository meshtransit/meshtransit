package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/control/connectivityfeed"
)

func TestNewConnectivityFeedValidatesComposition(t *testing.T) {
	t.Parallel()

	if _, _, err := newConnectivityFeed(0, time.Second, nil); !errors.Is(
		err,
		errInvalidConnectivityFeedComposition,
	) {
		t.Fatalf("newConnectivityFeed(invalid) error = %v", err)
	}
	feed, telemetry, err := newConnectivityFeed(
		1,
		time.Second,
		func(context.Context) (connectivityfeed.Subscription, error) {
			return nil, errors.New("composition fixture must not be called")
		},
	)
	if err != nil || feed == nil || telemetry == nil {
		t.Fatalf("newConnectivityFeed() = (%v, %v, %v)", feed, telemetry, err)
	}
}
