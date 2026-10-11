package daemon

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWatchDataPlaneStopsEndsTheSessionWithItsCause(t *testing.T) {
	t.Parallel()

	stops := make(chan struct{}, 1)
	stops <- struct{}{} // left from before the session
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	watchDataPlaneStops(ctx, stops, cancel)
	if ctx.Err() != nil {
		t.Fatal("a signal from before the session ended it")
	}

	stops <- struct{}{}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the session did not end")
	}
	if cause := context.Cause(ctx); !errors.Is(cause, errDataPlaneStopped) {
		t.Fatalf("cause = %v, want errDataPlaneStopped", cause)
	}
}

func TestWatchDataPlaneStopsWithoutSignalSource(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	watchDataPlaneStops(ctx, nil, cancel)
	if ctx.Err() != nil {
		t.Fatal("no signal source ended the session")
	}
}
