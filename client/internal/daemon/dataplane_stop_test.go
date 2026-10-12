package daemon

import (
	"context"
	"errors"
	"fmt"
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

func TestCapRetryForCauseKeepsDataPlaneStopsShort(t *testing.T) {
	t.Parallel()

	stopped := fmt.Errorf("%w: %w", errRuntimeRecovery, errDataPlaneStopped)
	for _, testCase := range []struct {
		name  string
		retry time.Duration
		cause error
		want  time.Duration
	}{
		{"short stop retry", 2 * time.Second, stopped, 2 * time.Second},
		{"long stop retry", 16 * time.Second, stopped, maxDataPlaneStopRetry},
		{"other failure", 16 * time.Second, errRuntimeRecovery, 16 * time.Second},
	} {
		if got := capRetryForCause(testCase.retry, testCase.cause); got != testCase.want {
			t.Errorf("%s: capRetryForCause() = %v, want %v", testCase.name, got, testCase.want)
		}
	}
}
