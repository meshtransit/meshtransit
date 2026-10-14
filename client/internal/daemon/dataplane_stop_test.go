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
		if got := capRetryForCause(testCase.retry, testCase.cause, 1); got != testCase.want {
			t.Errorf("%s: capRetryForCause() = %v, want %v", testCase.name, got, testCase.want)
		}
	}
}

func TestCapRetryForCauseBacksOffADeviceThatKeepsStopping(t *testing.T) {
	t.Parallel()

	stopped := fmt.Errorf("%w: %w", errRuntimeRecovery, errDataPlaneStopped)
	if got := capRetryForCause(16*time.Second, stopped, maxQuickDataPlaneStops); got != maxDataPlaneStopRetry {
		t.Fatalf("stop %d: retry = %v, want the short cap", maxQuickDataPlaneStops, got)
	}
	if got := capRetryForCause(16*time.Second, stopped, maxQuickDataPlaneStops+1); got != 16*time.Second {
		t.Fatalf("stop %d: retry = %v, want the normal backoff", maxQuickDataPlaneStops+1, got)
	}
}

func TestCountQuickStops(t *testing.T) {
	t.Parallel()

	stopped := fmt.Errorf("%w: %w", errRuntimeRecovery, errDataPlaneStopped)
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	for _, testCase := range []struct {
		name           string
		stops          int
		cause          error
		synchronizedAt time.Time
		want           int
	}{
		{"a stop before any map", 2, stopped, time.Time{}, 3},
		{"a stop soon after the map", 2, stopped, now.Add(-5 * time.Second), 3},
		{"a stop after a long session", 5, stopped, now.Add(-runtimeRetryReset), 1},
		{"another failure", 5, errRuntimeRecovery, time.Time{}, 0},
	} {
		if got := countQuickStops(testCase.stops, testCase.cause, testCase.synchronizedAt, now); got != testCase.want {
			t.Errorf("%s: countQuickStops() = %d, want %d", testCase.name, got, testCase.want)
		}
	}
}
