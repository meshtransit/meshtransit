package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"meshtransit.net/core/internal/platform/app"
)

type flakyChecker struct {
	tries   atomic.Int32
	failFor int32
}

func (*flakyChecker) Component() app.Component { return app.ComponentPostgreSQL }

func (checker *flakyChecker) Check(context.Context) error {
	if checker.tries.Add(1) <= checker.failFor {
		return errors.New("too many connections for role")
	}
	return nil
}

// TD-CORE-139: start-up waits for PostgreSQL to accept the pod, and gives up
// at its deadline with the last error.
func TestWaitForDependency(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var logs bytes.Buffer
	comes := &flakyChecker{failFor: 2}
	if err := waitForDependency(t.Context(), slog.New(slog.NewTextHandler(&logs, nil)), comes, time.Second,
		time.Now().Add(10*time.Second)); err != nil || comes.tries.Load() != 3 {
		t.Fatalf("waitForDependency() = %v after %d tries; want success on the third", err, comes.tries.Load())
	}
	// The logs name the dependency, not its numeric kind.
	if strings.Count(logs.String(), "dependency=postgresql") != 2 {
		t.Fatalf("logs do not name the dependency:\n%s", logs.String())
	}
	never := &flakyChecker{failFor: 1 << 30}
	started := time.Now()
	if err := waitForDependency(t.Context(), logger, never, time.Second, time.Now().Add(1500*time.Millisecond)); err == nil {
		t.Fatal("waitForDependency() past its deadline succeeded")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("waitForDependency() overran its deadline: %s", elapsed)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := waitForDependency(cancelled, logger, &flakyChecker{failFor: 1 << 30}, time.Second,
		time.Now().Add(10*time.Second)); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForDependency() cancelled = %v", err)
	}
}
