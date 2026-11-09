// Package servertiming adds up the database and Redis time one request
// spends, for an optional Server-Timing response header (TD-CON-48). It
// records durations only: never a statement, key or argument. "redis" is the
// rate-limit script's time, the only Redis call on a management request.
package servertiming

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

type contextKey struct{}

// Recorder holds one request's totals. It is safe for concurrent use.
type Recorder struct {
	database atomic.Int64
	redis    atomic.Int64
}

// With returns a context whose database and Redis time is added to the
// returned recorder.
func With(ctx context.Context) (context.Context, *Recorder) {
	recorder := &Recorder{}
	return context.WithValue(ctx, contextKey{}, recorder), recorder
}

func from(ctx context.Context) *Recorder {
	if ctx == nil {
		return nil
	}
	recorder, _ := ctx.Value(contextKey{}).(*Recorder)
	return recorder
}

// Active reports whether ctx belongs to a recorded request, so callers can
// skip even reading the clock otherwise.
func Active(ctx context.Context) bool { return from(ctx) != nil }

// AddDatabase adds time spent waiting on the database; outside a recorded
// request it does nothing.
func AddDatabase(ctx context.Context, elapsed time.Duration) {
	if recorder := from(ctx); recorder != nil && elapsed > 0 {
		recorder.database.Add(int64(elapsed))
	}
}

// AddRedis adds time spent waiting on Redis; outside a recorded request it
// does nothing.
func AddRedis(ctx context.Context, elapsed time.Duration) {
	if recorder := from(ctx); recorder != nil && elapsed > 0 {
		recorder.redis.Add(int64(elapsed))
	}
}

// Header is the Server-Timing value for a request that took total in all.
// Concurrent queries add up, so db may exceed app.
func (recorder *Recorder) Header(total time.Duration) string {
	if recorder == nil {
		return ""
	}
	return fmt.Sprintf("db;dur=%s, redis;dur=%s, app;dur=%s",
		milliseconds(time.Duration(recorder.database.Load())),
		milliseconds(time.Duration(recorder.redis.Load())), milliseconds(total))
}

func milliseconds(elapsed time.Duration) string {
	return fmt.Sprintf("%.1f", float64(elapsed)/float64(time.Millisecond))
}
