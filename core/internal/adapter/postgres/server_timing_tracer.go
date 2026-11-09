package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"meshtransit.net/core/internal/platform/servertiming"
)

type serverTimingStartKey struct{}

// serverTimingTracer adds each statement's time, and the wait for a pooled
// connection, to the request's Server-Timing recorder. It reads nothing of
// the statement, and outside a recorded request it does nothing. Batches and
// COPY are not traced (the adapter uses neither).
type serverTimingTracer struct{}

var (
	_ pgx.QueryTracer       = serverTimingTracer{}
	_ pgxpool.AcquireTracer = serverTimingTracer{}
)

func (serverTimingTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return markStart(ctx)
}

func (serverTimingTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	addSince(ctx)
}

func (serverTimingTracer) TraceAcquireStart(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireStartData) context.Context {
	return markStart(ctx)
}

func markStart(ctx context.Context) context.Context {
	if !servertiming.Active(ctx) {
		return ctx
	}
	return context.WithValue(ctx, serverTimingStartKey{}, time.Now())
}

func (serverTimingTracer) TraceAcquireEnd(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireEndData) {
	addSince(ctx)
}

func addSince(ctx context.Context) {
	if started, ok := ctx.Value(serverTimingStartKey{}).(time.Time); ok {
		servertiming.AddDatabase(ctx, time.Since(started))
	}
}
