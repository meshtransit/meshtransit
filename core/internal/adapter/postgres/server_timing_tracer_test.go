package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/platform/servertiming"
)

func TestServerTimingTracerLeavesUnrecordedContextsAlone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if (serverTimingTracer{}).TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{}) != ctx {
		t.Fatal("the tracer wrapped a context outside a recorded request")
	}
}

func TestServerTimingTracerAddsQueryTimeToTheRequest(t *testing.T) {
	t.Parallel()
	ctx, recorder := servertiming.With(context.Background())
	traced := serverTimingTracer{}.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{})
	time.Sleep(2 * time.Millisecond)
	serverTimingTracer{}.TraceQueryEnd(traced, nil, pgx.TraceQueryEndData{})
	if got := recorder.Header(0); strings.HasPrefix(got, "db;dur=0.0,") || !strings.HasPrefix(got, "db;dur=") {
		t.Fatalf("header = %q, want database time", got)
	}
}
