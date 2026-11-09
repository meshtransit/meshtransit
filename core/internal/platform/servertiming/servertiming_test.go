package servertiming

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestHeaderSumsDatabaseAndRedisTimeOfOneRequest(t *testing.T) {
	t.Parallel()
	ctx, recorder := With(context.Background())
	AddDatabase(ctx, 3*time.Millisecond)
	AddDatabase(ctx, 1500*time.Microsecond)
	AddRedis(ctx, 700*time.Microsecond)
	got := recorder.Header(12 * time.Millisecond)
	want := "db;dur=4.5, redis;dur=0.7, app;dur=12.0"
	if got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
}

func TestTimeOutsideARecordedRequestIsIgnored(t *testing.T) {
	t.Parallel()
	AddDatabase(context.Background(), time.Second)
	AddRedis(context.Background(), time.Second)
	var recorder *Recorder
	if recorder.Header(time.Second) != "" {
		t.Fatal("a nil recorder produced a header")
	}
}

func TestDatabaseTimeOfConcurrentQueriesAdds(t *testing.T) {
	t.Parallel()
	ctx, recorder := With(context.Background())
	done := make(chan struct{})
	for range 8 {
		go func() { AddDatabase(ctx, time.Millisecond); done <- struct{}{} }()
	}
	for range 8 {
		<-done
	}
	if got := recorder.Header(0); !strings.HasPrefix(got, "db;dur=8.0,") {
		t.Fatalf("header = %q", got)
	}
}

func TestActiveOnlyInsideARecordedRequest(t *testing.T) {
	t.Parallel()
	if Active(context.Background()) {
		t.Fatal("a plain context is recorded")
	}
	ctx, _ := With(context.Background())
	if !Active(ctx) {
		t.Fatal("a recorded context is not active")
	}
}
