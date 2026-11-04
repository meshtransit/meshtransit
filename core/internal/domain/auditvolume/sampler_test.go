package auditvolume

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

type fakeReader struct {
	events atomic.Int64
	fail   atomic.Bool
	calls  atomic.Int64
}

func (reader *fakeReader) DeploymentEvents(context.Context) (int64, error) {
	reader.calls.Add(1)
	if reader.fail.Load() {
		return 0, errors.New("read failed")
	}
	return reader.events.Load(), nil
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestNewRejectsUnsafeConfiguration(t *testing.T) {
	reader := &fakeReader{}
	var nilReader *fakeReader
	for name, build := range map[string]func() (*Sampler, error){
		"nil reader": func() (*Sampler, error) { return New(DefaultOptions(), nil, quietLogger()) },
		"typed nil":  func() (*Sampler, error) { return New(DefaultOptions(), nilReader, quietLogger()) },
		"nil logger": func() (*Sampler, error) { return New(DefaultOptions(), reader, nil) },
		"short interval": func() (*Sampler, error) {
			return New(Options{Interval: time.Second, Timeout: time.Second}, reader, quietLogger())
		},
		"long timeout": func() (*Sampler, error) {
			return New(Options{Interval: time.Minute, Timeout: time.Minute}, reader, quietLogger())
		},
	} {
		if sampler, err := build(); !errors.Is(err, ErrInvalidSampler) || sampler != nil {
			t.Errorf("%s: New() = %v, %v; want ErrInvalidSampler", name, sampler, err)
		}
	}
}

func TestSampleRecordsEventsAndFailures(t *testing.T) {
	reader := &fakeReader{}
	sampler, err := New(DefaultOptions(), reader, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if got := sampler.Snapshot(); got.Sampled || got.Events != 0 {
		t.Fatalf("before a sample: %+v", got)
	}
	reader.events.Store(1379)
	sampler.Sample(t.Context())
	got := sampler.Snapshot()
	if !got.Sampled || got.Events != 1379 || got.Failed != 0 || got.At.IsZero() {
		t.Fatalf("after a sample: %+v", got)
	}
	// A failed read keeps the last good value and counts the failure.
	reader.fail.Store(true)
	sampler.Sample(t.Context())
	if got := sampler.Snapshot(); got.Events != 1379 || got.Failed != 1 {
		t.Fatalf("after a failed sample: %+v", got)
	}
	// A negative answer is a broken database, not a value.
	reader.fail.Store(false)
	reader.events.Store(-1)
	sampler.Sample(t.Context())
	if got := sampler.Snapshot(); got.Events != 1379 || got.Failed != 2 {
		t.Fatalf("after a negative answer: %+v", got)
	}
}

func TestLifecycleSamplesAtStartAndStops(t *testing.T) {
	reader := &fakeReader{}
	reader.events.Store(7)
	sampler, err := New(DefaultOptions(), reader, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := sampler.Shutdown(t.Context()); !errors.Is(err, ErrSamplerNotStarted) {
		t.Fatalf("Shutdown before Start = %v", err)
	}
	if err := sampler.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := sampler.Start(t.Context()); !errors.Is(err, ErrSamplerStarted) {
		t.Fatalf("second Start = %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !sampler.Snapshot().Sampled {
		if time.Now().After(deadline) {
			t.Fatal("no sample at start")
		}
		time.Sleep(time.Millisecond)
	}
	if err := sampler.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-sampler.Done():
		if err != nil {
			t.Fatalf("Done = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sampler did not stop")
	}
	if got := sampler.Snapshot(); got.Events != 7 {
		t.Fatalf("events = %d, want 7", got.Events)
	}
}
