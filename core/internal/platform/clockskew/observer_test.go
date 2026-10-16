package clockskew

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// stepClock advances by step on every read, so a sample's round trip is
// exactly one step.
type stepClock struct {
	mu   sync.Mutex
	at   time.Time
	step time.Duration
}

func (clock *stepClock) now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	at := clock.at
	clock.at = clock.at.Add(clock.step)
	return at
}

// fixedDatabase answers with the database clock at the midpoint of the round
// trip of a host running skew ahead of it.
type fixedDatabase struct {
	mu    sync.Mutex
	at    time.Time
	err   error
	calls int
}

func (database *fixedDatabase) DatabaseClock(context.Context) (time.Time, error) {
	database.mu.Lock()
	defer database.mu.Unlock()
	database.calls++
	return database.at, database.err
}

func TestMeasureCorrectsHalfTheRoundTrip(t *testing.T) {
	sent := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, skew := range []time.Duration{2 * time.Second, -2 * time.Second, 0, 200 * time.Millisecond} {
		clock := &stepClock{at: sent, step: 40 * time.Millisecond}
		// The database read its clock at the round trip's midpoint.
		database := &fixedDatabase{at: sent.Add(20 * time.Millisecond).Add(-skew)}
		sample, err := Measure(t.Context(), database, clock.now)
		if err != nil {
			t.Fatalf("Measure(skew %v) error = %v", skew, err)
		}
		if sample.Skew != skew || sample.RoundTrip != 40*time.Millisecond {
			t.Fatalf("Measure(skew %v) = %+v, want skew %v round trip 40ms", skew, sample, skew)
		}
	}
}

func TestMeasureRejectsFailedAndZeroSamples(t *testing.T) {
	clock := &stepClock{at: time.Unix(1, 0), step: time.Millisecond}
	failure := errors.New("database unavailable")
	if _, err := Measure(t.Context(), &fixedDatabase{err: failure}, clock.now); !errors.Is(err, failure) {
		t.Fatalf("Measure(failed) error = %v", err)
	}
	if _, err := Measure(t.Context(), &fixedDatabase{}, clock.now); !errors.Is(err, ErrInvalidObserver) {
		t.Fatalf("Measure(zero) error = %v", err)
	}
}

func TestObserverExportsSkewAndWarnsAboveThreshold(t *testing.T) {
	for _, test := range []struct {
		name string
		skew time.Duration
		warn bool
	}{
		{name: "ahead", skew: 1500 * time.Millisecond, warn: true},
		{name: "behind", skew: -1500 * time.Millisecond, warn: true},
		{name: "within", skew: 200 * time.Millisecond, warn: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			sent := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
			clock := &stepClock{at: sent, step: 10 * time.Millisecond}
			database := &fixedDatabase{at: sent.Add(5 * time.Millisecond).Add(-test.skew)}
			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, nil))
			observer, err := newObserver(DefaultOptions(), database, logger, clock.now)
			if err != nil {
				t.Fatal(err)
			}
			if body := gather(t, observer); strings.Contains(body, "meshtransit_postgres_clock_skew_seconds ") {
				t.Fatalf("skew gauge before the first sample:\n%s", body)
			}
			observer.observe(t.Context())
			body := gather(t, observer)
			for _, want := range []string{
				"meshtransit_postgres_clock_skew_seconds " + formatSeconds(test.skew),
				"meshtransit_postgres_clock_skew_round_trip_seconds 0.01",
				`meshtransit_postgres_clock_skew_samples_total{result="success"} 1`,
				`meshtransit_postgres_clock_skew_samples_total{result="error"} 0`,
			} {
				if !strings.Contains(body, want+"\n") {
					t.Fatalf("metrics missing %q:\n%s", want, body)
				}
			}
			warned := strings.Contains(output.String(), `"error_code":"clock_skew_exceeded"`)
			if warned != test.warn {
				t.Fatalf("warned = %v, want %v; log %s", warned, test.warn, output.String())
			}
		})
	}
}

func TestObserverCountsFailedSamplesWithoutAGauge(t *testing.T) {
	var output bytes.Buffer
	observer, err := newObserver(DefaultOptions(), &fixedDatabase{err: errors.New("down")},
		slog.New(slog.NewJSONHandler(&output, nil)), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	observer.observe(t.Context())
	body := gather(t, observer)
	if !strings.Contains(body, `meshtransit_postgres_clock_skew_samples_total{result="error"} 1`+"\n") ||
		strings.Contains(body, "meshtransit_postgres_clock_skew_seconds ") {
		t.Fatalf("metrics after only a failed sample:\n%s", body)
	}
	if !strings.Contains(output.String(), `"error_code":"clock_skew_sample_failed"`) {
		t.Fatalf("failed sample was not logged: %s", output.String())
	}
}

func TestObserverSamplesAtStartWithoutBlockingIt(t *testing.T) {
	blocked := make(chan struct{})
	database := &blockingDatabase{called: make(chan struct{}), release: blocked}
	observer, err := New(DefaultOptions(), database, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := observer.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := observer.Start(t.Context()); !errors.Is(err, ErrObserverStarted) {
		t.Fatalf("second Start() error = %v", err)
	}
	select {
	case <-database.called:
	case <-time.After(10 * time.Second):
		t.Fatal("observer did not sample at start")
	}
	if err := observer.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	select {
	case err := <-observer.Done():
		if err != nil {
			t.Fatalf("Done() = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("observer did not stop while a sample was in flight")
	}
	close(blocked)
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	var nilDatabase *fixedDatabase
	for name, build := range map[string]func() (*Observer, error){
		"nil sampler":       func() (*Observer, error) { return New(DefaultOptions(), nil, logger) },
		"typed nil sampler": func() (*Observer, error) { return New(DefaultOptions(), nilDatabase, logger) },
		"nil logger":        func() (*Observer, error) { return New(DefaultOptions(), &fixedDatabase{}, nil) },
		"timeout too long": func() (*Observer, error) {
			return New(Options{Interval: time.Second, OperationTimeout: time.Second}, &fixedDatabase{}, logger)
		},
	} {
		if _, err := build(); !errors.Is(err, ErrInvalidObserver) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	var observer *Observer
	if err := observer.Shutdown(t.Context()); !errors.Is(err, ErrInvalidObserver) {
		t.Fatalf("nil Shutdown() error = %v", err)
	}
	stopped, err := New(DefaultOptions(), &fixedDatabase{}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := stopped.Shutdown(t.Context()); !errors.Is(err, ErrObserverNotStarted) {
		t.Fatalf("Shutdown() before Start error = %v", err)
	}
}

type blockingDatabase struct {
	once    sync.Once
	called  chan struct{}
	release chan struct{}
}

func (database *blockingDatabase) DatabaseClock(ctx context.Context) (time.Time, error) {
	database.once.Do(func() { close(database.called) })
	select {
	case <-ctx.Done():
		return time.Time{}, ctx.Err()
	case <-database.release:
		return time.Now(), nil
	}
}

func gather(t *testing.T, collector prometheus.Collector) string {
	t.Helper()
	registry := prometheus.NewRegistry()
	if err := registry.Register(collector); err != nil {
		t.Fatalf("register collector: %v", err)
	}
	recorder := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(
		recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil),
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", recorder.Code)
	}
	return recorder.Body.String()
}

func formatSeconds(duration time.Duration) string {
	return strconv.FormatFloat(duration.Seconds(), 'g', -1, 64)
}
