// Package clockskew observes how far this host's clock is from the database
// clock. The database clock is the single source of truth for every persisted
// timestamp and every comparison with persisted state; this host's clock only
// bounds local timeouts and backoff. A large skew therefore never changes an
// authority decision, but it does mislead operators reading logs and it means
// local deadlines and database deadlines disagree, so it is exported as a
// metric and logged. Observation never blocks readiness.
package clockskew

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"reflect"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// WarnThreshold is the absolute skew above which every sample is logged as a
// warning.
const WarnThreshold = time.Second

var (
	// ErrInvalidObserver rejects unsafe dependencies or timing bounds.
	ErrInvalidObserver = errors.New("clock skew observer: invalid configuration")
	// ErrObserverStarted rejects duplicate lifecycle ownership.
	ErrObserverStarted = errors.New("clock skew observer: already started")
	// ErrObserverNotStarted rejects shutdown before startup.
	ErrObserverNotStarted = errors.New("clock skew observer: not started")
)

// Sampler reads the database's current clock_timestamp() in one round trip.
type Sampler interface {
	DatabaseClock(context.Context) (time.Time, error)
}

// Options bounds one observer.
type Options struct {
	Interval         time.Duration
	OperationTimeout time.Duration
}

// DefaultOptions samples once a minute.
func DefaultOptions() Options {
	return Options{Interval: time.Minute, OperationTimeout: 5 * time.Second}
}

func (options Options) valid() bool {
	return options.Interval >= time.Second && options.Interval <= time.Hour &&
		options.OperationTimeout > 0 && options.OperationTimeout < options.Interval
}

// Sample is one corrected measurement. Skew is this host's clock minus the
// database clock: positive when this host runs ahead. RoundTrip bounds the
// measurement error to half of it.
type Sample struct {
	Skew      time.Duration
	RoundTrip time.Duration
}

// Measure reads the database clock once and corrects for half the round trip:
// the database read its clock somewhere inside the round trip, so the local
// instant compared with it is the round trip's midpoint.
func Measure(ctx context.Context, sampler Sampler, now func() time.Time) (Sample, error) {
	if ctx == nil || sampler == nil || now == nil {
		return Sample{}, ErrInvalidObserver
	}
	sent := now()
	database, err := sampler.DatabaseClock(ctx)
	received := now()
	if err != nil {
		return Sample{}, err
	}
	if database.IsZero() {
		return Sample{}, ErrInvalidObserver
	}
	roundTrip := received.Sub(sent)
	if roundTrip < 0 {
		roundTrip = 0
	}
	midpoint := sent.Add(roundTrip / 2).Round(0)
	return Sample{Skew: midpoint.Sub(database.Round(0)), RoundTrip: roundTrip}, nil
}

// Observer owns one goroutine that samples at Start and then every Interval.
// It is a prometheus.Collector. Failed samples are counted and never fail the
// process or its readiness.
type Observer struct {
	options Options
	sampler Sampler
	logger  *slog.Logger
	now     func() time.Time

	skewDesc      *prometheus.Desc
	roundTripDesc *prometheus.Desc
	sampledDesc   *prometheus.Desc
	samples       *prometheus.CounterVec

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan error

	stateMu   sync.Mutex
	last      Sample
	lastAt    time.Time
	hasSample bool
}

// New constructs a stopped observer without I/O.
func New(options Options, sampler Sampler, logger *slog.Logger) (*Observer, error) {
	return newObserver(options, sampler, logger, time.Now)
}

func newObserver(options Options, sampler Sampler, logger *slog.Logger, now func() time.Time) (*Observer, error) {
	if !options.valid() || sampler == nil || logger == nil || now == nil {
		return nil, ErrInvalidObserver
	}
	if value := reflect.ValueOf(sampler); value.Kind() == reflect.Pointer && value.IsNil() {
		return nil, ErrInvalidObserver
	}
	// Dashboard: meshtransit_postgres_clock_skew_seconds
	// Alert: abs(meshtransit_postgres_clock_skew_seconds) > 1
	samples := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_postgres_clock_skew_samples_total",
		Help: "Database clock samples taken to measure this host's clock skew, by result.",
	}, []string{"result"})
	for _, result := range [...]string{"success", "error"} {
		samples.WithLabelValues(result)
	}
	return &Observer{
		options: options,
		sampler: sampler,
		logger:  logger,
		now:     now,
		skewDesc: prometheus.NewDesc(
			"meshtransit_postgres_clock_skew_seconds",
			"This host's clock minus the PostgreSQL clock at the last successful sample, "+
				"corrected by half the round trip; positive when this host runs ahead.",
			nil, nil,
		),
		roundTripDesc: prometheus.NewDesc(
			"meshtransit_postgres_clock_skew_round_trip_seconds",
			"Round trip of the last successful clock sample; the skew is accurate to half of it.",
			nil, nil,
		),
		sampledDesc: prometheus.NewDesc(
			"meshtransit_postgres_clock_skew_sampled_timestamp_seconds",
			"Unix time of the last successful clock sample, by this host's clock.",
			nil, nil,
		),
		samples: samples,
	}, nil
}

// Start owns cancellation separately from the caller's startup context. The
// first sample runs in the background, so a slow database never delays
// startup or readiness.
func (observer *Observer) Start(ctx context.Context) error {
	if observer == nil || ctx == nil {
		return ErrInvalidObserver
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if observer.started {
		return ErrObserverStarted
	}
	owned, cancel := context.WithCancel(context.WithoutCancel(ctx))
	observer.cancel, observer.done, observer.started = cancel, make(chan error, 1), true
	go func() {
		observer.run(owned)
		observer.done <- nil
		close(observer.done)
	}()
	return nil
}

// Done is the process-owned lifecycle join, available after Start.
func (observer *Observer) Done() <-chan error {
	if observer == nil {
		return nil
	}
	observer.mu.Lock()
	defer observer.mu.Unlock()
	return observer.done
}

// Shutdown cancels the loop. Done is the join path used by the process owner.
func (observer *Observer) Shutdown(ctx context.Context) error {
	if observer == nil || ctx == nil {
		return ErrInvalidObserver
	}
	observer.mu.Lock()
	defer observer.mu.Unlock()
	if !observer.started {
		return ErrObserverNotStarted
	}
	observer.cancel()
	return nil
}

// Last returns the last successful sample, if any.
func (observer *Observer) Last() (Sample, bool) {
	if observer == nil {
		return Sample{}, false
	}
	observer.stateMu.Lock()
	defer observer.stateMu.Unlock()
	return observer.last, observer.hasSample
}

func (observer *Observer) run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			observer.observe(ctx)
			if ctx.Err() != nil {
				return
			}
			timer.Reset(observer.options.Interval)
		}
	}
}

func (observer *Observer) observe(ctx context.Context) {
	operationCtx, cancel := context.WithTimeout(ctx, observer.options.OperationTimeout)
	sample, err := Measure(operationCtx, observer.sampler, observer.now)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			observer.samples.WithLabelValues("error").Inc()
			observer.logger.WarnContext(ctx, "Database clock sample failed",
				"error_code", "clock_skew_sample_failed")
		}
		return
	}
	observer.samples.WithLabelValues("success").Inc()
	observer.stateMu.Lock()
	observer.last, observer.lastAt, observer.hasSample = sample, observer.now(), true
	observer.stateMu.Unlock()
	if sample.Skew.Abs() > WarnThreshold {
		observer.logger.WarnContext(ctx, "This host's clock is skewed from the database clock",
			"error_code", "clock_skew_exceeded",
			"skew_seconds", sample.Skew.Seconds(),
			"round_trip_seconds", sample.RoundTrip.Seconds(),
			"threshold_seconds", WarnThreshold.Seconds())
	}
}

// Describe implements prometheus.Collector.
func (observer *Observer) Describe(descriptions chan<- *prometheus.Desc) {
	descriptions <- observer.skewDesc
	descriptions <- observer.roundTripDesc
	descriptions <- observer.sampledDesc
	observer.samples.Describe(descriptions)
}

// Collect implements prometheus.Collector. The gauges appear only after the
// first successful sample, so a missing series is distinguishable from zero.
func (observer *Observer) Collect(metrics chan<- prometheus.Metric) {
	observer.samples.Collect(metrics)
	observer.stateMu.Lock()
	sample, at, ok := observer.last, observer.lastAt, observer.hasSample
	observer.stateMu.Unlock()
	if !ok {
		return
	}
	metrics <- prometheus.MustNewConstMetric(observer.skewDesc, prometheus.GaugeValue, sample.Skew.Seconds())
	metrics <- prometheus.MustNewConstMetric(observer.roundTripDesc, prometheus.GaugeValue, sample.RoundTrip.Seconds())
	metrics <- prometheus.MustNewConstMetric(observer.sampledDesc, prometheus.GaugeValue,
		math.Round(float64(at.UnixMilli()))/1000)
}
