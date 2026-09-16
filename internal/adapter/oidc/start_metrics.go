package oidc

import (
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/prometheus/client_golang/prometheus"
)

// StartTelemetry owns isolated, bounded-cardinality OIDC login-start metrics.
// The composition root must register it only on the private operator registry.
type StartTelemetry struct {
	active   prometheus.Gauge
	starts   *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewStartTelemetry constructs metrics without global registration or goroutines.
func NewStartTelemetry() *StartTelemetry {
	// Dashboard: meshtransit_oidc_login_starts_active
	active := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_oidc_login_starts_active",
		Help: "Number of OIDC login starts currently owned by this process.",
	})
	// Dashboard: sum by (result) (rate(meshtransit_oidc_login_starts_total[5m]))
	// Alert (for: 2m):
	// sum(increase(meshtransit_oidc_login_starts_total{result=~"uncertain|cleanup_failed"}[5m])) > 0
	starts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_oidc_login_starts_total",
		Help: "OIDC login starts by closed terminal result, without identity or secrets.",
	}, []string{"result"})
	// Dashboard:
	// histogram_quantile(0.99, sum(rate(meshtransit_oidc_login_start_duration_seconds_bucket[5m])) by (le))
	// Alert (for: 5m):
	// histogram_quantile(0.99, sum(rate(meshtransit_oidc_login_start_duration_seconds_bucket[5m])) by (le)) > 10
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_oidc_login_start_duration_seconds",
		Help:    "OIDC login-start duration by closed terminal result.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 45},
	}, []string{"result"})
	return &StartTelemetry{active: active, starts: starts, duration: duration}
}

// StartOpened records one owned operation without receiving request data.
func (telemetry *StartTelemetry) StartOpened() { telemetry.active.Inc() }

// StartClosed records only a bounded outcome; unknown values share one label.
func (telemetry *StartTelemetry) StartClosed(outcome oidcauth.StartOutcome, duration time.Duration) {
	telemetry.active.Dec()
	telemetry.starts.WithLabelValues(outcome.String()).Inc()
	telemetry.duration.WithLabelValues(outcome.String()).Observe(max(duration.Seconds(), 0))
}

// Describe implements prometheus.Collector for an explicitly owned registry.
func (telemetry *StartTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	telemetry.active.Describe(descriptions)
	telemetry.starts.Describe(descriptions)
	telemetry.duration.Describe(descriptions)
}

// Collect implements prometheus.Collector for the private operator endpoint.
func (telemetry *StartTelemetry) Collect(metrics chan<- prometheus.Metric) {
	telemetry.active.Collect(metrics)
	telemetry.starts.Collect(metrics)
	telemetry.duration.Collect(metrics)
}

var (
	_ oidcauth.StartObserver = (*StartTelemetry)(nil)
	_ prometheus.Collector   = (*StartTelemetry)(nil)
)
