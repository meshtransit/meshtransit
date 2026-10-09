package httpapi

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// LoginHTTPTelemetry owns private, bounded-cardinality browser-admission metrics.
// The composition root must explicitly register it only on the operator registry.
type LoginHTTPTelemetry struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewLoginHTTPTelemetry creates isolated metrics without global registration.
func NewLoginHTTPTelemetry() *LoginHTTPTelemetry {
	// Dashboard: sum by (result) (rate(meshtransit_browser_login_requests_total[5m]))
	// Alert (for: 5m): sum(rate(meshtransit_browser_login_requests_total{result="unavailable"}[5m])) > 1
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_browser_login_requests_total",
		Help: "Browser login prepare/start requests by closed outcome, without identity or secrets.",
	}, []string{"result"})
	// Dashboard:
	// histogram_quantile(0.99, sum(rate(meshtransit_browser_login_request_duration_seconds_bucket[5m])) by (le))
	// Alert (for: 5m):
	// histogram_quantile(0.99, sum(rate(meshtransit_browser_login_request_duration_seconds_bucket[5m])) by (le)) > 10
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_browser_login_request_duration_seconds",
		Help:    "Browser login HTTP admission duration by closed outcome.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 45},
	}, []string{"result"})
	return &LoginHTTPTelemetry{requests: requests, duration: duration}
}

// ObserveLoginHTTP receives no request data and safely coalesces unknown outcomes.
func (telemetry *LoginHTTPTelemetry) ObserveLoginHTTP(outcome LoginHTTPOutcome, duration time.Duration) {
	telemetry.requests.WithLabelValues(outcome.String()).Inc()
	telemetry.duration.WithLabelValues(outcome.String()).Observe(max(duration.Seconds(), 0))
}

// Describe implements Collector without adding global labels or ownership.
func (telemetry *LoginHTTPTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	telemetry.requests.Describe(descriptions)
	telemetry.duration.Describe(descriptions)
}

// Collect emits only aggregate operator metrics, never browser proof material.
func (telemetry *LoginHTTPTelemetry) Collect(metrics chan<- prometheus.Metric) {
	telemetry.requests.Collect(metrics)
	telemetry.duration.Collect(metrics)
}

var (
	_ LoginHTTPObserver    = (*LoginHTTPTelemetry)(nil)
	_ prometheus.Collector = (*LoginHTTPTelemetry)(nil)
)
