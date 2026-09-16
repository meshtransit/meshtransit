package httpapi

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// LoginCompletionTelemetry owns private aggregate metrics; nothing is registered globally.
type LoginCompletionTelemetry struct {
	active   prometheus.Gauge
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewLoginCompletionTelemetry registers no route/collector; the future operator root owns it.
func NewLoginCompletionTelemetry() *LoginCompletionTelemetry {
	// Dashboard: meshtransit_browser_completion_requests_active
	// Alert (for: 5m): sum(rate(meshtransit_browser_completion_requests_total{result="saturated"}[5m])) > 1
	active := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_browser_completion_requests_active", Help: "Owned browser completion work including joined cleanup/delivery.",
	})
	// Dashboard: sum by (result) (rate(meshtransit_browser_completion_requests_total[5m]))
	// Alert (for: 5m): sum(rate(meshtransit_browser_completion_requests_total{result=~"unavailable|commit_unknown|delivery_failed"}[5m])) > 1
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_browser_completion_requests_total", Help: "Browser completion by closed outcome, not acknowledged browser receipt.",
	}, []string{"result"})
	// Dashboard/alert (for: 5m; >10):
	// histogram_quantile(0.99, sum by (le) (rate(meshtransit_browser_completion_duration_seconds_bucket[5m])))
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "meshtransit_browser_completion_duration_seconds", Help: "Whole browser completion including joined cleanup and delivery.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 45},
	}, []string{"result"})
	return &LoginCompletionTelemetry{active: active, requests: requests, duration: duration}
}

// CompletionOpened counts ownership, including fail-fast rejection, never authority.
func (telemetry *LoginCompletionTelemetry) CompletionOpened() { telemetry.active.Inc() }

// CompletionClosed releases ownership and coalesces unknown labels/negative duration.
func (telemetry *LoginCompletionTelemetry) CompletionClosed(outcome LoginCompletionOutcome, elapsed time.Duration) {
	telemetry.active.Dec()
	telemetry.requests.WithLabelValues(outcome.String()).Inc()
	telemetry.duration.WithLabelValues(outcome.String()).Observe(max(elapsed.Seconds(), 0))
}

// Describe publishes only fixed private descriptions.
func (telemetry *LoginCompletionTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	telemetry.active.Describe(descriptions)
	telemetry.requests.Describe(descriptions)
	telemetry.duration.Describe(descriptions)
}

// Collect publishes no input, response headers, identity or dependency details.
func (telemetry *LoginCompletionTelemetry) Collect(metrics chan<- prometheus.Metric) {
	telemetry.active.Collect(metrics)
	telemetry.requests.Collect(metrics)
	telemetry.duration.Collect(metrics)
}

var (
	_ LoginCompletionObserver = (*LoginCompletionTelemetry)(nil)
	_ prometheus.Collector    = (*LoginCompletionTelemetry)(nil)
)
