package httpapi

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// LoginContinuationTelemetry owns isolated private no-grant HTTP-admission metrics.
// Explicit operator-only registration is the composition root's responsibility.
type LoginContinuationTelemetry struct {
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewLoginContinuationTelemetry creates no global registration or public endpoint.
func NewLoginContinuationTelemetry() *LoginContinuationTelemetry {
	// Dashboard: sum by (operation, result) (rate(meshtransit_browser_continuation_requests_total[5m]))
	// Alert (for: 5m): sum(rate(meshtransit_browser_continuation_requests_total{result="saturated"}[5m])) > 1
	// Alert (for: 5m): sum(rate(meshtransit_browser_continuation_requests_total{result="unavailable"}[5m])) > 1
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_browser_continuation_requests_total",
		Help: "No-grant browser continuation admission by closed operation and outcome.",
	}, []string{"operation", "result"})
	// Dashboard:
	// histogram_quantile(0.99, sum by (le) (rate(meshtransit_browser_continuation_duration_seconds_bucket[5m])))
	// Alert (for: 5m):
	// histogram_quantile(0.99, sum by (le) (rate(meshtransit_browser_continuation_duration_seconds_bucket[5m]))) > 10
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_browser_continuation_duration_seconds",
		Help:    "No-grant HTTP admission duration, not authentication or session issuance.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 45},
	}, []string{"operation", "result"})
	return &LoginContinuationTelemetry{requests: requests, duration: duration}
}

// ObserveLoginContinuation coalesces arbitrary enum values and bounds negative elapsed time.
func (telemetry *LoginContinuationTelemetry) ObserveLoginContinuation(
	operation LoginContinuationOperation,
	outcome LoginContinuationOutcome,
	elapsed time.Duration,
) {
	telemetry.requests.WithLabelValues(operation.String(), outcome.String()).Inc()
	telemetry.duration.WithLabelValues(operation.String(), outcome.String()).Observe(max(elapsed.Seconds(), 0))
}

// Describe emits only fixed operator metric descriptions.
func (telemetry *LoginContinuationTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	telemetry.requests.Describe(descriptions)
	telemetry.duration.Describe(descriptions)
}

// Collect emits aggregate bounded labels without input-derived material.
func (telemetry *LoginContinuationTelemetry) Collect(metrics chan<- prometheus.Metric) {
	telemetry.requests.Collect(metrics)
	telemetry.duration.Collect(metrics)
}

var (
	_ LoginContinuationObserver = (*LoginContinuationTelemetry)(nil)
	_ prometheus.Collector      = (*LoginContinuationTelemetry)(nil)
)
