package httpapi

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// LoginLandingTelemetry owns isolated presentation metrics, never authentication evidence.
// Private runtime registration is explicitly deferred to the composition root.
type LoginLandingTelemetry struct {
	active   prometheus.Gauge
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewLoginLandingTelemetry creates no global registration or public endpoint.
func NewLoginLandingTelemetry() *LoginLandingTelemetry {
	active := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_browser_landing_requests_active",
		Help: "Active bounded static continuation presentations, not authenticated browsers.",
	})
	// Dashboard: sum by (result) (rate(meshtransit_browser_landing_requests_total[5m]))
	// Alert (for: 5m): sum(rate(meshtransit_browser_landing_requests_total{result="saturated"}[5m])) > 1
	// Alert (for: 5m): sum(rate(meshtransit_browser_landing_requests_total{result="unavailable"}[5m])) > 1
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_browser_landing_requests_total",
		Help: "Static presentation outcomes, not session issuance or browser receipt.",
	}, []string{"result"})
	// Dashboard/alert (for: 5m, >10s):
	// histogram_quantile(0.99, sum by (le) (rate(meshtransit_browser_landing_duration_seconds_bucket[5m])))
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_browser_landing_duration_seconds",
		Help:    "Owned static presentation duration including response delivery.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 45},
	}, []string{"result"})
	return &LoginLandingTelemetry{active: active, requests: requests, duration: duration}
}

// LandingOpened counts only the lifetime owned by Present, including rejected input.
func (telemetry *LoginLandingTelemetry) LandingOpened() { telemetry.active.Inc() }

// LandingClosed coalesces unsupported values and clamps negative elapsed time.
func (telemetry *LoginLandingTelemetry) LandingClosed(outcome LoginLandingOutcome, elapsed time.Duration) {
	telemetry.active.Dec()
	telemetry.requests.WithLabelValues(outcome.String()).Inc()
	telemetry.duration.WithLabelValues(outcome.String()).Observe(max(elapsed.Seconds(), 0))
}

// Describe emits fixed private metric descriptions only.
func (telemetry *LoginLandingTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	telemetry.active.Describe(descriptions)
	telemetry.requests.Describe(descriptions)
	telemetry.duration.Describe(descriptions)
}

// Collect emits bounded aggregate labels without input or topology material.
func (telemetry *LoginLandingTelemetry) Collect(metrics chan<- prometheus.Metric) {
	telemetry.active.Collect(metrics)
	telemetry.requests.Collect(metrics)
	telemetry.duration.Collect(metrics)
}

var (
	_ LoginLandingObserver = (*LoginLandingTelemetry)(nil)
	_ prometheus.Collector = (*LoginLandingTelemetry)(nil)
)
