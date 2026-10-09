package httpapi

import (
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// BrowserCaptureTelemetry observes bounded GET presentation, never authentication.
// Registration is isolated by BrowserLogin; no request or error text becomes a label.
type BrowserCaptureTelemetry struct {
	active   prometheus.Gauge
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewBrowserCaptureTelemetry creates fixed private descriptions, not a global endpoint.
func NewBrowserCaptureTelemetry() *BrowserCaptureTelemetry {
	// Dashboard: sum by (result) (rate(meshtransit_browser_capture_http_requests_total[5m]))
	// Alert (for: 5m): sum(rate(meshtransit_browser_capture_http_requests_total{result="unavailable"}[5m])) > 1
	// Alert (for: 5m): sum(rate(meshtransit_browser_capture_http_requests_total{result="saturated"}[5m])) > 1
	return &BrowserCaptureTelemetry{
		active: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "meshtransit_browser_capture_http_requests_active", Help: "Owned no-grant callback capture requests.",
		}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_browser_capture_http_requests_total", Help: "Capture submission outcomes, not browser receipt.",
		}, []string{"result"}),
		// p99 dashboard/alert (>10s for: 5m): histogram_quantile(0.99,
		// sum by (le) (rate(meshtransit_browser_capture_http_duration_seconds_bucket[5m])))
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "meshtransit_browser_capture_http_duration_seconds", Help: "Owned capture duration through submission.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 45},
		}, []string{"result"}),
	}
}

func (telemetry *BrowserCaptureTelemetry) opened() { telemetry.active.Inc() }
func (telemetry *BrowserCaptureTelemetry) closed(err error, elapsed time.Duration) {
	result := "submitted"
	switch {
	case errors.Is(err, ErrInvalidBrowserLogin):
		result = "invalid"
	case errors.Is(err, ErrBrowserCaptureLimited):
		result = "limited"
	case errors.Is(err, ErrBrowserCaptureSaturated):
		result = "saturated"
	case err != nil:
		result = "unavailable"
	}
	telemetry.active.Dec()
	telemetry.requests.WithLabelValues(result).Inc()
	telemetry.duration.WithLabelValues(result).Observe(max(elapsed.Seconds(), 0))
}

// Describe emits fixed bounded descriptions only.
func (telemetry *BrowserCaptureTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	telemetry.active.Describe(descriptions)
	telemetry.requests.Describe(descriptions)
	telemetry.duration.Describe(descriptions)
}

// Collect emits closed aggregate results without topology or credential material.
func (telemetry *BrowserCaptureTelemetry) Collect(metrics chan<- prometheus.Metric) {
	telemetry.active.Collect(metrics)
	telemetry.requests.Collect(metrics)
	telemetry.duration.Collect(metrics)
}

var _ prometheus.Collector = (*BrowserCaptureTelemetry)(nil)
