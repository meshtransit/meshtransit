package httpapi

import (
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// BrowserManagementTelemetry observes private HTTP submission, not mutation commit.
type BrowserManagementTelemetry struct {
	active   prometheus.Gauge
	requests *prometheus.CounterVec
	duration *prometheus.HistogramVec
}

// NewBrowserManagementTelemetry creates fixed isolated descriptions, never a listener.
func NewBrowserManagementTelemetry() *BrowserManagementTelemetry {
	// Dashboard: sum by (operation, result) (rate(meshtransit_browser_management_requests_total[5m]))
	// Alert (for: 5m): sum(rate(meshtransit_browser_management_requests_total{result="unavailable"}[5m])) > 1
	// Alert (for: 5m): sum(rate(meshtransit_browser_management_requests_total{result="saturated"}[5m])) > 1
	return &BrowserManagementTelemetry{
		active: prometheus.NewGauge(prometheus.GaugeOpts{Name: "meshtransit_browser_management_requests_active",
			Help: "Owned private cookie-management HTTP requests."}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_browser_management_requests_total",
			Help: "Cookie-management submission outcomes, not durable authority or browser receipt.",
		}, []string{"operation", "result"}),
		// p99 dashboard/alert (>10s for: 5m): histogram_quantile(0.99,
		// sum by (le) (rate(meshtransit_browser_management_duration_seconds_bucket[5m])))
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "meshtransit_browser_management_duration_seconds",
			Help:    "Private cookie-management duration through submission.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 45},
		}, []string{"operation", "result"}),
	}
}

func (telemetry *BrowserManagementTelemetry) opened() { telemetry.active.Inc() }
func (telemetry *BrowserManagementTelemetry) closed(operation string, err error, elapsed time.Duration) {
	switch operation {
	case "prepare", "logout", "read", "mutation":
	default:
		operation = "unknown"
	}
	result := "submitted"
	switch {
	case errors.Is(err, ErrInvalidBrowserManagement):
		result = "invalid"
	case errors.Is(err, ErrBrowserManagementLimited):
		result = "limited"
	case errors.Is(err, ErrBrowserManagementSaturated):
		result = "saturated"
	case errors.Is(err, ErrBrowserManagementDelivery):
		result = "delivery_failed"
	case err != nil:
		result = "unavailable"
	}
	telemetry.active.Dec()
	telemetry.requests.WithLabelValues(operation, result).Inc()
	telemetry.duration.WithLabelValues(operation, result).Observe(max(elapsed.Seconds(), 0))
}

// Describe emits fixed descriptions only.
func (telemetry *BrowserManagementTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	telemetry.active.Describe(descriptions)
	telemetry.requests.Describe(descriptions)
	telemetry.duration.Describe(descriptions)
}

// Collect emits closed aggregate labels without credential or caller data.
func (telemetry *BrowserManagementTelemetry) Collect(metrics chan<- prometheus.Metric) {
	telemetry.active.Collect(metrics)
	telemetry.requests.Collect(metrics)
	telemetry.duration.Collect(metrics)
}

var _ prometheus.Collector = (*BrowserManagementTelemetry)(nil)
