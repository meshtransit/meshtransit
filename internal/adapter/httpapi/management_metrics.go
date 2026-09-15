package httpapi

import (
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ErrInvalidManagementTelemetry reports an unsafe request limit.
var ErrInvalidManagementTelemetry = errors.New("invalid management telemetry")

// ManagementTelemetry owns bounded-cardinality management request metrics.
type ManagementTelemetry struct {
	collectors []prometheus.Collector
	active     prometheus.Gauge
	limit      prometheus.Gauge
	requests   *prometheus.CounterVec
	duration   *prometheus.HistogramVec
}

// NewManagementTelemetry constructs isolated metrics without the default registry.
func NewManagementTelemetry(requestLimit int) (*ManagementTelemetry, error) {
	if requestLimit <= 0 || requestLimit > maximumManagementRequests {
		return nil, ErrInvalidManagementTelemetry
	}
	active := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_management_requests_active",
		Help: "Number of admitted management requests currently active.",
	})
	limit := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_management_requests_limit",
		Help: "Configured per-process management request admission limit.",
	})
	limit.Set(float64(requestLimit))
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_management_requests_total",
		Help: "Total management requests by bounded operation and terminal result.",
	}, []string{"operation", "result"})
	duration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_management_request_duration_seconds",
		Help:    "Management request duration by bounded operation and terminal result.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
	}, []string{"operation", "result"})
	telemetry := &ManagementTelemetry{
		active: active, limit: limit, requests: requests, duration: duration,
	}
	telemetry.collectors = []prometheus.Collector{active, limit, requests, duration}
	return telemetry, nil
}

func (telemetry *ManagementTelemetry) requestOpened() { telemetry.active.Inc() }
func (telemetry *ManagementTelemetry) requestClosed() { telemetry.active.Dec() }

func (telemetry *ManagementTelemetry) observe(operation, result string, duration time.Duration) {
	telemetry.requests.WithLabelValues(operation, result).Inc()
	telemetry.duration.WithLabelValues(operation, result).Observe(duration.Seconds())
}

// Describe implements prometheus.Collector.
func (telemetry *ManagementTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	for _, collector := range telemetry.collectors {
		collector.Describe(descriptions)
	}
}

// Collect implements prometheus.Collector.
func (telemetry *ManagementTelemetry) Collect(metrics chan<- prometheus.Metric) {
	for _, collector := range telemetry.collectors {
		collector.Collect(metrics)
	}
}

// MetricsCollector returns this handler's private-operator collector.
func (handler *ManagementHandler) MetricsCollector() prometheus.Collector {
	if handler == nil || handler.telemetry == nil {
		return nil
	}
	return handler.telemetry
}

var _ prometheus.Collector = (*ManagementTelemetry)(nil)
