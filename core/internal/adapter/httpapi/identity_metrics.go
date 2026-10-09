package httpapi

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	identityMetricRouteDiscovery     = "discovery"
	identityMetricRouteAuthorization = "authorization"
	identityMetricRouteConnector     = "connector"
	identityMetricRouteCallback      = "callback"
	identityMetricRouteToken         = "token"
	identityMetricRouteKeys          = "keys"
	identityMetricRouteNotFound      = "not_found"
)

// IdentityTelemetry owns one process's bounded broker-ingress measurements.
// Route and result labels are selected only from closed internal sets.
type IdentityTelemetry struct {
	collectors      []prometheus.Collector
	connections     prometheus.Gauge
	connectionLimit prometheus.Gauge
	requestsActive  prometheus.Gauge
	requestLimit    prometheus.Gauge
	requestTotal    *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	saturationTotal prometheus.Counter
}

func newIdentityTelemetry(connectionLimit, requestLimit int) *IdentityTelemetry {
	connections := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_identity_connections_active",
		Help: "Number of accepted private Identity connections, including TLS handshakes.",
	})
	connectionLimitMetric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_identity_connections_limit",
		Help: "Configured per-process private Identity connection limit.",
	})
	connectionLimitMetric.Set(float64(connectionLimit))
	requestsActive := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_identity_requests_active",
		Help: "Number of Identity requests occupying non-queuing admission slots.",
	})
	requestLimitMetric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_identity_requests_limit",
		Help: "Configured per-process Identity request admission limit.",
	})
	requestLimitMetric.Set(float64(requestLimit))
	requestTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_identity_requests_total",
		Help: "Total Identity requests by bounded route and HTTP status class.",
	}, []string{"route", "status"})
	requestDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_identity_request_duration_seconds",
		Help:    "Identity request duration by bounded route.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
	}, []string{"route"})
	saturationTotal := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "meshtransit_identity_saturation_total",
		Help: "Total Identity requests rejected without queueing because admission was full.",
	})
	telemetry := &IdentityTelemetry{
		connections: connections, connectionLimit: connectionLimitMetric,
		requestsActive: requestsActive, requestLimit: requestLimitMetric,
		requestTotal: requestTotal, requestDuration: requestDuration,
		saturationTotal: saturationTotal,
	}
	telemetry.collectors = []prometheus.Collector{
		telemetry.connections,
		telemetry.connectionLimit,
		telemetry.requestsActive,
		telemetry.requestLimit,
		telemetry.requestTotal,
		telemetry.requestDuration,
		telemetry.saturationTotal,
	}
	return telemetry
}

// Describe implements prometheus.Collector.
func (telemetry *IdentityTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	for _, collector := range telemetry.collectors {
		collector.Describe(descriptions)
	}
}

// Collect implements prometheus.Collector.
func (telemetry *IdentityTelemetry) Collect(metrics chan<- prometheus.Metric) {
	for _, collector := range telemetry.collectors {
		collector.Collect(metrics)
	}
}

// MetricsCollector returns the listener's process-local private-operator metrics.
func (owner *IdentityServer) MetricsCollector() prometheus.Collector {
	if owner == nil || owner.telemetry == nil {
		return nil
	}
	return owner.telemetry
}

func (telemetry *IdentityTelemetry) connectionOpened() {
	telemetry.connections.Inc()
}

func (telemetry *IdentityTelemetry) connectionClosed() {
	telemetry.connections.Dec()
}

func (telemetry *IdentityTelemetry) requestOpened() {
	telemetry.requestsActive.Inc()
}

func (telemetry *IdentityTelemetry) requestClosed() {
	telemetry.requestsActive.Dec()
}

func (telemetry *IdentityTelemetry) requestSaturated() {
	telemetry.saturationTotal.Inc()
}

func (telemetry *IdentityTelemetry) recordRequest(route string, status int, elapsed time.Duration) {
	telemetry.requestTotal.WithLabelValues(route, statusClass(status)).Inc()
	telemetry.requestDuration.WithLabelValues(route).Observe(elapsed.Seconds())
}

var _ prometheus.Collector = (*IdentityTelemetry)(nil)
