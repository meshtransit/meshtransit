package controllistener

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// ErrInvalidTelemetry reports an invalid connection limit.
var ErrInvalidTelemetry = errors.New("controllistener: invalid telemetry")

// Telemetry is the listener's connection accounting, kept out of the
// default registry.
type Telemetry struct {
	connectionCapacity   int
	connectionsActive    prometheus.Gauge
	connectionLimit      prometheus.Gauge
	connectionRejections prometheus.Counter
}

// NewTelemetry constructs the connection metrics for a listener bound to
// connectionLimit sockets.
func NewTelemetry(connectionLimit int) (*Telemetry, error) {
	if connectionLimit < 1 || connectionLimit > MaxConnections {
		return nil, ErrInvalidTelemetry
	}
	// Dashboard: meshtransit_control_connections_active / meshtransit_control_connections_limit
	// Alert: meshtransit_control_connections_active / meshtransit_control_connections_limit > 0.9
	telemetry := &Telemetry{
		connectionCapacity: connectionLimit,
		connectionsActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "meshtransit_control_connections_active",
			Help: "Number of accepted public control connections, including TLS handshakes.",
		}),
		connectionLimit: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "meshtransit_control_connections_limit",
			Help: "Configured per-process public control connection limit.",
		}),
		// Dashboard: rate(meshtransit_control_connection_rejections_total[5m])
		// Alert: rate(meshtransit_control_connection_rejections_total[5m]) > 0
		connectionRejections: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "meshtransit_control_connection_rejections_total",
			Help: "Total public control connections rejected before TLS due to capacity.",
		}),
	}
	telemetry.connectionLimit.Set(float64(connectionLimit))
	return telemetry, nil
}

func (telemetry *Telemetry) collectors() [3]prometheus.Collector {
	return [3]prometheus.Collector{telemetry.connectionsActive, telemetry.connectionLimit, telemetry.connectionRejections}
}

// Describe implements prometheus.Collector.
func (telemetry *Telemetry) Describe(descriptions chan<- *prometheus.Desc) {
	for _, collector := range telemetry.collectors() {
		collector.Describe(descriptions)
	}
}

// Collect implements prometheus.Collector.
func (telemetry *Telemetry) Collect(metrics chan<- prometheus.Metric) {
	for _, collector := range telemetry.collectors() {
		collector.Collect(metrics)
	}
}

// MetricsCollector returns the listener's process-local, private-operator collector.
func (listener *Listener) MetricsCollector() prometheus.Collector {
	if listener == nil || listener.telemetry == nil {
		return nil
	}
	return listener.telemetry
}

func (telemetry *Telemetry) connectionOpened()   { telemetry.connectionsActive.Inc() }
func (telemetry *Telemetry) connectionClosed()   { telemetry.connectionsActive.Dec() }
func (telemetry *Telemetry) connectionRejected() { telemetry.connectionRejections.Inc() }
