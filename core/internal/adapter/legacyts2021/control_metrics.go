package legacyts2021

import (
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ErrInvalidControlTelemetry reports invalid immutable telemetry limits.
var ErrInvalidControlTelemetry = errors.New("legacyts2021: invalid control telemetry")

type sessionAttemptResult uint8

const (
	sessionAttemptInvalidRequest sessionAttemptResult = iota
	sessionAttemptCapacity
	sessionAttemptShutdown
	sessionAttemptTransportFailure
	sessionAttemptHandshakeFailure
	sessionAttemptCapabilityFailure
	sessionAttemptIdentityFailure
	sessionAttemptHandlerFailure
	sessionAttemptEstablished
)

// ControlTelemetry owns one process's concurrency-safe control-ingress metrics.
// Every label value comes from a closed internal enum.
type ControlTelemetry struct {
	collectors            []prometheus.Collector
	connectionCapacity    int
	sessionCapacity       int
	connectionsActive     prometheus.Gauge
	connectionLimit       prometheus.Gauge
	connectionRejections  prometheus.Counter
	sessionSlotsActive    prometheus.Gauge
	authenticatedActive   prometheus.Gauge
	sessionLimit          prometheus.Gauge
	sessionAttempts       *prometheus.CounterVec
	handshakeDuration     *prometheus.HistogramVec
	authenticatedDuration prometheus.Histogram
	registrations         registrationMetrics
	maps                  mapMetrics
}

// NewControlTelemetry constructs isolated metrics without using the default registry.
func NewControlTelemetry(connectionLimit, sessionLimit int) (*ControlTelemetry, error) {
	if connectionLimit < 1 || connectionLimit > maxControlSessions ||
		sessionLimit < 1 || sessionLimit > maxControlSessions {
		return nil, ErrInvalidControlTelemetry
	}
	// Dashboard: meshtransit_control_connections_active / meshtransit_control_connections_limit
	// Alert: meshtransit_control_connections_active / meshtransit_control_connections_limit > 0.9
	connectionsActive := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_control_connections_active",
		Help: "Number of accepted public control connections, including TLS handshakes.",
	})
	connectionLimitMetric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_control_connections_limit",
		Help: "Configured per-process public control connection limit.",
	})
	connectionLimitMetric.Set(float64(connectionLimit))
	// Dashboard: rate(meshtransit_control_connection_rejections_total[5m])
	// Alert: rate(meshtransit_control_connection_rejections_total[5m]) > 0
	connectionRejections := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "meshtransit_control_connection_rejections_total",
		Help: "Total public control connections rejected before TLS due to capacity.",
	})
	// Dashboard: meshtransit_control_session_slots_active / meshtransit_control_sessions_limit
	// Alert: meshtransit_control_session_slots_active / meshtransit_control_sessions_limit > 0.9
	sessionSlotsActive := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_control_session_slots_active",
		Help: "Number of control session slots occupied by handshake or authenticated work.",
	})
	// Dashboard: meshtransit_control_authenticated_sessions_active
	authenticatedActive := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_control_authenticated_sessions_active",
		Help: "Number of active transport-authenticated control sessions.",
	})
	sessionLimitMetric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_control_sessions_limit",
		Help: "Configured per-process control session admission limit.",
	})
	sessionLimitMetric.Set(float64(sessionLimit))
	// Dashboard: sum by (result) (rate(meshtransit_control_session_attempts_total[5m]))
	// Alert: sum(rate(meshtransit_control_session_attempts_total{result!="established"}[5m])) > 1
	sessionAttempts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meshtransit_control_session_attempts_total",
		Help: "Total control session attempts by bounded terminal result.",
	}, []string{"result"})
	for _, result := range allSessionAttemptResults() {
		sessionAttempts.WithLabelValues(result.label())
	}
	// Dashboard: histogram_quantile(0.99, sum by (le, result) (rate(meshtransit_control_noise_handshake_duration_seconds_bucket[5m])))
	handshakeDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "meshtransit_control_noise_handshake_duration_seconds",
		Help:    "Noise handshake duration by bounded result.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
	}, []string{"result"})
	for _, result := range []string{"success", "failure"} {
		handshakeDuration.WithLabelValues(result)
	}
	// Dashboard: histogram_quantile(0.99, sum by (le) (rate(meshtransit_control_authenticated_session_duration_seconds_bucket[5m])))
	authenticatedDuration := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "meshtransit_control_authenticated_session_duration_seconds",
		Help:    "Duration of established transport-authenticated control sessions.",
		Buckets: []float64{0.1, 0.5, 1, 5, 15, 30, 60, 300, 900, 3600},
	})
	registrations := newRegistrationMetrics()
	maps := newMapMetrics()

	telemetry := &ControlTelemetry{
		connectionCapacity:    connectionLimit,
		sessionCapacity:       sessionLimit,
		connectionsActive:     connectionsActive,
		connectionLimit:       connectionLimitMetric,
		connectionRejections:  connectionRejections,
		sessionSlotsActive:    sessionSlotsActive,
		authenticatedActive:   authenticatedActive,
		sessionLimit:          sessionLimitMetric,
		sessionAttempts:       sessionAttempts,
		handshakeDuration:     handshakeDuration,
		authenticatedDuration: authenticatedDuration,
		registrations:         registrations,
		maps:                  maps,
	}
	telemetry.collectors = []prometheus.Collector{
		telemetry.connectionsActive,
		telemetry.connectionLimit,
		telemetry.connectionRejections,
		telemetry.sessionSlotsActive,
		telemetry.authenticatedActive,
		telemetry.sessionLimit,
		telemetry.sessionAttempts,
		telemetry.handshakeDuration,
		telemetry.authenticatedDuration,
	}
	registrationCollectors := registrations.collectors()
	telemetry.collectors = append(telemetry.collectors, registrationCollectors[:]...)
	mapCollectors := maps.collectors()
	telemetry.collectors = append(telemetry.collectors, mapCollectors[:]...)
	return telemetry, nil
}

func allSessionAttemptResults() [9]sessionAttemptResult {
	return [9]sessionAttemptResult{
		sessionAttemptInvalidRequest,
		sessionAttemptCapacity,
		sessionAttemptShutdown,
		sessionAttemptTransportFailure,
		sessionAttemptHandshakeFailure,
		sessionAttemptCapabilityFailure,
		sessionAttemptIdentityFailure,
		sessionAttemptHandlerFailure,
		sessionAttemptEstablished,
	}
}

// Describe implements prometheus.Collector.
func (telemetry *ControlTelemetry) Describe(descriptions chan<- *prometheus.Desc) {
	for _, collector := range telemetry.collectors {
		collector.Describe(descriptions)
	}
}

// Collect implements prometheus.Collector.
func (telemetry *ControlTelemetry) Collect(metrics chan<- prometheus.Metric) {
	for _, collector := range telemetry.collectors {
		collector.Collect(metrics)
	}
}

// MetricsCollector returns the listener's process-local, private-operator collector.
func (listener *ControlListener) MetricsCollector() prometheus.Collector {
	if listener == nil || listener.telemetry == nil {
		return nil
	}
	return listener.telemetry
}

func (telemetry *ControlTelemetry) connectionOpened() {
	telemetry.connectionsActive.Inc()
}

func (telemetry *ControlTelemetry) connectionClosed() {
	telemetry.connectionsActive.Dec()
}

func (telemetry *ControlTelemetry) connectionRejected() {
	telemetry.connectionRejections.Inc()
}

func (telemetry *ControlTelemetry) sessionSlotOpened() {
	telemetry.sessionSlotsActive.Inc()
}

func (telemetry *ControlTelemetry) sessionSlotClosed() {
	telemetry.sessionSlotsActive.Dec()
}

func (telemetry *ControlTelemetry) recordSessionAttempt(result sessionAttemptResult) {
	telemetry.sessionAttempts.WithLabelValues(result.label()).Inc()
}

func (telemetry *ControlTelemetry) recordHandshake(duration time.Duration, succeeded bool) {
	result := "failure"
	if succeeded {
		result = "success"
	}
	telemetry.handshakeDuration.WithLabelValues(result).Observe(duration.Seconds())
}

func (telemetry *ControlTelemetry) authenticatedSessionOpened() time.Time {
	telemetry.authenticatedActive.Inc()
	return time.Now()
}

func (telemetry *ControlTelemetry) authenticatedSessionClosed(startedAt time.Time) {
	telemetry.authenticatedActive.Dec()
	telemetry.authenticatedDuration.Observe(time.Since(startedAt).Seconds())
}

func (result sessionAttemptResult) label() string {
	switch result {
	case sessionAttemptInvalidRequest:
		return "invalid_request"
	case sessionAttemptCapacity:
		return "capacity"
	case sessionAttemptShutdown:
		return "shutdown"
	case sessionAttemptTransportFailure:
		return "transport_failure"
	case sessionAttemptHandshakeFailure:
		return "handshake_failure"
	case sessionAttemptCapabilityFailure:
		return "capability_failure"
	case sessionAttemptIdentityFailure:
		return "identity_failure"
	case sessionAttemptHandlerFailure:
		return "handler_failure"
	case sessionAttemptEstablished:
		return "established"
	default:
		return "internal_failure"
	}
}

var _ prometheus.Collector = (*ControlTelemetry)(nil)
