package flowloginternal

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics are the internal API's collectors (C55): labels are route and
// outcome names, never a Network.
type Metrics struct {
	requests     *prometheus.CounterVec
	bytes        *prometheus.CounterVec
	reloads      prometheus.Counter
	reloadedAt   prometheus.Gauge
	certificate  prometheus.Gauge
	rejections   *prometheus.CounterVec
	serverErrors prometheus.Counter
}

// NewMetrics creates unregistered collectors.
func NewMetrics() *Metrics {
	return &Metrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_flowlog_internal_requests_total",
			Help: "Requests of the connection log receiver's internal API, by route and outcome.",
		}, []string{"route", "result"}),
		bytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_flowlog_internal_response_bytes_total",
			Help: "Bytes answered to the connection log receiver, by route.",
		}, []string{"route"}),
		reloads: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "meshtransit_flowlog_internal_tls_reload_failures_total",
			Help: "Failed reads of the internal API's certificate, key or receiver CA.",
		}),
		reloadedAt: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "meshtransit_flowlog_internal_tls_reload_timestamp_seconds",
			Help: "Time of the last good read of the internal API's TLS files; stale after five minutes.",
		}),
		certificate: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "meshtransit_flowlog_internal_tls_certificate_expiry_timestamp_seconds",
			Help: "Expiry of the internal API's server certificate.",
		}),
		rejections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_flowlog_internal_client_rejections_total",
			Help: "Verified client certificates refused as not the receiver, by reason.",
		}, []string{"reason"}),
		serverErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "meshtransit_flowlog_internal_connection_errors_total",
			Help: "Failed handshakes and other connection errors of the internal API.",
		}),
	}
}

func (m *Metrics) reloaded(at time.Time) { m.reloadedAt.Set(float64(at.Unix())) }

func (m *Metrics) certificateExpiry(at time.Time) { m.certificate.Set(float64(at.Unix())) }

func (m *Metrics) rejected(reason string) { m.rejections.WithLabelValues(reason).Inc() }

func (m *Metrics) serverError() { m.serverErrors.Inc() }

func (m *Metrics) request(route, result string) { m.requests.WithLabelValues(route, result).Inc() }

func (m *Metrics) responseBytes(route string, size int) {
	m.bytes.WithLabelValues(route).Add(float64(size))
}

func (m *Metrics) reloadFailed() { m.reloads.Inc() }

// Describe implements prometheus.Collector.
func (m *Metrics) Describe(ch chan<- *prometheus.Desc) {
	m.requests.Describe(ch)
	m.bytes.Describe(ch)
	m.reloads.Describe(ch)
	m.reloadedAt.Describe(ch)
	m.certificate.Describe(ch)
	m.rejections.Describe(ch)
	m.serverErrors.Describe(ch)
}

// Collect implements prometheus.Collector.
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	m.requests.Collect(ch)
	m.bytes.Collect(ch)
	m.reloads.Collect(ch)
	m.reloadedAt.Collect(ch)
	m.certificate.Collect(ch)
	m.rejections.Collect(ch)
	m.serverErrors.Collect(ch)
}
