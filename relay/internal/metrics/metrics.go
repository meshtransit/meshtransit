// Package metrics exports relay counters to Prometheus. Labels are outcome
// names only; no key, address, zone or route number ever becomes a label
// (mtrp-v1 §7).
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Relay holds the relay's collectors. It implements server.Metrics.
type Relay struct {
	registry   *prometheus.Registry
	handshakes *prometheus.CounterVec
	control    *prometheus.CounterVec
	data       *prometheus.CounterVec
	dataBytes  prometheus.Counter
	sessions   prometheus.Gauge
	routes     prometheus.Gauge
	stun       *prometheus.CounterVec
	streams    *prometheus.CounterVec
	certExpiry prometheus.Gauge
	coreLink   *prometheus.CounterVec
	closed     *prometheus.CounterVec
	revoked    prometheus.Gauge
	probes     *prometheus.CounterVec
}

// New registers the relay collectors and the Go runtime and process ones.
func New() *Relay {
	r := &Relay{
		registry: prometheus.NewRegistry(),
		handshakes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshrelay_handshakes_total", Help: "MTRP handshakes by outcome.",
		}, []string{"result"}),
		control: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshrelay_control_frames_total", Help: "CONTROL frames by outcome.",
		}, []string{"result"}),
		data: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshrelay_data_frames_total", Help: "DATA frames by outcome.",
		}, []string{"result"}),
		dataBytes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "meshrelay_data_forwarded_bytes_total", Help: "Payload bytes forwarded.",
		}),
		sessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "meshrelay_sessions", Help: "Active sessions.",
		}),
		routes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "meshrelay_routes", Help: "Active routes.",
		}),
		stun: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshrelay_stun_requests_total", Help: "STUN requests by outcome.",
		}, []string{"result"}),
		streams: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshrelay_stream_events_total", Help: "TLS and WebSocket connection events by outcome.",
		}, []string{"result"}),
		coreLink: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshrelay_core_state_polls_total", Help: "Relay state polls of Core by outcome.",
		}, []string{"result"}),
		closed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshrelay_sessions_closed_total", Help: "Sessions the relay ended, by reason.",
		}, []string{"reason"}),
		revoked: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "meshrelay_revocations", Help: "Revocation entries (tickets, nodes, disco keys, zones) in force from Core.",
		}),
		probes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshrelay_captive_probes_total", Help: "Captive portal probes (GET /generate_204) by outcome.",
		}, []string{"result"}),
		certExpiry: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "meshrelay_tls_certificate_expiry_timestamp_seconds",
			Help: "Expiry of the TLS certificate last served (alert when it nears).",
		}),
	}
	r.registry.MustRegister(
		r.handshakes, r.control, r.data, r.dataBytes, r.sessions, r.routes, r.stun, r.streams, r.certExpiry, r.coreLink,
		r.closed, r.revoked, r.probes,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return r
}

// Handler serves the metrics.
func (r *Relay) Handler() http.Handler {
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{})
}

// Handshake implements server.Metrics.
func (r *Relay) Handshake(result string) { r.handshakes.WithLabelValues(result).Inc() }

// Control implements server.Metrics.
func (r *Relay) Control(result string) { r.control.WithLabelValues(result).Inc() }

// Data implements server.Metrics.
func (r *Relay) Data(result string, payloadBytes int) {
	r.data.WithLabelValues(result).Inc()
	if payloadBytes > 0 {
		r.dataBytes.Add(float64(payloadBytes))
	}
}

// Sessions implements server.Metrics.
func (r *Relay) Sessions(active int) { r.sessions.Set(float64(active)) }

// Routes implements server.Metrics.
func (r *Relay) Routes(delta int) { r.routes.Add(float64(delta)) }

// Stream counts a stream transport event.
func (r *Relay) Stream(result string) { r.streams.WithLabelValues(result).Inc() }

// CertificateServed records the expiry of the certificate being served.
func (r *Relay) CertificateServed(notAfter time.Time) {
	r.certExpiry.Set(float64(notAfter.Unix()))
}

// SessionClosed counts a session the relay ended.
func (r *Relay) SessionClosed(reason string) { r.closed.WithLabelValues(reason).Inc() }

// Revocations records how many revocation entries are in force.
func (r *Relay) Revocations(n int) { r.revoked.Set(float64(n)) }

// CoreLink counts a relay state poll outcome.
func (r *Relay) CoreLink(result string) { r.coreLink.WithLabelValues(result).Inc() }

// STUN counts a STUN request outcome.
func (r *Relay) STUN(result string) { r.stun.WithLabelValues(result).Inc() }

// Probe counts a captive portal probe outcome.
func (r *Relay) Probe(result string) { r.probes.WithLabelValues(result).Inc() }
