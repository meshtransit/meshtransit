// Package metrics exports relay counters to Prometheus. Labels are outcome
// names only; no key, address, zone or route number ever becomes a label
// (mtrp-v1 §7).
package metrics

import (
	"net/http"

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
	}
	r.registry.MustRegister(
		r.handshakes, r.control, r.data, r.dataBytes, r.sessions, r.routes, r.stun,
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

// STUN counts a STUN request outcome.
func (r *Relay) STUN(result string) { r.stun.WithLabelValues(result).Inc() }
