package mtcp

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	sharedmtcp "meshtransit.net/shared/mtcp"
)

// Metrics owns identifier-free MTCP measurements. Labels come from closed
// sets: handshake outcomes and message type numbers.
type Metrics struct {
	handshakes *prometheus.CounterVec
	sessions   prometheus.Gauge
	messages   *prometheus.CounterVec
}

var handshakeResults = []string{
	"invalid", "unknown_key", "shed", "decrypt", "replay", "internal", "respond", "rejected", "responded",
	"not_established", "established",
}

// NewMetrics constructs unregistered collectors.
func NewMetrics() *Metrics {
	metrics := &Metrics{
		// Dashboard: sum by (result) (rate(meshtransit_mtcp_handshakes_total[5m]))
		handshakes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_handshakes_total",
			Help: "MTCP upgrade attempts by bounded outcome.",
		}, []string{"result"}),
		sessions: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "meshtransit_mtcp_sessions_active",
			Help: "Established MTCP sessions on this replica.",
		}),
		messages: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_messages_total",
			Help: "MTCP messages by direction and message type number.",
		}, []string{"direction", "type"}),
	}
	for _, result := range handshakeResults {
		metrics.handshakes.WithLabelValues(result)
	}
	return metrics
}

// Collectors returns the collectors to register.
func (metrics *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{metrics.handshakes, metrics.sessions, metrics.messages}
}

func (metrics *Metrics) handshake(result string) { metrics.handshakes.WithLabelValues(result).Inc() }
func (metrics *Metrics) sessionOpened()          { metrics.sessions.Inc() }
func (metrics *Metrics) sessionClosed()          { metrics.sessions.Dec() }

func (metrics *Metrics) sent(t sharedmtcp.MessageType) {
	metrics.messages.WithLabelValues("sent", fmt.Sprintf("%#02x", uint8(t))).Inc()
}

func (metrics *Metrics) received(t sharedmtcp.MessageType) {
	metrics.messages.WithLabelValues("received", fmt.Sprintf("%#02x", uint8(t))).Inc()
}
