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
	streamEnds *prometheus.CounterVec
	sheds      prometheus.Counter
}

// streamEndReasons is the closed set of map stream end causes.
var streamEndReasons = []string{
	"suspended", "unauthorized", "presence_conflict", "unavailable", "write_failed", "discontinuity", "other",
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
		// Alert on: rate(meshtransit_mtcp_map_stream_ends_total{reason="unavailable"}[5m]) > 0
		streamEnds: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_map_stream_ends_total",
			Help: "MTCP map streams that ended on a live session, by bounded cause.",
		}, []string{"reason"}),
		sheds: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_sessions_shed_total",
			Help: "MTCP sessions this replica asked to reconnect elsewhere to rebalance load.",
		}),
	}
	for _, result := range handshakeResults {
		metrics.handshakes.WithLabelValues(result)
	}
	for _, reason := range streamEndReasons {
		metrics.streamEnds.WithLabelValues(reason)
	}
	return metrics
}

// Collectors returns the collectors to register.
func (metrics *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{metrics.handshakes, metrics.sessions, metrics.messages, metrics.streamEnds,
		metrics.sheds}
}

// streamEnded counts a map stream end; a nil Metrics counts nothing.
func (metrics *Metrics) streamEnded(reason string) {
	if metrics == nil {
		return
	}
	metrics.streamEnds.WithLabelValues(reason).Inc()
}

func (metrics *Metrics) handshake(result string) { metrics.handshakes.WithLabelValues(result).Inc() }
func (metrics *Metrics) sessionOpened()          { metrics.sessions.Inc() }
func (metrics *Metrics) sessionClosed()          { metrics.sessions.Dec() }
func (metrics *Metrics) shed(count int)          { metrics.sheds.Add(float64(count)) }

func (metrics *Metrics) sent(t sharedmtcp.MessageType) {
	metrics.messages.WithLabelValues("sent", fmt.Sprintf("%#02x", uint8(t))).Inc()
}

func (metrics *Metrics) received(t sharedmtcp.MessageType) {
	metrics.messages.WithLabelValues("received", fmt.Sprintf("%#02x", uint8(t))).Inc()
}
