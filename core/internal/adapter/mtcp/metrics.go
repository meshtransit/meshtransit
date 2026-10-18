package mtcp

import (
	"fmt"
	"sync"

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
	unproven   prometheus.Counter
	forwarding prometheus.Counter
	keyExpiry  prometheus.Gauge
	limits     *prometheus.CounterVec
	mapNames   *prometheus.CounterVec
	expiring   *deviceExpiryCollector
}

// The closed set of ways a map's names were degraded (mapsession.DNSView).
const (
	// namesUnlabeled: a Device of the Network was listed without a name.
	namesUnlabeled = "unlabeled_device"
	// namesDropped: a record was left out (a taken name or past the limit).
	namesDropped = "dropped_record"
)

// The closed set of per-session limits (rate_budget.go).
const (
	limitInbound     = "inbound"
	limitResync      = "resync"
	limitEnforcement = "enforcement"
	limitBrowser     = "browser"
	limitIdentity    = "identity"
	// limitSendDeadline: a message was not sent by its send deadline.
	limitSendDeadline = "send_deadline"
)

var sessionLimits = []string{limitInbound, limitResync, limitEnforcement, limitBrowser, limitIdentity,
	limitSendDeadline}

// streamEndReasons is the closed set of map stream end causes.
var streamEndReasons = []string{
	"suspended", "unauthorized", "presence_conflict", "presence_churn", "unavailable", "write_failed",
	"discontinuity", "other",
}

var handshakeResults = []string{
	"invalid", "unknown_key", "shed", "decrypt", "replay", "internal", "respond", "rejected", "responded",
	"not_established", "established",
}

// NewMetrics constructs unregistered collectors.
func NewMetrics() *Metrics {
	metrics := &Metrics{
		// Alert: sum(meshtransit_mtcp_sessions_device_expiring{within="1d"}) > 0
		expiring: &deviceExpiryCollector{desc: prometheus.NewDesc(
			"meshtransit_mtcp_sessions_device_expiring",
			"Sessions on this replica whose Device expires within the window (14d or 1d) and has not yet; "+
				"a Device that never expires is not counted.",
			[]string{"within"}, nil)},
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
		// Watch, not page: a rising rate means sessions held open without
		// registering, a slot-holding pattern; nodes whose key was not found
		// also end here after the unproven lifetime.
		unproven: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_unproven_sessions_closed_total",
			Help: "MTCP sessions closed because they proved no Device within the unproven limit.",
		}),
		// Alert on: rate(meshtransit_mtcp_untrusted_forwarding_total[15m]) > 0 for long:
		// a reverse proxy missing from the trusted proxies. Clients that
		// connect directly and send such headers themselves also count.
		forwarding: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_untrusted_forwarding_total",
			Help: "MTCP requests whose client-forwarding headers were ignored because the peer is not a trusted proxy.",
		}),
		// Alert on: meshtransit_mtcp_control_key_not_after_timestamp_seconds - time() < 60 * 86400
		// Past it nodes refuse the key and the control role no longer starts.
		// Watch: a rising rate means nodes that do not follow the protocol,
		// or a limit too tight for real traffic.
		limits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_session_limits_total",
			Help: "MTCP messages refused, or sessions ended, by the per-session limit they exceeded.",
		}, []string{"limit"}),
		// Watch: a Device without a DNS label (a write path that bypassed the
		// label trigger) or names that collide; the maps themselves still flow.
		mapNames: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_map_names_degraded_total",
			Help: "Device names and DNS records left out of encoded maps, by bounded cause.",
		}, []string{"reason"}),
		keyExpiry: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "meshtransit_mtcp_control_key_not_after_timestamp_seconds",
			Help: "Expiry of the latest control key this replica answers with (Unix seconds).",
		}),
	}
	for _, result := range handshakeResults {
		metrics.handshakes.WithLabelValues(result)
	}
	for _, limit := range sessionLimits {
		metrics.limits.WithLabelValues(limit)
	}
	for _, reason := range streamEndReasons {
		metrics.streamEnds.WithLabelValues(reason)
	}
	for _, reason := range []string{namesUnlabeled, namesDropped} {
		metrics.mapNames.WithLabelValues(reason)
	}
	return metrics
}

// Collectors returns the collectors to register.
func (metrics *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{metrics.handshakes, metrics.sessions, metrics.messages, metrics.streamEnds,
		metrics.sheds, metrics.unproven, metrics.forwarding, metrics.keyExpiry, metrics.limits, metrics.mapNames,
		metrics.expiring}
}

// streamEnded counts a map stream end; a nil Metrics counts nothing.
func (metrics *Metrics) streamEnded(reason string) {
	if metrics == nil {
		return
	}
	metrics.streamEnds.WithLabelValues(reason).Inc()
}

// namesDegraded counts names a map left out; a nil Metrics counts nothing.
func (metrics *Metrics) namesDegraded(reason string, count int) {
	if metrics == nil || count <= 0 {
		return
	}
	metrics.mapNames.WithLabelValues(reason).Add(float64(count))
}

func (metrics *Metrics) handshake(result string) { metrics.handshakes.WithLabelValues(result).Inc() }

// controlKeysExpire records the latest expiry among keys; a nil Metrics
// records nothing.
func (metrics *Metrics) controlKeysExpire(keys []ControlKey) {
	if metrics == nil || len(keys) == 0 {
		return
	}
	latest := keys[0].NotAfter
	for _, controlKey := range keys[1:] {
		if controlKey.NotAfter.After(latest) {
			latest = controlKey.NotAfter
		}
	}
	metrics.keyExpiry.Set(float64(latest.Unix()))
}
func (metrics *Metrics) sessionOpened()  { metrics.sessions.Inc() }
func (metrics *Metrics) sessionClosed()  { metrics.sessions.Dec() }
func (metrics *Metrics) shed(count int)  { metrics.sheds.Add(float64(count)) }
func (metrics *Metrics) unprovenClosed() { metrics.unproven.Inc() }

func (metrics *Metrics) limited(limit string) {
	if metrics == nil {
		return
	}
	metrics.limits.WithLabelValues(limit).Inc()
}

func (metrics *Metrics) untrustedForwarding() { metrics.forwarding.Inc() }

func (metrics *Metrics) sent(t sharedmtcp.MessageType) {
	metrics.messages.WithLabelValues("sent", fmt.Sprintf("%#02x", uint8(t))).Inc()
}

func (metrics *Metrics) received(t sharedmtcp.MessageType) {
	metrics.messages.WithLabelValues("received", fmt.Sprintf("%#02x", uint8(t))).Inc()
}

// deviceExpiryCollector counts, at scrape time, the sessions whose Device
// expires soon. count is bound by the Server; until then it reports zero.
type deviceExpiryCollector struct {
	desc  *prometheus.Desc
	mu    sync.Mutex
	count func() (within14d, within1d int)
}

func (collector *deviceExpiryCollector) Describe(descriptions chan<- *prometheus.Desc) {
	descriptions <- collector.desc
}

func (collector *deviceExpiryCollector) Collect(metrics chan<- prometheus.Metric) {
	collector.mu.Lock()
	count := collector.count
	collector.mu.Unlock()
	var within14d, within1d int
	if count != nil {
		within14d, within1d = count()
	}
	metrics <- prometheus.MustNewConstMetric(collector.desc, prometheus.GaugeValue, float64(within14d), "14d")
	metrics <- prometheus.MustNewConstMetric(collector.desc, prometheus.GaugeValue, float64(within1d), "1d")
}

// countExpiringDevices binds the count the gauge reports; a nil Metrics
// binds nothing.
func (metrics *Metrics) countExpiringDevices(count func() (within14d, within1d int)) {
	if metrics == nil || metrics.expiring == nil {
		return
	}
	metrics.expiring.mu.Lock()
	metrics.expiring.count = count
	metrics.expiring.mu.Unlock()
}
