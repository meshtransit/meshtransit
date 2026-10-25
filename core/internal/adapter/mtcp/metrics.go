package mtcp

import (
	"fmt"
	mtcpv1 "meshtransit.net/api/mtcp/v1"
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
	// routeOffers counts stored offers by result; routeOfferDropped the
	// offered prefixes ignored as unusable (mtcp-v1 §8.2).
	routeOffers       *prometheus.CounterVec
	exitOffers        *prometheus.CounterVec
	routeOfferDropped prometheus.Counter
	// routes counts the Sites of routes sent to nodes by status, and those
	// the bounds of one map left out (mtcp-v1 §7.6, §14).
	routes *prometheus.CounterVec
	// dnsRelayDropped counts the zones' Internet resolvers left out of the
	// relay lists sent to exit nodes by a map's bounds (TD-CORE-88).
	dnsRelayDropped prometheus.Counter
}

// The closed set of route statuses and cut Sites counted when sent.
var routeResults = []string{"served", "unserved", "conflict", "capacity", "omitted"}

// The closed set of route offer store results.
const (
	routeOfferChanged   = "changed"
	routeOfferUnchanged = "unchanged"
	routeOfferFailed    = "failed"
)

// The closed set of ways a map's names were degraded (mapsession.DNSView).
const (
	// namesUnlabeled: a Device of the Network was listed without a name.
	namesUnlabeled = "unlabeled_device"
	// namesDropped: a record was left out (a taken name or past the limit).
	namesDropped = "dropped_record"
	// namesOverBudget: a zone, search domain or name was left out by the
	// route budget of one map (DNS design D3 §4.3).
	namesOverBudget = "route_budget"
	// namesDNSDigestFailed: the DNS digest of a map sent to a node that
	// reports the DNS it applied could not be computed (DNS design D1b §8).
	namesDNSDigestFailed = "dns_digest_failed"
)

// The closed set of per-session limits (rate_budget.go).
const (
	limitInbound        = "inbound"
	limitResync         = "resync"
	limitEnforcement    = "enforcement"
	limitBrowser        = "browser"
	limitIdentity       = "identity"
	limitRouteOffer     = "route_offer"
	limitRouteHealth    = "route_health"
	limitDNSHealth      = "dns_health"
	limitRouteSelection = "route_selection"
	// limitSendDeadline: a message was not sent by its send deadline.
	limitSendDeadline = "send_deadline"
	// limitGatewayContested: a gateway session asked to rotate a key while
	// its machine key was contested (§6.8), as a copy of its Secret would.
	limitGatewayContested = "gateway_contested"
)

var sessionLimits = []string{limitInbound, limitResync, limitEnforcement, limitBrowser, limitIdentity,
	limitRouteOffer, limitRouteHealth, limitDNSHealth, limitRouteSelection, limitSendDeadline, limitGatewayContested}

// streamEndReasons is the closed set of map stream end causes.
var streamEndReasons = []string{
	"suspended", "unauthorized", "presence_conflict", "presence_churn", "unavailable", "write_failed",
	"discontinuity", "other",
}

var handshakeResults = []string{
	"invalid", "unknown_key", "shed", "decrypt", "replay", "internal", "respond", "rejected", "responded",
	"not_established", "established",
	// A Kubernetes gateway refused before it proved its node key (§6.7):
	// a retired machine key or a node key that is not current is what a
	// stale copy of its Secret presents.
	"gateway_unproven", "gateway_retired", "gateway_stale_node_key", "gateway_bad_proof",
	// A gateway session pushed out a live session of its machine key; a
	// second holder of its keys was refused a stale timestamp; a gateway's
	// timestamp was too far ahead.
	"gateway_replaced", "gateway_contested", "gateway_future_timestamp",
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
		// label trigger), names that collide, or a Network whose zones and
		// names pass what one client routes; the maps themselves still flow.
		mapNames: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_map_names_degraded_total",
			Help: "Device names and DNS records left out of encoded maps, or DNS evidence lost, by bounded cause.",
		}, []string{"reason"}),
		// Watch: failed means routers may keep serving with an old offer;
		// dropped prefixes are entries clients should not send.
		routeOffers: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_route_offers_total",
			Help: "Subnet offers of HostinfoReports stored, by result (changed, unchanged, failed).",
		}, []string{"result"}),
		exitOffers: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_exit_offers_total",
			Help: "Exit offers of HostinfoReports stored, by result (changed, unchanged, failed).",
		}, []string{"result"}),
		routeOfferDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_route_offer_prefixes_dropped_total",
			Help: "Offered subnet prefixes ignored as malformed, not canonical or unusable for a Site.",
		}),
		// Watch: conflict or capacity growing means policies or routers that
		// cannot serve every consumer; omitted means a map hit its bounds.
		routes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_map_route_sites_total",
			Help: "Sites in subnet routes sent to nodes, by status, and Sites left out by a map's bounds.",
		}, []string{"result"}),
		// Watch: above zero means consumers are refused resolvers admins
		// chose (more than 256 resolvers, 64 Group sets or 16,384 consumers).
		dnsRelayDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_dns_relay_targets_dropped_total",
			Help: "DNS zone resolver listings left out of the relay lists sent to exit nodes by a map's bounds, counted per list sent; above zero since start means some were.",
		}),
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
	for _, reason := range []string{namesUnlabeled, namesDropped, namesOverBudget, namesDNSDigestFailed} {
		metrics.mapNames.WithLabelValues(reason)
	}
	for _, result := range []string{routeOfferChanged, routeOfferUnchanged, routeOfferFailed} {
		metrics.routeOffers.WithLabelValues(result)
		metrics.exitOffers.WithLabelValues(result)
	}
	for _, result := range routeResults {
		metrics.routes.WithLabelValues(result)
	}
	return metrics
}

// Collectors returns the collectors to register.
func (metrics *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{metrics.handshakes, metrics.sessions, metrics.messages, metrics.streamEnds,
		metrics.sheds, metrics.unproven, metrics.forwarding, metrics.keyExpiry, metrics.limits, metrics.mapNames,
		metrics.expiring, metrics.routeOffers, metrics.exitOffers, metrics.routeOfferDropped, metrics.routes, metrics.dnsRelayDropped, routedFilterOmitted,
		exitFilterOmitted}
}

// routedFilterOmitted reports the routed traffic groups left out of router
// filters (TD-CORE-64). Watch: any increase means a router has more
// consumers than one filter holds; some Sites refuse them.
var routedFilterOmitted = prometheus.NewCounterFunc(prometheus.CounterOpts{
	Name: "meshtransit_mtcp_routed_filter_groups_omitted_total",
	Help: "Routed traffic groups left out of a router's packet filter because it was full.",
}, func() float64 { return float64(omittedRoutedFilterGroups.Load()) })

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

// routeOffer counts one stored offer; a nil Metrics counts nothing.
func (metrics *Metrics) routeOffer(result string) {
	if metrics == nil {
		return
	}
	metrics.routeOffers.WithLabelValues(result).Inc()
}

// exitOffer counts one stored exit offer; a nil Metrics counts nothing.
func (metrics *Metrics) exitOffer(result string) {
	if metrics == nil {
		return
	}
	metrics.exitOffers.WithLabelValues(result).Inc()
}

// routesSent counts the Sites of routes a node now holds, when they change.
func (metrics *Metrics) routesSent(routes *mtcpv1.RouteConfig, omitted int) {
	if metrics == nil {
		return
	}
	for _, site := range routes.GetSites() {
		result := "unserved"
		switch site.GetStatus() {
		case mtcpv1.SiteRoute_SERVED:
			result = "served"
		case mtcpv1.SiteRoute_CONFLICT:
			result = "conflict"
		case mtcpv1.SiteRoute_CAPACITY:
			result = "capacity"
		}
		metrics.routes.WithLabelValues(result).Inc()
	}
	if omitted > 0 {
		metrics.routes.WithLabelValues("omitted").Add(float64(omitted))
	}
}

// servedExitsSent counts the relay resolvers an exit node's map leaves out.
func (metrics *Metrics) servedExitsSent(dropped int) {
	if metrics == nil || dropped <= 0 {
		return
	}
	metrics.dnsRelayDropped.Add(float64(dropped))
}

// routeOfferPrefixesDropped counts ignored offered prefixes.
func (metrics *Metrics) routeOfferPrefixesDropped(count int) {
	if metrics == nil || count <= 0 {
		return
	}
	metrics.routeOfferDropped.Add(float64(count))
}

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
