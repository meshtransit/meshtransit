package mtcp

import (
	"fmt"
	"sync"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/adapter/kubetoken"
	"meshtransit.net/core/internal/domain/kubeaudit"
	"meshtransit.net/core/internal/domain/kubeca/certqueue"
	"meshtransit.net/core/internal/domain/kubecluster"

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
	// kubeClusters counts, per map message carrying Kubernetes clusters
	// (§7.11), the clusters past a map's bound, the roots past a
	// message's DER budget and the clusters whose zone name is not their
	// certificates' name, by kind.
	kubeClusters *prometheus.CounterVec
	// gatewayKeyAudit counts reports of Kubernetes gateways' stale or
	// contested keys by what became of them (schema 229).
	gatewayKeyAudit *prometheus.CounterVec
	// kubeCerts and kubeCertWait count gateway.cert1 answers (mtcp-v1 §6.9).
	kubeCerts    *prometheus.CounterVec
	kubeCertWait prometheus.Histogram
	// kubeAudits and kubeAuditWait count gateway.audit1 intents answered
	// and how long a batch took; kubeAuditReports their outcomes and
	// denials taken or dropped (K1b0 §8).
	kubeAudits       *prometheus.CounterVec
	kubeAuditWait    prometheus.Histogram
	kubeAuditReports *prometheus.CounterVec
	// gatewayTokenOffset is Core's clock minus a valid pod token's iat
	// (mostly the token's age; negative: the cluster runs ahead);
	// gatewayTokenRemaining, how long a valid token had left.
	gatewayTokenOffset    prometheus.Histogram
	gatewayTokenRemaining prometheus.Histogram
	// gatewayTokenMode is 1 for this replica's gateway token mode, "off"
	// without gateway.token1 (design §3.4 L1).
	gatewayTokenMode *prometheus.GaugeVec
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
	limitInbound = "inbound"
	// limitAudit: a gateway.audit1 message over the session's audit budget
	// (refused or dropped); limitAuditCeiling: over its ceiling (the
	// session ended).
	limitAudit          = "audit"
	limitAuditCeiling   = "audit_ceiling"
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
	// A Kubernetes gateway's rotation refused by its presence (K1a1 plan
	// §16.12): held by another stream, not yet claimed by the session's
	// stream, or unknown (Redis failed). Since K1.1 a contest refuses no
	// rotation (limitGatewayContestOverridden counts it).
	limitGatewayPresenceElsewhere = "gateway_presence_elsewhere"
	limitGatewayPresencePending   = "gateway_presence_pending"
	limitGatewayPresenceUnknown   = "gateway_presence_unknown"
	// limitClusterJoinToken: a cluster join without a valid pod token, or
	// from a cluster with a public issuer (K1.1).
	limitClusterJoinToken = "cluster_join_token"
	// A gateway's rotation refused for its pod token (K1.1 design §7.3):
	// gateway_<kubetoken reason>, the trust missing or unreadable, or the
	// store refusing the token's use (replayed, trust changed, expired).
	limitGatewayTrustMissing     = "gateway_trust_missing"
	limitGatewayTrustUnavailable = "gateway_trust_unavailable"
	limitGatewayTokenStore       = "gateway_token_store_refused"
	// limitGatewayContestOverridden: a rotation with a valid token while the
	// keys were marked contested (design §7.4); counted, not refused.
	limitGatewayContestOverridden = "gateway_contest_overridden"
	// limitGatewayTokenObserved counts what mode observe let through and
	// would have refused; limitGatewayTokenRefresh, GatewayPodToken over
	// its rate (mtcp-v1 §6.7).
	limitGatewayTokenObserved = "gateway_token_observed"
	limitGatewayTokenRefresh  = "gateway_token_refresh"
)

// gatewaySessionTokenLimit names a session refused for its pod token.
func gatewaySessionTokenLimit(reason kubecluster.KeyEventReason) string {
	return "gateway_" + string(reason)
}

// gatewaySessionTokenReasons are the session refusal reasons (schema 246).
var gatewaySessionTokenReasons = []kubecluster.KeyEventReason{
	kubecluster.KeyEventSessionTokenMissing, kubecluster.KeyEventSessionTokenMalformed,
	kubecluster.KeyEventSessionTokenUnknownKey, kubecluster.KeyEventSessionTokenSignature,
	kubecluster.KeyEventSessionTokenExpired, kubecluster.KeyEventSessionTokenAudience,
	kubecluster.KeyEventSessionTokenIdentity, kubecluster.KeyEventSessionTrustMissing,
	kubecluster.KeyEventSessionTrustUnavailable, kubecluster.KeyEventSessionClockSkew,
}

// gatewayTokenLimit names the limit of a token refusal reason.
func gatewayTokenLimit(reason kubetoken.Reason) string { return "gateway_" + string(reason) }

var sessionLimits = []string{limitInbound, limitAudit, limitAuditCeiling, limitResync, limitEnforcement, limitBrowser, limitIdentity,
	limitRouteOffer, limitRouteHealth, limitDNSHealth, limitRouteSelection, limitSendDeadline,
	limitGatewayPresenceElsewhere, limitGatewayPresencePending, limitGatewayPresenceUnknown,
	limitClusterJoinToken, limitGatewayTrustMissing, limitGatewayTrustUnavailable, limitGatewayTokenStore,
	limitGatewayContestOverridden, limitGatewayTokenObserved, limitGatewayTokenRefresh,
	gatewayTokenLimit(kubetoken.ReasonMissing), gatewayTokenLimit(kubetoken.ReasonMalformed),
	gatewayTokenLimit(kubetoken.ReasonUnknownKey), gatewayTokenLimit(kubetoken.ReasonSignature),
	gatewayTokenLimit(kubetoken.ReasonExpired), gatewayTokenLimit(kubetoken.ReasonAudience),
	gatewayTokenLimit(kubetoken.ReasonIdentity)}

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
	// A gateway refused for its pod token (gateway.token1, mtcp-v1 §6.7).
	"gateway_token_required", "gateway_token_refused",
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
		kubeClusters: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_kubernetes_clusters_left_total",
			Help: "Kubernetes cluster entries of client maps (kube.ca1) by kind: dropped past the map's 1,000 clusters, root_deferred past a message's 2 MiB of DER (sent later), name_mismatch when the zone name differs from the name gateways' certificates carry.",
		}, []string{"kind"}),
		dnsRelayDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_dns_relay_targets_dropped_total",
			Help: "DNS zone resolver listings left out of the relay lists sent to exit nodes by a map's bounds, counted per list sent; above zero since start means some were.",
		}),
		// Watch: failed or dropped means key warnings that never reached the
		// audit trail; the handshake metrics still count every case.
		gatewayKeyAudit: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_gateway_key_audit_total",
			Help: "Reports of Kubernetes gateways' stale or contested keys by result: recorded, limited, busy, suppressed, dropped, failed, unknown.",
		}, []string{"result"}),
		// Watch: unavailable means no worker signs (gateways back off for
		// minutes); contested, token or proof climbing means copies of a
		// gateway's identity, or gateways that do not follow the protocol.
		kubeCerts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_mtcp_kube_cert_results_total",
			Help: "Kubernetes gateway certificate requests answered, by outcome and reason.",
		}, []string{"outcome", "reason"}),
		kubeCertWait: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "meshtransit_mtcp_kube_cert_wait_seconds",
			Help:    "How long a Kubernetes gateway certificate request took to answer.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5, 8},
		}),
		// Watch: refused{reason=overloaded|unavailable} over 1% for 5
		// minutes, or a p99 wait over 200 ms (K1b0 §8).
		kubeAudits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_kubernetes_operations_total",
			Help: "Kubernetes gateway operation intents answered, by result and reason.",
		}, []string{"result", "reason"}),
		kubeAuditWait: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "meshtransit_kubernetes_operation_ack_seconds",
			Help:    "How long a batch of Kubernetes operation intents took to answer.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1, 2},
		}),
		kubeAuditReports: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_kubernetes_operation_outcomes_total",
			Help: "Kubernetes operation outcomes and denials queued, or dropped, by kind.",
		}, []string{"kind"}),
		// Watch: offsets below 0 (a cluster ahead of Core); alert under -60.
		gatewayTokenOffset: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "meshtransit_mtcp_gateway_token_age_seconds",
			Help:    "Core's clock minus the iat of each valid gateway pod token; negative: the cluster runs ahead.",
			Buckets: []float64{-120, -60, -30, -10, 0, 60, 300, 480, 600, 900},
		}),
		// Alert: replicas disagree, count(count by (mode) (... == 1)) > 1.
		gatewayTokenMode: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "meshtransit_mtcp_gateway_token_mode",
			Help: "1 for the gateway pod token mode this replica holds gateways to; off without gateway.token1.",
		}, []string{"mode"}),
		// Alert: a p10 under 60 s (kubelet refreshes late, sessions near cut).
		gatewayTokenRemaining: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "meshtransit_mtcp_gateway_token_remaining_seconds",
			Help:    "How long each valid gateway pod token had left when Core checked it.",
			Buckets: []float64{-120, 0, 30, 60, 120, 240, 480, 600, 900},
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
	for _, reason := range gatewaySessionTokenReasons {
		metrics.limits.WithLabelValues(gatewaySessionTokenLimit(reason))
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
	for _, result := range gatewayKeyAuditResults {
		metrics.gatewayKeyAudit.WithLabelValues(result)
	}
	metrics.kubeCerts.WithLabelValues("issued", "")
	metrics.kubeAudits.WithLabelValues("accepted", "")
	for _, outcome := range []kubeaudit.Outcome{kubeaudit.OutcomeConflict, kubeaudit.OutcomeInvalid,
		kubeaudit.OutcomeGateway, kubeaudit.OutcomeDevice, kubeaudit.OutcomeNotGranted, kubeaudit.OutcomeStale,
		kubeaudit.OutcomeLimited, kubeaudit.OutcomeOverloaded, kubeaudit.OutcomeUnavailable} {
		metrics.kubeAudits.WithLabelValues("refused", string(outcome))
	}
	for _, kind := range []string{"outcome", "denial", "dropped"} {
		metrics.kubeAuditReports.WithLabelValues(kind)
	}
	return metrics
}

// Collectors returns the collectors to register.
func (metrics *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{metrics.handshakes, metrics.sessions, metrics.messages, metrics.streamEnds,
		metrics.sheds, metrics.unproven, metrics.forwarding, metrics.keyExpiry, metrics.limits, metrics.mapNames,
		metrics.expiring, metrics.routeOffers, metrics.exitOffers, metrics.routeOfferDropped, metrics.routes, metrics.dnsRelayDropped, metrics.kubeClusters, metrics.gatewayKeyAudit, metrics.kubeCerts, metrics.kubeCertWait,
		metrics.kubeAudits, metrics.kubeAuditWait, metrics.kubeAuditReports, metrics.gatewayTokenOffset,
		metrics.gatewayTokenRemaining, metrics.gatewayTokenMode, routedFilterOmitted,
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

// gatewayTokensHeld sets this replica's gateway token mode; nil tokens is
// off.
func (metrics *Metrics) gatewayTokensHeld(tokens *GatewayTokens) {
	held := "off"
	if tokens != nil {
		held = string(tokens.Mode)
	}
	modes := []string{
		"off", string(kubecluster.GatewayTokenObserve), string(kubecluster.GatewayTokenRatchet),
		string(kubecluster.GatewayTokenRequired),
	}
	for _, mode := range modes {
		value := 0.0
		if mode == held {
			value = 1
		}
		metrics.gatewayTokenMode.WithLabelValues(mode).Set(value)
	}
}

// gatewayTokenAccepted observes a valid gateway pod token; a nil Metrics
// observes nothing.
func (metrics *Metrics) gatewayTokenAccepted(age, remaining time.Duration) {
	if metrics == nil {
		return
	}
	metrics.gatewayTokenOffset.Observe(age.Seconds())
	metrics.gatewayTokenRemaining.Observe(remaining.Seconds())
}

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

// kubernetesClustersSent counts what a map message's Kubernetes clusters
// left out or found mismatched.
func (metrics *Metrics) kubernetesClustersSent(counts kubeClusterCounts) {
	if metrics == nil {
		return
	}
	for kind, count := range map[string]int{
		"dropped": counts.dropped, "root_deferred": counts.deferred, "name_mismatch": counts.mismatched,
	} {
		if count > 0 {
			metrics.kubeClusters.WithLabelValues(kind).Add(float64(count))
		}
	}
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

// gatewayKeyAuditResults is the closed set of report results.
var gatewayKeyAuditResults = []string{"recorded", "limited", "busy", "suppressed", "dropped", "failed", "unknown"}

// kubeCertAnswered counts one certificate request's answer, by outcome
// and a known reason; a nil Metrics counts nothing.
func (metrics *Metrics) kubeCertAnswered(result certqueue.Result, took time.Duration) {
	if metrics == nil {
		return
	}
	outcome, reason := "retry", result.Reason
	switch result.Outcome {
	case certqueue.OutcomeIssued:
		outcome, reason = "issued", ""
	case certqueue.OutcomeRefused:
		outcome = "refused"
	}
	if reason != "" && !certqueue.KnownReason(reason) {
		reason = "other"
	}
	metrics.kubeCerts.WithLabelValues(outcome, reason).Inc()
	if took > 0 {
		metrics.kubeCertWait.Observe(took.Seconds())
	}
}

// kubeCertUnanswered counts a certificate request answered with an Error
// (no capability, no request ID); a nil Metrics counts nothing.
func (metrics *Metrics) kubeCertUnanswered(reason string) {
	if metrics == nil {
		return
	}
	metrics.kubeCerts.WithLabelValues("error", reason).Inc()
}

// gatewayKeyReported counts one report result; a nil Metrics counts nothing.
func (metrics *Metrics) gatewayKeyReported(result string) {
	if metrics == nil {
		return
	}
	metrics.gatewayKeyAudit.WithLabelValues(result).Inc()
}

// kubeAuditAnswered counts one batch's answers and, for one the writer
// answered (took ≥ 0), how long it took; a nil Metrics counts nothing.
func (metrics *Metrics) kubeAuditAnswered(answers []kubeaudit.Answer, took time.Duration) {
	if metrics == nil {
		return
	}
	for _, answer := range answers {
		if answer.Outcome.Recorded() {
			metrics.kubeAudits.WithLabelValues("accepted", "").Inc()
			continue
		}
		metrics.kubeAudits.WithLabelValues("refused", string(answer.Outcome)).Inc()
	}
	if took >= 0 {
		metrics.kubeAuditWait.Observe(took.Seconds())
	}
}

// kubeAuditReported counts outcomes and denials queued or dropped.
func (metrics *Metrics) kubeAuditReported(kind string, count int) {
	if metrics == nil || count == 0 {
		return
	}
	metrics.kubeAuditReports.WithLabelValues(kind).Add(float64(count))
}
