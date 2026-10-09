package relayauthority

import (
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/platform/clientip"
)

// Public paths served on the control listener.
const (
	StatePath = "/relay/v1/state"
	MapPath   = "/relay/v1/map"
	// PathPrefix selects the requests the control listener routes here.
	PathPrefix = "/relay/v1/"

	sourceRate   = 20 // requests per second per source address
	sourceBurst  = 40
	maxSources   = 4096
	pruneEvery   = time.Minute
	documentType = "application/vnd.meshtransit.signed-document"
)

// Handler serves the signed documents. Each response is a precomputed byte
// slice; a per-source limiter bounds abuse without touching storage.
type Handler struct {
	publisher *Publisher
	clients   clientip.Resolver
	now       func() time.Time
	metrics   *Metrics

	mu        sync.Mutex
	buckets   map[netip.Addr]*bucket
	lastPrune time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewHandler serves a publisher's documents, rate limiting each client
// address as resolved through the trusted proxies.
func NewHandler(p *Publisher, clients clientip.Resolver) *Handler {
	return &Handler{
		publisher: p, clients: clients, now: p.opts.Now, metrics: p.opts.Metrics,
		buckets: make(map[netip.Addr]*bucket),
	}
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var doc *document
	switch r.URL.Path {
	case StatePath:
		doc = h.publisher.state.Load()
	case MapPath:
		doc = h.publisher.relayMap.Load()
		if doc == nil {
			h.metrics.requests.WithLabelValues("not_found").Inc()
			http.NotFound(w, r)
			return
		}
	default:
		h.metrics.requests.WithLabelValues("not_found").Inc()
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.metrics.requests.WithLabelValues("bad_method").Inc()
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	client, err := h.clients.Resolve(r)
	if err != nil || !h.allow(client) {
		h.metrics.requests.WithLabelValues("rate_limited").Inc()
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if doc == nil {
		h.metrics.requests.WithLabelValues("unavailable").Inc()
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	header := w.Header()
	header.Set("ETag", doc.etag)
	header.Set("Cache-Control", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
	if r.Header.Get("If-None-Match") == doc.etag {
		h.metrics.requests.WithLabelValues("not_modified").Inc()
		w.WriteHeader(http.StatusNotModified)
		return
	}
	header.Set("Content-Type", documentType)
	h.metrics.requests.WithLabelValues("ok").Inc()
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(doc.body)
}

// allow applies the per-source token bucket with bounded memory.
func (h *Handler) allow(addr netip.Addr) bool {
	now := h.now()
	h.mu.Lock()
	defer h.mu.Unlock()
	b, ok := h.buckets[addr]
	if !ok {
		if len(h.buckets) >= maxSources {
			if now.Sub(h.lastPrune) < pruneEvery {
				return false // full and recently pruned: refuse new sources
			}
			h.lastPrune = now
			for a, old := range h.buckets {
				if now.Sub(old.last) > 2*time.Second {
					delete(h.buckets, a)
				}
			}
			if len(h.buckets) >= maxSources {
				return false
			}
		}
		b = &bucket{tokens: sourceBurst, last: now}
		h.buckets[addr] = b
	}
	b.tokens = min(sourceBurst, b.tokens+now.Sub(b.last).Seconds()*sourceRate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Metrics are the relay authority's collectors. Labels are outcome names.
type Metrics struct {
	refreshes   *prometheus.CounterVec
	requests    *prometheus.CounterVec
	tickets     *prometheus.CounterVec
	revocations prometheus.Gauge
	lastSuccess prometheus.Gauge
}

// NewMetrics creates unregistered collectors.
func NewMetrics() *Metrics {
	return &Metrics{
		refreshes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_relay_authority_refreshes_total", Help: "Relay state and map signing rounds by outcome.",
		}, []string{"result"}),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_relay_authority_requests_total", Help: "Relay state and map requests by outcome.",
		}, []string{"result"}),
		tickets: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "meshtransit_relay_authority_tickets_total", Help: "Relay tickets issued to nodes, by outcome.",
		}, []string{"result"}),
		revocations: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "meshtransit_relay_authority_revocations", Help: "Revocation entries in the published relay state.",
		}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "meshtransit_relay_authority_last_refresh_timestamp_seconds", Help: "Time of the last successful signing round.",
		}),
	}
}

// Describe implements prometheus.Collector.
func (m *Metrics) Describe(ch chan<- *prometheus.Desc) {
	m.refreshes.Describe(ch)
	m.requests.Describe(ch)
	m.tickets.Describe(ch)
	m.revocations.Describe(ch)
	m.lastSuccess.Describe(ch)
}

// Collect implements prometheus.Collector.
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	m.refreshes.Collect(ch)
	m.requests.Collect(ch)
	m.tickets.Collect(ch)
	m.revocations.Collect(ch)
	m.lastSuccess.Collect(ch)
}
