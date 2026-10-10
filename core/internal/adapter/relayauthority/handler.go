package relayauthority

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/platform/clientip"
	"meshtransit.net/shared/key"
)

// Public paths served on the control listener.
const (
	StatePath = "/relay/v1/state"
	MapPath   = "/relay/v1/map"
	// GrantPath serves a Private Interchange relay its sealed grant
	// (mtrp-v1 §9.2): GET /relay/v1/grant?relay=<mtrelay:…>.
	GrantPath = "/relay/v1/grant"
	// PathPrefix selects the requests the control listener routes here.
	PathPrefix = "/relay/v1/"

	// Sources are IPv4 addresses and IPv6 /64s, as on the relay. The table
	// is bounded; when it is full the least recently seen source is
	// evicted, so filling it never locks out a relay arriving later.
	sourceRate     = 20 // requests per second per source
	sourceBurst    = 40
	maxSources     = 4096
	ipv6SourceBits = 64
	documentType   = "application/vnd.meshtransit.signed-document"

	// MaxStateWait bounds a relay's long poll for the next state (wait=N
	// seconds, mtrp-v1 §9); maxStateWaiters bounds the polls held at once.
	// Past it a poll is answered at once and the relay simply asks again.
	// maxStateWaitersPerSource keeps one source from taking every slot.
	MaxStateWait             = 25 * time.Second
	maxStateWaiters          = 1024
	maxStateWaitersPerSource = 4
	stateWriteSlack          = 10 * time.Second
)

// Handler serves the signed documents. Each response is a precomputed byte
// slice; a per-source limiter bounds abuse without touching storage.
type Handler struct {
	publisher *Publisher
	clients   clientip.Resolver
	now       func() time.Time
	metrics   *Metrics

	mu      sync.Mutex
	buckets map[netip.Prefix]*bucket
	held    map[netip.Prefix]int // long polls held per source

	waiters chan struct{} // semaphore of held long polls
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
		buckets: make(map[netip.Prefix]*bucket), held: make(map[netip.Prefix]int),
		waiters: make(chan struct{}, maxStateWaiters),
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
	case GrantPath:
		h.serveGrant(w, r)
		return
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
	if r.URL.Path == StatePath {
		wait, ok := stateWait(r)
		if !ok {
			h.metrics.requests.WithLabelValues("bad_request").Inc()
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if wait > 0 && r.Header.Get("If-None-Match") == doc.etag {
			doc = h.awaitState(w, r, sourceOf(client), doc, wait)
		}
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

// stateWait reads the optional wait=N (1–25 seconds) of a state request.
func stateWait(r *http.Request) (time.Duration, bool) {
	query := r.URL.Query()
	if len(query) == 0 {
		return 0, true
	}
	values := query["wait"]
	if len(query) != 1 || len(values) != 1 {
		return 0, false
	}
	seconds, err := strconv.Atoi(values[0])
	if err != nil || seconds < 1 || time.Duration(seconds)*time.Second > MaxStateWait {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

// awaitState holds a relay that already has held until a newer state is
// stored, its wait ends or it goes away, and returns the state to answer.
func (h *Handler) awaitState(w http.ResponseWriter, r *http.Request, source netip.Prefix, held *document,
	wait time.Duration) *document {
	if !h.holdFor(source) {
		return held // the source holds its share of polls: answer now
	}
	defer h.releaseFor(source)
	select {
	case h.waiters <- struct{}{}:
		defer func() { <-h.waiters }()
	default:
		return held // too many polls held: answer now
	}
	// The control listener's write timeout is sized for ordinary requests;
	// a held poll needs the wait plus time to write the answer.
	err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(wait + stateWriteSlack))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		return held
	}
	changed := h.publisher.stateChanged()
	if current := h.publisher.state.Load(); current != held {
		return current
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-changed:
		h.metrics.requests.WithLabelValues("long_poll_woken").Inc()
		return h.publisher.state.Load()
	case <-timer.C:
	case <-r.Context().Done():
	}
	return held
}

// serveGrant answers a Private Interchange relay with its grant sealed to
// its key. Anyone may ask; only the relay can read the answer. A key no
// Workspace registered gets 404.
func (h *Handler) serveGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.metrics.requests.WithLabelValues("bad_method").Inc()
		w.Header().Set("Allow", "GET")
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
	query := r.URL.Query()
	relayKey, err := key.ParseRelayPublic(query.Get("relay"))
	if err != nil || len(query) != 1 || len(query["relay"]) != 1 {
		h.metrics.requests.WithLabelValues("bad_request").Inc()
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	sealed, found, err := h.publisher.sealedGrant(relayKey)
	switch {
	case err != nil:
		h.metrics.requests.WithLabelValues("unavailable").Inc()
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	case !found:
		h.metrics.requests.WithLabelValues("not_found").Inc()
		http.NotFound(w, r)
		return
	}
	header := w.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Type", "application/vnd.meshtransit.sealed-relay-grant")
	h.metrics.requests.WithLabelValues("ok").Inc()
	_, _ = w.Write(sealed) //nolint:gosec // G705: an encrypted binary document, never rendered as HTML
}

// sourceOf is the rate-limited source of a client address: the address for
// IPv4, its /64 for IPv6 (one host commonly holds a whole /64).
func sourceOf(addr netip.Addr) netip.Prefix {
	addr = addr.Unmap()
	bits := addr.BitLen()
	if addr.Is6() {
		bits = ipv6SourceBits
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return netip.Prefix{}
	}
	return prefix
}

// allow applies the per-source token bucket with bounded memory.
func (h *Handler) allow(addr netip.Addr) bool {
	source := sourceOf(addr)
	if !source.IsValid() {
		return false
	}
	now := h.now()
	h.mu.Lock()
	defer h.mu.Unlock()
	b, ok := h.buckets[source]
	if !ok {
		if len(h.buckets) >= maxSources {
			h.evictLocked()
		}
		b = &bucket{tokens: sourceBurst, last: now}
		h.buckets[source] = b
	}
	b.tokens = min(sourceBurst, b.tokens+now.Sub(b.last).Seconds()*sourceRate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictLocked drops the least recently seen source that holds no long
// poll. It runs only when the table is full; h.mu is held.
func (h *Handler) evictLocked() {
	var oldest netip.Prefix
	var oldestSeen time.Time
	for source, b := range h.buckets {
		if h.held[source] != 0 {
			continue
		}
		if !oldest.IsValid() || b.last.Before(oldestSeen) {
			oldest, oldestSeen = source, b.last
		}
	}
	if oldest.IsValid() {
		delete(h.buckets, oldest)
	}
}

func (h *Handler) holdFor(source netip.Prefix) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.held[source] >= maxStateWaitersPerSource {
		return false
	}
	h.held[source]++
	return true
}

func (h *Handler) releaseFor(source netip.Prefix) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.held[source] <= 1 {
		delete(h.held, source)
		return
	}
	h.held[source]--
}

// heldBy reports the polls a source holds (for tests).
func (h *Handler) heldBy(source netip.Prefix) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.held[source]
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
