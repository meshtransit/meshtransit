package relayauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"meshtransit.net/core/internal/platform/clientip"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

var t0 = time.UnixMilli(1760000000000).UTC()

func signer(t *testing.T, b byte) key.SigningPrivate {
	t.Helper()
	k, err := key.SigningPrivateFromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

const mapJSON = `{
  "schema_version": 1,
  "revision": 3,
  "regions": [{
    "id": 1, "code": "sgp", "name": "Singapore",
    "nodes": [{
      "name": "sgp1", "host_name": "relay-sgp1.meshtransit.net",
      "ipv4": "18.142.253.199",
      "key": "mtrelay:18b4b75ba362b5f9ae802fa02d840ab49038436ad1d51a2ea7510c3f1fa27a3e",
      "udp_port": 3479, "tls_port": 443, "stun_port": 3478, "stun_alt_port": 3480, "weight": 100
    }]
  }]
}`

func testMap(t *testing.T) mtrp.RelayMap {
	t.Helper()
	m, err := decodeMap([]byte(mapJSON), t0)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

type clock struct{ ms atomic.Int64 }

func newClock(at time.Time) *clock {
	c := &clock{}
	c.ms.Store(at.UnixMilli())
	return c
}

func (c *clock) now() time.Time          { return time.UnixMilli(c.ms.Load()) }
func (c *clock) advance(d time.Duration) { c.ms.Add(d.Milliseconds()) }

func TestDecodeMap(t *testing.T) {
	t.Parallel()

	m := testMap(t)
	if m.Version != 3 || len(m.Regions) != 1 || len(m.Regions[0].Nodes) != 1 {
		t.Fatalf("decoded map = %+v", m)
	}
	node := m.Regions[0].Nodes[0]
	if node.IPv4 != netip.MustParseAddr("18.142.253.199") || node.TLSPort != 443 || node.Key.IsZero() {
		t.Fatalf("decoded node = %+v", node)
	}
	for name, input := range map[string]string{
		"unknown field":  strings.Replace(mapJSON, `"revision"`, `"extra": 1, "revision"`, 1),
		"schema version": strings.Replace(mapJSON, `"schema_version": 1`, `"schema_version": 2`, 1),
		"trailing data":  mapJSON + "{}",
		"bad address":    strings.Replace(mapJSON, "18.142.253.199", "18.142.253", 1),
		"zoned address":  strings.Replace(mapJSON, `"ipv4": "18.142.253.199"`, `"ipv6": "fe80::1%eth0"`, 1),
		"no regions":     `{"schema_version": 1, "revision": 1, "regions": []}`,
	} {
		if _, err := decodeMap([]byte(input), t0); !errors.Is(err, ErrInvalidMap) {
			t.Errorf("%s: error = %v, want ErrInvalidMap", name, err)
		}
	}
}

func TestLoadMapVerifiesDigest(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "relay-map.json")
	if err := os.WriteFile(path, []byte(mapJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(mapJSON))
	if _, err := LoadMap(t.Context(), path, digest, t0); err != nil {
		t.Fatalf("LoadMap() error = %v", err)
	}
	digest[0] ^= 1
	if _, err := LoadMap(t.Context(), path, digest, t0); !errors.Is(err, ErrInvalidMap) {
		t.Fatalf("LoadMap() with wrong digest error = %v", err)
	}
}

func newPublisher(t *testing.T, c *clock, opts Options) *Publisher {
	t.Helper()
	opts.Now = c.now
	p, err := NewPublisher(opts)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func openState(t *testing.T, doc *document, keys ...key.SigningPublic) mtrp.RelayState {
	t.Helper()
	payload, _, err := mtrp.OpenDocument(doc.body, mtrp.DocumentRelayState, mtrp.NewStaticKeys(keys...))
	if err != nil {
		t.Fatal(err)
	}
	s, err := mtrp.ParseRelayState(payload)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type revocations struct {
	err   error
	nodes []mtrp.RevocationID
}

func (r revocations) RelayRevocations(context.Context, time.Time) (tickets, nodes, discos []mtrp.RevocationID, err error) {
	return nil, r.nodes, nil, r.err
}

func TestPublisherSignsStateAndMap(t *testing.T) {
	t.Parallel()

	current, next := signer(t, 1), signer(t, 2)
	c := newClock(t0)
	m := testMap(t)
	drained := key.RelayPublic{0x5e}
	revoked := mtrp.RevocationHash(mtrp.RevokeNode, []byte{1})
	p := newPublisher(t, c, Options{
		Signer: current, Next: &next, Map: &m, Drain: []key.RelayPublic{drained},
		Revocations: revocations{nodes: []mtrp.RevocationID{revoked}},
	})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	s := openState(t, p.state.Load(), current.Public())
	if s.Sequence != t0.UnixMilli() || !s.ExpiresAt.Equal(t0.Add(StateLifetime)) {
		t.Fatalf("state timing = seq %d expires %v", s.Sequence, s.ExpiresAt)
	}
	if len(s.SigningKeys) != 2 || s.SigningKeys[1].Key != next.Public() ||
		!s.SigningKeys[0].NotAfter.Equal(t0.Add(keyTrustWindow)) {
		t.Fatalf("signing keys = %+v", s.SigningKeys)
	}
	if len(s.Drain) != 1 || s.Drain[0] != drained || len(s.Nodes) != 1 || s.Nodes[0] != revoked {
		t.Fatal("drain or revocations not published")
	}
	if _, _, err := mtrp.OpenDocument(p.state.Load().body, mtrp.DocumentRelayState, mtrp.NewStaticKeys(next.Public())); err == nil {
		t.Fatal("state verified with the next key, which must not sign")
	}

	payload, _, err := mtrp.OpenDocument(p.relayMap.Load().body, mtrp.DocumentRelayMap, mtrp.NewStaticKeys(current.Public()))
	if err != nil {
		t.Fatal(err)
	}
	signedMap, err := mtrp.ParseRelayMap(payload, t0)
	if err != nil || signedMap.Version != 3 || !signedMap.ExpiresAt.Equal(t0.Add(MapLifetime)) {
		t.Fatalf("signed map = %+v, %v", signedMap, err)
	}
}

func TestPublisherSignsOncePerWindow(t *testing.T) {
	t.Parallel()

	current := signer(t, 1)
	c := newClock(t0.Add(3 * time.Second))
	p := newPublisher(t, c, Options{Signer: current})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	first := p.state.Load()
	if got := openState(t, first, current.Public()); got.Sequence != t0.UnixMilli() || !got.IssuedAt.Equal(t0) {
		t.Fatalf("first state seq %d issued %v, want the window start", got.Sequence, got.IssuedAt)
	}
	// A later tick in the same window and a clock step back keep the document.
	c.advance(5 * time.Second)
	if err := p.refresh(t.Context()); err != nil || p.state.Load() != first {
		t.Fatalf("same window re-signed: %v", err)
	}
	c.advance(-20 * time.Second)
	if err := p.refresh(t.Context()); err != nil || p.state.Load() != first {
		t.Fatalf("earlier window re-signed: %v", err)
	}
	c.advance(25 * time.Second)
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := openState(t, p.state.Load(), current.Public()).Sequence; got != t0.Add(RefreshInterval).UnixMilli() {
		t.Fatalf("next window sequence = %d", got)
	}
	if p.state.Load().etag == first.etag {
		t.Fatal("etag unchanged for a new document")
	}
	if p.relayMap.Load() != nil {
		t.Fatal("map published without a map file")
	}
}

func TestReplicasPublishIdenticalDocuments(t *testing.T) {
	t.Parallel()

	m := testMap(t)
	opts := Options{Signer: signer(t, 1), Map: &m}
	a := newPublisher(t, newClock(t0.Add(1200*time.Millisecond)), opts)
	b := newPublisher(t, newClock(t0.Add(8700*time.Millisecond)), opts)
	for _, p := range []*Publisher{a, b} {
		if err := p.refresh(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(a.state.Load().body, b.state.Load().body) || a.state.Load().etag != b.state.Load().etag ||
		!bytes.Equal(a.relayMap.Load().body, b.relayMap.Load().body) {
		t.Fatal("replicas signing in the same window published different documents")
	}
}

func TestUntilNextWindow(t *testing.T) {
	t.Parallel()

	if got := untilNextWindow(t0.Add(3 * time.Second)); got != 7*time.Second+windowSlack {
		t.Fatalf("untilNextWindow mid-window = %v", got)
	}
	if got := untilNextWindow(t0); got != RefreshInterval+windowSlack {
		t.Fatalf("untilNextWindow on a boundary = %v", got)
	}
}

func TestPublisherKeepsDocumentsWhenRevocationsFail(t *testing.T) {
	t.Parallel()

	src := &failingSource{}
	p := newPublisher(t, newClock(t0), Options{Signer: signer(t, 1), Revocations: src})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	before := p.state.Load()
	src.fail.Store(true)
	p.opts.Now = func() time.Time { return t0.Add(RefreshInterval) }
	if err := p.refresh(t.Context()); err == nil {
		t.Fatal("refresh succeeded with failing revocation source")
	}
	if p.state.Load() != before {
		t.Fatal("previous state replaced after a failed refresh")
	}
}

type failingSource struct{ fail atomic.Bool }

func (f *failingSource) RelayRevocations(context.Context, time.Time) (tickets, nodes, discos []mtrp.RevocationID, err error) {
	if f.fail.Load() {
		return nil, nil, nil, errors.New("ledger unavailable")
	}
	return nil, nil, nil, nil
}

func TestNewPublisherValidates(t *testing.T) {
	t.Parallel()

	if _, err := NewPublisher(Options{}); err == nil {
		t.Fatal("accepted no signing key")
	}
	current := signer(t, 1)
	if _, err := NewPublisher(Options{Signer: current, Next: &current}); err == nil {
		t.Fatal("accepted next key equal to current")
	}
}

func TestPublisherLifecycle(t *testing.T) {
	t.Parallel()

	p := newPublisher(t, newClock(t0), Options{Signer: signer(t, 1)})
	if p.Done() != nil {
		t.Fatal("Done() before Start must be nil")
	}
	if err := p.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown before Start: %v", err)
	}
	if err := p.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if p.state.Load() == nil {
		t.Fatal("Start returned before the first state was signed")
	}
	if err := p.Start(t.Context()); err == nil {
		t.Fatal("second Start accepted")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := p.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Done():
	default:
		t.Fatal("Done not closed after Shutdown")
	}
}

func serve(h http.Handler, method, path, remote string, header http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), method, path, nil)
	r.RemoteAddr = remote
	for name, values := range header {
		r.Header[name] = values
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHandlerServesDocuments(t *testing.T) {
	t.Parallel()

	m := testMap(t)
	p := newPublisher(t, newClock(t0), Options{Signer: signer(t, 1), Map: &m})
	h := NewHandler(p, clientip.Resolver{})
	const remote = "192.0.2.1:4000"

	if w := serve(h, http.MethodGet, StatePath, remote, nil); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("before first refresh: %d", w.Code)
	}
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	w := serve(h, http.MethodGet, StatePath, remote, nil)
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), p.state.Load().body) ||
		w.Header().Get("ETag") == "" || w.Header().Get("Content-Type") != documentType ||
		w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("GET state: %d %v", w.Code, w.Header())
	}
	etag := w.Header().Get("ETag")
	if w := serve(h, http.MethodGet, StatePath, remote, http.Header{"If-None-Match": {etag}}); w.Code != http.StatusNotModified || w.Body.Len() != 0 {
		t.Fatalf("conditional GET: %d", w.Code)
	}
	if w := serve(h, http.MethodHead, MapPath, remote, nil); w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("HEAD map: %d body %d", w.Code, w.Body.Len())
	}
	if w := serve(h, http.MethodGet, MapPath, remote, nil); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), p.relayMap.Load().body) {
		t.Fatalf("GET map: %d", w.Code)
	}
	if w := serve(h, http.MethodPost, StatePath, remote, nil); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST: %d", w.Code)
	}
	if w := serve(h, http.MethodGet, PathPrefix+"tickets", remote, nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown path: %d", w.Code)
	}
}

func TestHandlerMapNotFoundWithoutMap(t *testing.T) {
	t.Parallel()

	p := newPublisher(t, newClock(t0), Options{Signer: signer(t, 1)})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if w := serve(NewHandler(p, clientip.Resolver{}), http.MethodGet, MapPath, "192.0.2.1:1", nil); w.Code != http.StatusNotFound {
		t.Fatalf("GET map without map: %d", w.Code)
	}
}

func TestHandlerRateLimitsPerSource(t *testing.T) {
	t.Parallel()

	c := newClock(t0)
	p := newPublisher(t, c, Options{Signer: signer(t, 1)})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(p, clientip.Resolver{})
	for i := range sourceBurst {
		if w := serve(h, http.MethodGet, StatePath, "192.0.2.1:1", nil); w.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	w := serve(h, http.MethodGet, StatePath, "[::ffff:192.0.2.1]:2", nil)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("over burst (mapped address): %d", w.Code)
	}
	if w := serve(h, http.MethodGet, StatePath, "192.0.2.2:1", nil); w.Code != http.StatusOK {
		t.Fatalf("other source limited: %d", w.Code)
	}
	c.advance(time.Second)
	if w := serve(h, http.MethodGet, StatePath, "192.0.2.1:1", nil); w.Code != http.StatusOK {
		t.Fatalf("after refill: %d", w.Code)
	}
	if w := serve(h, http.MethodGet, StatePath, "not-an-address", nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("unparseable remote: %d", w.Code)
	}
}

func TestHandlerBoundsSourceTable(t *testing.T) {
	t.Parallel()

	c := newClock(t0)
	p := newPublisher(t, c, Options{Signer: signer(t, 1)})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(p, clientip.Resolver{})
	base := netip.MustParseAddr("10.0.0.0").As4()
	for i := range maxSources {
		a := base
		a[2], a[3] = byte(i>>8), byte(i)
		h.allow(netip.AddrFrom4(a))
	}
	if h.allow(netip.MustParseAddr("192.0.2.9")) {
		t.Fatal("new source admitted while the table is full")
	}
	c.advance(pruneEvery)
	if !h.allow(netip.MustParseAddr("192.0.2.9")) || len(h.buckets) != 1 {
		t.Fatalf("idle sources not pruned: %d buckets", len(h.buckets))
	}
}

func TestHandlerLimitsClientsBehindTrustedProxy(t *testing.T) {
	t.Parallel()

	p := newPublisher(t, newClock(t0), Options{Signer: signer(t, 1)})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	clients, err := clientip.NewResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(p, clients)
	const proxy = "10.0.0.5:443"
	for range sourceBurst {
		serve(h, http.MethodGet, StatePath, proxy, http.Header{"X-Forwarded-For": {"198.51.100.1"}})
	}
	if w := serve(h, http.MethodGet, StatePath, proxy, http.Header{"X-Forwarded-For": {"198.51.100.1"}}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("forwarded client over burst: %d", w.Code)
	}
	if w := serve(h, http.MethodGet, StatePath, proxy, http.Header{"X-Forwarded-For": {"198.51.100.2"}}); w.Code != http.StatusOK {
		t.Fatalf("second client behind the same proxy limited: %d", w.Code)
	}
	if w := serve(h, http.MethodGet, StatePath, proxy, http.Header{"X-Forwarded-For": {"bogus"}}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("malformed forwarding accepted: %d", w.Code)
	}
}
