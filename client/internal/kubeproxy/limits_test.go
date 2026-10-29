package kubeproxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"meshtransit.net/client/internal/kubeaudit"
)

// limited is a fixture whose limits change makes small.
func limitedFixture(t *testing.T, change func(*Limits)) *fixture {
	t.Helper()
	return newFixtureAt(t, "", func(options *Options) {
		limits := DefaultLimits()
		change(&limits)
		options.Limits = limits
	})
}

// A Device past its rate gets 429 with Retry-After.
func TestLimitsDeviceRate(t *testing.T) {
	t.Parallel()
	f := limitedFixture(t, func(limits *Limits) { limits.DeviceRate, limits.DeviceBurst = 0.01, 2 })
	for range 2 {
		if response, _ := f.do(http.MethodGet, "/api/v1/pods", nil); response.StatusCode != http.StatusOK {
			t.Fatalf("within the burst: %d", response.StatusCode)
		}
		f.forwarded()
	}
	response, body := f.do(http.MethodGet, "/api/v1/pods", nil)
	if response.StatusCode != http.StatusTooManyRequests || response.Header.Get("Retry-After") != "1" ||
		!strings.Contains(body, "rate") {
		t.Fatalf("past the rate: %d %s", response.StatusCode, body)
	}
	if f.server.Limited()[limitRate] != 1 {
		t.Fatalf("limited %v", f.server.Limited())
	}
}

// A Device past its watches gets 429 for the next one; requests go on.
func TestLimitsDeviceWatches(t *testing.T) {
	t.Parallel()
	f := limitedFixture(t, func(limits *Limits) { limits.DeviceWatches = 1 })
	body := f.openStream("/api/v1/namespaces/a/pods?watch=true")
	defer body.Close()
	response, text := f.do(http.MethodGet, "/api/v1/namespaces/b/pods?watch=true", nil)
	if response.StatusCode != http.StatusTooManyRequests || !strings.Contains(text, "watches") {
		t.Fatalf("second watch: %d %s", response.StatusCode, text)
	}
	if response, _ := f.do(http.MethodGet, "/api/v1/namespaces/a/pods/web-0", nil); response.StatusCode != http.StatusOK {
		t.Fatalf("a request beside the watch: %d", response.StatusCode)
	}
}

// Under memory pressure new watches and lists are refused, a get is not.
func TestLimitsMemoryPressure(t *testing.T) {
	t.Parallel()
	f := newFixtureAt(t, "", func(options *Options) { options.Pressure = func() bool { return true } })
	for _, path := range []string{"/api/v1/namespaces/a/pods?watch=true", "/api/v1/namespaces/a/pods"} {
		if response, text := f.do(http.MethodGet, path, nil); response.StatusCode != http.StatusTooManyRequests ||
			!strings.Contains(text, "memory") {
			t.Fatalf("%s: %d %s", path, response.StatusCode, text)
		}
	}
	if response, _ := f.do(http.MethodGet, "/api/v1/namespaces/a/pods/web-0", nil); response.StatusCode != http.StatusOK {
		t.Fatalf("a get under pressure: %d", response.StatusCode)
	}
}

// A Device past its connections fails the TLS handshake; one closed frees
// its place.
func TestLimitsDeviceConnections(t *testing.T) {
	t.Parallel()
	f := limitedFixture(t, func(limits *Limits) { limits.DeviceConnections = 1 })
	roots := f.client.Transport.(*http.Transport).TLSClientConfig.RootCAs
	dial := func() (*tls.Conn, error) {
		return tls.Dial("tcp", f.address, &tls.Config{RootCAs: roots, ServerName: clusterName,
			NextProtos: []string{"http/1.1"}})
	}
	first, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	if second, err := dial(); err == nil {
		_ = second.Close()
		t.Fatal("a second connection was taken")
	}
	_ = first.Close()
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		third, err := dial()
		if err == nil {
			_ = third.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the place was never freed: %v", err)
		}
	}
}

// A source past its handshakes a second has its connections closed.
func TestLimitsSourceHandshakes(t *testing.T) {
	t.Parallel()
	f := limitedFixture(t, func(limits *Limits) { limits.SourceHandshakes = 0.001 })
	roots := f.client.Transport.(*http.Transport).TLSClientConfig.RootCAs
	first, err := tls.Dial("tcp", f.address, &tls.Config{RootCAs: roots, ServerName: clusterName})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := tls.Dial("tcp", f.address, &tls.Config{RootCAs: roots, ServerName: clusterName})
	if err == nil {
		_ = second.SetReadDeadline(time.Now().Add(time.Second))
		_, err = io.ReadAll(second)
		_ = second.Close()
	}
	if err == nil {
		t.Fatal("a second handshake was taken")
	}
	if f.server.Limited()[limitHandshakes] != 1 {
		t.Fatalf("limited %v", f.server.Limited())
	}
}

// Past half the streams a Device keeps to an even share of what is left.
func TestLimitsFairShare(t *testing.T) {
	t.Parallel()
	limits := DefaultLimits()
	limits.Streams = 64
	sessions := newRegistry()
	add := func(device string) string {
		_, limit := sessions.add(&session{device: device, kind: kindWatch}, limits)
		return limit
	}
	for range 32 {
		if limit := add("heavy"); limit != "" {
			t.Fatalf("below half: %s", limit)
		}
	}
	// 32 open of 64, heavy the only user: its share is max(16, 32/1) = 32,
	// which it holds.
	if limit := add("heavy"); limit != limitFairShare {
		t.Fatalf("heavy past its share: %q", limit)
	}
	if limit := add("light"); limit != "" {
		t.Fatalf("light within its share: %q", limit)
	}
	// light stops at its share of 16 too; a third Device still gets in.
	taken := 1
	for add("light") == "" {
		taken++
	}
	if taken != 16 {
		t.Fatalf("light took %d", taken)
	}
	if limit := add("third"); limit != "" {
		t.Fatalf("a third Device: %q", limit)
	}

	// No share past the replica's streams.
	limits.Streams = 4
	small := newRegistry()
	for range 4 {
		if _, limit := small.add(&session{device: "one", kind: kindRequest}, limits); limit != "" {
			t.Fatalf("within the streams: %q", limit)
		}
	}
	if _, limit := small.add(&session{device: "two", kind: kindRequest}, limits); limit != limitStreams {
		t.Fatalf("past the streams: %q", limit)
	}
}

// A connection closed before it joined its Device never counts against it
// (review b6b M1).
func TestLimitsCloseBeforeJoin(t *testing.T) {
	t.Parallel()
	g := newGate(DefaultLimits())
	if limit := g.accept(netip.MustParseAddr("100.64.1.9")); limit != "" {
		t.Fatal(limit)
	}
	conn := &identified{Conn: nopConn{}, gate: g, deviceID: "device-a", source: netip.MustParseAddr("100.64.1.9")}
	_ = conn.Close()
	if limit, joined := conn.join(); joined || limit != "" {
		t.Fatalf("joined after close: %q %t", limit, joined)
	}
	_ = conn.Close()
	if g.open != 0 || g.unidentified != 0 || len(g.devices) != 0 || len(g.sources) != 0 {
		t.Fatalf("open %d, unidentified %d, devices %v, sources %v", g.open, g.unidentified, g.devices, g.sources)
	}
}

// Connections that come and go leave no count behind.
func TestLimitsReleaseEverything(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.do(http.MethodGet, "/api/v1/pods", nil)
	f.forwarded()
	f.client.Transport.(*http.Transport).CloseIdleConnections()
	roots := f.client.Transport.(*http.Transport).TLSClientConfig.RootCAs
	if conn, err := tls.Dial("tcp", f.address, &tls.Config{RootCAs: roots, ServerName: "other.test",
		InsecureSkipVerify: true}); err == nil { //nolint:gosec // the handshake itself fails
		_ = conn.Close()
	}
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		f.server.gate.mu.Lock()
		open, devices, sources := f.server.gate.open, len(f.server.gate.devices), len(f.server.gate.sources)
		f.server.gate.mu.Unlock()
		if open == 0 && devices == 0 && sources == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("open %d, devices %d, sources %d", open, devices, sources)
		}
	}
}

// Full buckets are dropped at the bound; those in use kept.
func TestLimitsPrune(t *testing.T) {
	t.Parallel()
	now := time.Now()
	limiters := map[int]*rate.Limiter{}
	for key := range maximumLimiters {
		limiters[key] = rate.NewLimiter(1, 2)
	}
	limiters[0].AllowN(now, 2)
	prune(limiters, now)
	if len(limiters) != 1 || limiters[0] == nil {
		t.Fatalf("%d kept", len(limiters))
	}
}

// Core's refusals are counted by a known reason or "other".
func TestUnrecordedReasons(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.records.mu.Lock()
	f.records.answer = kubeaudit.Answer{Refused: "something new from Core"}
	f.records.mu.Unlock()
	f.do(http.MethodDelete, "/api/v1/namespaces/a/pods/b", nil)
	if got := f.server.Unrecorded(); got["other"] != 1 || len(got) != 1 {
		t.Fatalf("unrecorded %v", got)
	}
}

type nopConn struct{ net.Conn }

func (nopConn) Close() error { return nil }

// One source holds at most 4 connections not yet through their handshake
// and a Device's in all; all those not yet named hold at most a quarter of
// the replica's (review b6b N1, R1).
func TestLimitsUnidentifiedConnections(t *testing.T) {
	t.Parallel()
	limits := DefaultLimits()
	limits.SourceHandshakes, limits.Connections = 1000, 40
	g := newGate(limits)
	one := netip.MustParseAddr("100.64.1.9")
	for range sourceUnidentified {
		if limit := g.accept(one); limit != "" {
			t.Fatal(limit)
		}
	}
	if limit := g.accept(one); limit != limitSourceUnnamed {
		t.Fatalf("a 5th unnamed from one source: %q", limit)
	}
	// Named, they make room for more, up to a Device's connections.
	for index := range sourceUnidentified {
		if !g.joinDevice("device-"+string(rune('a'+index)), one) {
			t.Fatal("not named")
		}
	}
	for range limits.DeviceConnections - sourceUnidentified {
		if limit := g.accept(one); limit != "" {
			t.Fatal(limit)
		}
		g.mu.Lock()
		g.named(one)
		g.mu.Unlock()
	}
	if limit := g.accept(one); limit != limitSourceConnections {
		t.Fatalf("a 17th from one source: %q", limit)
	}
	// Other sources fill the unnamed quarter (10).
	for index := range 10 {
		source := netip.AddrFrom4([4]byte{100, 64, 2, byte(index / 4)})
		if limit := g.accept(source); limit != "" && index < 10 {
			t.Fatalf("unnamed %d: %q", index, limit)
		}
	}
	if limit := g.accept(netip.MustParseAddr("100.64.3.1")); limit != limitUnidentified {
		t.Fatalf("past the unnamed share: %q", limit)
	}
	for range limits.DeviceConnections {
		g.release(one, false)
	}
	for index := range 10 {
		g.release(netip.AddrFrom4([4]byte{100, 64, 2, byte(index / 4)}), true)
	}
	if g.open != 0 || g.unidentified != 0 || len(g.sources) != 0 || len(g.pending) != 0 {
		t.Fatalf("open %d, unidentified %d, sources %v, pending %v", g.open, g.unidentified, g.sources, g.pending)
	}
}

// A write honours a sooner deadline set on the connection, such as TLS's
// for its close alert (review b6b N2).
func TestIdentifiedWriteHonoursASoonerDeadline(t *testing.T) {
	t.Parallel()
	near, far := net.Pipe()
	defer func() { _ = far.Close() }()
	conn := &identified{Conn: near, writeTimeout: time.Minute}
	defer func() { _ = conn.Close() }()
	_ = conn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	started := time.Now()
	if _, err := conn.Write([]byte("alert")); err == nil {
		t.Fatal("a write no one reads went through")
	}
	if took := time.Since(started); took > time.Second {
		t.Fatalf("took %s", took)
	}
}
