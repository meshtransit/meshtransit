package relayauthority

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"meshtransit.net/core/internal/platform/clientip"
	"meshtransit.net/shared/mtrp"
)

// mutableRevocations is a revocation source a test changes between checks.
type mutableRevocations struct {
	mu      sync.Mutex
	revoked Revoked
}

func (m *mutableRevocations) RelayRevocations(context.Context, time.Duration) (Revoked, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Revoked{NodeKeys: append([][32]byte(nil), m.revoked.NodeKeys...),
		TrustContracts: append([][16]byte(nil), m.revoked.TrustContracts...)}, nil
}

func (m *mutableRevocations) revokeNode(node [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked.NodeKeys = append(m.revoked.NodeKeys, node)
}

// TestPublisherSignsNewRevocationsWithinTheWindow keeps relay revocation
// within seconds: a new revocation is signed at the next one-second check,
// not at the next ten-second window, and only the state is re-signed.
func TestPublisherSignsNewRevocationsWithinTheWindow(t *testing.T) {
	t.Parallel()

	current := signer(t, 1)
	m := testMap(t)
	source := &mutableRevocations{}
	c := newClock(t0.Add(3 * time.Second))
	p := newPublisher(t, c, Options{Signer: current, Map: &m, Revocations: source})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	first, firstMap := p.state.Load(), p.relayMap.Load()

	// Nothing changed: the check keeps the document.
	c.advance(time.Second)
	if err := p.checkRevocations(t.Context()); err != nil || p.state.Load() != first {
		t.Fatalf("unchanged revocations re-signed the state: %v", err)
	}

	node := [32]byte{7}
	source.revokeNode(node)
	c.advance(1400 * time.Millisecond) // t0 + 5.4 s
	changed := p.stateChanged()
	if err := p.checkRevocations(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	default:
		t.Fatal("waiters were not woken")
	}
	state := openState(t, p.state.Load(), current.Public())
	want := t0.Add(5 * time.Second)
	if state.Sequence != want.UnixMilli() || !state.IssuedAt.Equal(want) || !state.ExpiresAt.Equal(want.Add(StateLifetime)) {
		t.Fatalf("state seq %d issued %v expires %v, want the one-second check time", state.Sequence, state.IssuedAt,
			state.ExpiresAt)
	}
	if len(state.Nodes) != 1 || state.Nodes[0] != mtrp.RevocationHash(mtrp.RevokeNode, node[:]) {
		t.Fatalf("revoked nodes = %v", state.Nodes)
	}
	if p.relayMap.Load() != firstMap {
		t.Fatal("a revocation re-signed the relay map")
	}

	// The next window still signs a newer state.
	c.advance(5 * time.Second)
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := openState(t, p.state.Load(), current.Public()).Sequence; got != t0.Add(RefreshInterval).UnixMilli() {
		t.Fatalf("window after a fast state: sequence %d", got)
	}
}

// TestHandlerLongPollsState answers a relay holding the current state when
// a new one is signed, or with 304 when its wait ends.
func TestHandlerLongPollsState(t *testing.T) {
	t.Parallel()

	source := &mutableRevocations{}
	c := newClock(t0)
	p := newPublisher(t, c, Options{Signer: signer(t, 1), Revocations: source})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(p, clientip.Resolver{})
	held := http.Header{"If-None-Match": {p.state.Load().etag}}

	start := time.Now()
	if w := serve(h, http.MethodGet, StatePath+"?wait=1", "192.0.2.1:1000", held); w.Code != http.StatusNotModified ||
		time.Since(start) < 900*time.Millisecond {
		t.Fatalf("idle long poll: %d after %v", w.Code, time.Since(start))
	}

	answered := make(chan int, 1)
	go func() {
		answered <- serve(h, http.MethodGet, StatePath+"?wait=20", "192.0.2.1:1000", held).Code
	}()
	time.Sleep(100 * time.Millisecond)
	source.revokeNode([32]byte{9})
	c.advance(2 * time.Second)
	if err := p.checkRevocations(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-answered:
		if code != http.StatusOK {
			t.Fatalf("long poll answered %d, want 200", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long poll was not woken by the new state")
	}

	for _, query := range []string{"?wait=0", "?wait=26", "?wait=x", "?wait=1&wait=2", "?other=1"} {
		if w := serve(h, http.MethodGet, StatePath+query, "192.0.2.2:1000", held); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", query, w.Code)
		}
	}
}

// TestLongPollOutlivesTheListenerWriteTimeout holds a poll on a server whose
// write timeout is shorter than the wait, as on the control listener.
func TestLongPollOutlivesTheListenerWriteTimeout(t *testing.T) {
	t.Parallel()

	p := newPublisher(t, newClock(t0), Options{Signer: signer(t, 1), Revocations: &mutableRevocations{}})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(NewHandler(p, clientip.Resolver{}))
	server.Config.WriteTimeout = 200 * time.Millisecond
	server.Start()
	defer server.Close()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+StatePath+"?wait=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("If-None-Match", p.state.Load().etag)
	start := time.Now()
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("held poll failed after %v: %v", time.Since(start), err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotModified || time.Since(start) < 900*time.Millisecond {
		t.Fatalf("held poll: %d after %v", response.StatusCode, time.Since(start))
	}
}

// One source cannot take the long-poll slots of every relay: past its own
// few held polls it is answered at once, while another source still waits.
func TestLongPollSlotsArePerSource(t *testing.T) {
	t.Parallel()

	c := newClock(t0)
	p := newPublisher(t, c, Options{Signer: signer(t, 1), Revocations: &mutableRevocations{}})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(p, clientip.Resolver{})
	held := http.Header{"If-None-Match": {p.state.Load().etag}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	for range maxStateWaitersPerSource {
		go func() {
			r := httptest.NewRequestWithContext(ctx, http.MethodGet, StatePath+"?wait=20", nil)
			r.RemoteAddr = "192.0.2.1:1000"
			r.Header = held.Clone()
			h.ServeHTTP(httptest.NewRecorder(), r)
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for h.heldBy(sourceOf(netip.MustParseAddr("192.0.2.1"))) < maxStateWaitersPerSource {
		if time.Now().After(deadline) {
			t.Fatal("polls were not held")
		}
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	if w := serve(h, http.MethodGet, StatePath+"?wait=5", "192.0.2.1:1001", held); w.Code != http.StatusNotModified ||
		time.Since(start) > time.Second {
		t.Fatalf("poll past the source's slots: %d after %v, want an immediate 304", w.Code, time.Since(start))
	}
	start = time.Now()
	if w := serve(h, http.MethodGet, StatePath+"?wait=1", "192.0.2.2:1000", held); w.Code != http.StatusNotModified ||
		time.Since(start) < 900*time.Millisecond {
		t.Fatalf("another source was not held: %d after %v", w.Code, time.Since(start))
	}
}

// TestPublisherReachesBackFromTheWindowStart checks that each read reaches
// back from the window start by this host's elapsed time: the database
// applies that duration to its own clock, so skew between the two clocks
// changes nothing.
func TestPublisherReachesBackFromTheWindowStart(t *testing.T) {
	t.Parallel()

	current := signer(t, 1)
	m := testMap(t)
	var lookback time.Duration
	c := newClock(t0.Add(3 * time.Second))
	p := newPublisher(t, c, Options{Signer: current, Map: &m, Revocations: revocations{lookback: &lookback}})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if lookback != 3*time.Second+RevocationWindow {
		t.Fatalf("refresh lookback = %v, want 3s + %v", lookback, RevocationWindow)
	}
	c.advance(2 * time.Second)
	if err := p.checkRevocations(t.Context()); err != nil {
		t.Fatal(err)
	}
	if lookback != 5*time.Second+RevocationWindow {
		t.Fatalf("check lookback = %v, want 5s + %v", lookback, RevocationWindow)
	}
}
