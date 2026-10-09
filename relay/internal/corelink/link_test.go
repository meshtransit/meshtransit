package corelink

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

var t0 = time.UnixMilli(1760000000000)

func signer(t *testing.T, b byte) key.SigningPrivate {
	t.Helper()
	k, err := key.SigningPrivateFromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fakeCore serves whatever signed state the test sets.
type fakeCore struct {
	mu       sync.Mutex
	doc      []byte
	etag     string
	requests atomic.Int64
}

func (c *fakeCore) set(t *testing.T, s mtrp.RelayState, by key.SigningPrivate, etag string) {
	t.Helper()
	payload, err := s.Payload()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := mtrp.SignDocument(mtrp.DocumentRelayState, payload, by)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.doc, c.etag = doc, etag
	c.mu.Unlock()
}

func (c *fakeCore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.requests.Add(1)
	if r.URL.Path != statePath {
		http.NotFound(w, r)
		return
	}
	c.mu.Lock()
	doc, etag := c.doc, c.etag
	c.mu.Unlock()
	if etag != "" && r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	_, _ = w.Write(doc)
}

func state(seq int64, keys ...mtrp.TrustedKey) mtrp.RelayState {
	return mtrp.RelayState{Sequence: seq, IssuedAt: t0, ExpiresAt: t0.Add(10 * time.Minute), SigningKeys: keys}
}

func newLink(t *testing.T, core http.Handler, now *atomic.Int64, boot key.SigningPublic, self key.RelayPublic, drained *atomic.Int32) *Link {
	t.Helper()
	srv := httptest.NewTLSServer(core)
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	l, err := New(Config{
		CoreURL: srv.URL, Bootstrap: []key.SigningPublic{boot}, Self: self, Client: client,
		Now:     func() time.Time { return time.UnixMilli(now.Load()) },
		OnDrain: func() { drained.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLinkAppliesRotatesAndRevokes(t *testing.T) {
	t.Parallel()
	a, b := signer(t, 1), signer(t, 2)
	var now atomic.Int64
	now.Store(t0.UnixMilli())
	var drained atomic.Int32
	core := &fakeCore{}
	self := key.RelayPublic{0x5e}
	l := newLink(t, core, &now, a.Public(), self, &drained)

	// State 1, signed by the bootstrap key, introduces key b and revokes a node.
	node := key.NodePublic{0x77}
	s1 := state(1, mtrp.TrustedKey{Key: a.Public(), NotAfter: t0.Add(time.Hour)}, mtrp.TrustedKey{Key: b.Public(), NotAfter: t0.Add(24 * time.Hour)})
	s1.Nodes = []mtrp.RevocationID{mtrp.RevocationHash(mtrp.RevokeNode, node[:])}
	contract := mtrp.Zone{Kind: mtrp.ZoneTrustContract, ID: [16]byte{0x0c}}
	s1.Zones = []mtrp.RevocationID{mtrp.ZoneRevocationHash(contract)}
	core.set(t, s1, a, `"1"`)
	if err := l.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !l.Revoked(mtrp.Ticket{Node: node}) || l.Generation() != 1 {
		t.Fatal("revocation not applied")
	}
	if !l.ZoneRevoked(contract) || l.ZoneRevoked(mtrp.Zone{Kind: mtrp.ZoneNetwork, ID: [16]byte{1}}) {
		t.Fatal("zone withdrawal not applied")
	}
	if _, ok := l.SigningKey(b.Public().ID()); !ok {
		t.Fatal("rotated-in key not trusted")
	}

	// Unchanged state: 304, nothing changes.
	if err := l.Poll(t.Context()); err != nil || l.Generation() != 1 {
		t.Fatalf("304 poll: %v, generation %d", err, l.Generation())
	}

	// State 2, signed by the new key, drops a and drains this relay.
	s2 := state(2, mtrp.TrustedKey{Key: b.Public(), NotAfter: t0.Add(24 * time.Hour)})
	s2.Drain = []key.RelayPublic{self}
	core.set(t, s2, b, `"2"`)
	if err := l.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := l.SigningKey(a.Public().ID()); ok {
		t.Fatal("retired key still trusted")
	}
	if l.Revoked(mtrp.Ticket{Node: node}) || drained.Load() != 1 {
		t.Fatalf("state 2 not applied: revoked=%v drained=%d", l.Revoked(mtrp.Ticket{Node: node}), drained.Load())
	}

	// A state signed by the retired key is rejected; so is an older one.
	core.set(t, state(3, mtrp.TrustedKey{Key: a.Public(), NotAfter: t0.Add(time.Hour)}), a, `"3"`)
	if err := l.Poll(t.Context()); err == nil {
		t.Fatal("state signed by a retired key accepted")
	}
	// A state that is not newer (a lagging Core replica) is ignored without error.
	core.set(t, state(2, mtrp.TrustedKey{Key: b.Public(), NotAfter: t0.Add(time.Hour)}), b, `"2b"`)
	generation := l.Generation()
	if err := l.Poll(t.Context()); err != nil || l.Generation() != generation || l.etag != `"2"` {
		t.Fatalf("replayed sequence: err %v, generation %d -> %d, etag %s", err, generation, l.Generation(), l.etag)
	}
	if drained.Load() != 1 {
		t.Fatal("drain fired twice")
	}

	// When every trusted key passes not_after without an update, trust fails closed.
	now.Store(t0.Add(25 * time.Hour).UnixMilli())
	l.refreshKeys()
	if _, ok := l.SigningKey(b.Public().ID()); ok {
		t.Fatal("expired key still trusted")
	}
}

func TestLinkRejectsExpiredAndForeign(t *testing.T) {
	t.Parallel()
	a := signer(t, 1)
	var now atomic.Int64
	now.Store(t0.Add(11 * time.Minute).UnixMilli())
	var drained atomic.Int32
	core := &fakeCore{}
	l := newLink(t, core, &now, a.Public(), key.RelayPublic{1}, &drained)
	core.set(t, state(1, mtrp.TrustedKey{Key: a.Public(), NotAfter: t0.Add(time.Hour)}), a, "")
	if err := l.Poll(t.Context()); err == nil {
		t.Fatal("expired state accepted")
	}
	stranger := signer(t, 9)
	now.Store(t0.UnixMilli())
	core.set(t, state(1, mtrp.TrustedKey{Key: stranger.Public(), NotAfter: t0.Add(time.Hour)}), stranger, "")
	if err := l.Poll(t.Context()); err == nil {
		t.Fatal("state signed by an untrusted key accepted")
	}
	if _, ok := l.SigningKey(a.Public().ID()); !ok {
		t.Fatal("bootstrap trust lost after rejected states")
	}
}

func TestLinkDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/state", http.StatusFound)
	})
	var now atomic.Int64
	now.Store(t0.UnixMilli())
	var drained atomic.Int32
	l := newLink(t, redirect, &now, signer(t, 1).Public(), key.RelayPublic{1}, &drained)
	if err := l.Poll(t.Context()); err == nil {
		t.Fatal("redirect followed")
	}
}

func TestNewValidates(t *testing.T) {
	t.Parallel()
	boot := []key.SigningPublic{signer(t, 1).Public()}
	for _, u := range []string{"http://core.example", "https://user:pw@core.example", "https://core.example?x=1", "core.example"} {
		if _, err := New(Config{CoreURL: u, Bootstrap: boot}); err == nil {
			t.Errorf("accepted %q", u)
		}
	}
	if _, err := New(Config{CoreURL: "https://core.example"}); err == nil {
		t.Fatal("accepted no bootstrap key")
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	t.Parallel()
	a := signer(t, 1)
	var now atomic.Int64
	now.Store(t0.UnixMilli())
	var drained atomic.Int32
	core := &fakeCore{}
	core.set(t, state(1, mtrp.TrustedKey{Key: a.Public(), NotAfter: t0.Add(time.Hour)}), a, `"1"`)
	l := newLink(t, core, &now, a.Public(), key.RelayPublic{1}, &drained)
	l.cfg.Interval = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for core.requests.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if core.requests.Load() < 3 || l.Generation() != 1 {
		t.Fatalf("requests %d generation %d", core.requests.Load(), l.Generation())
	}
}
