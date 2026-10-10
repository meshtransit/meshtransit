package corelink

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// grantCore serves a relay state and a sealed grant for one relay.
type grantCore struct {
	fakeCore
	gmu    sync.Mutex
	sealed []byte
	asked  atomic.Value // the relay query parameter
}

func (c *grantCore) setGrant(t *testing.T, grant mtrp.RelayGrant, by key.SigningPrivate, to key.RelayPublic) {
	t.Helper()
	payload, err := grant.Payload()
	if err != nil {
		t.Fatal(err)
	}
	doc, err := mtrp.SignDocument(mtrp.DocumentRelayGrant, payload, by)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := mtrp.SealRelayGrant(doc, to, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.gmu.Lock()
	c.sealed = sealed
	c.gmu.Unlock()
}

func (c *grantCore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == grantPath {
		c.asked.Store(r.URL.Query().Get("relay"))
		c.gmu.Lock()
		sealed := c.sealed
		c.gmu.Unlock()
		if sealed == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(sealed)
		return
	}
	c.fakeCore.ServeHTTP(w, r)
}

func TestPrivateInterchangeAdmitsOnlyGrantedNetworks(t *testing.T) {
	t.Parallel()
	signing := signer(t, 1)
	relay, err := key.NewRelayPrivate()
	if err != nil {
		t.Fatal(err)
	}
	var now atomic.Int64
	now.Store(t0.UnixMilli())
	core := &grantCore{}
	core.set(t, state(1, mtrp.TrustedKey{Key: signing.Public(), NotAfter: t0.Add(time.Hour)}), signing, `"1"`)
	srv := httptest.NewTLSServer(core)
	t.Cleanup(srv.Close)
	link, err := New(Config{
		CoreURL: srv.URL, Bootstrap: []key.SigningPublic{signing.Public()},
		Self: relay.Public(), Client: srv.Client(), Now: func() time.Time { return time.UnixMilli(now.Load()) },
		Private: true, Key: relay,
	})
	if err != nil {
		t.Fatal(err)
	}
	granted := mtrp.Zone{Kind: mtrp.ZoneNetwork, ID: [16]byte{0x01, 0x89}}
	other := mtrp.Zone{Kind: mtrp.ZoneNetwork, ID: [16]byte{0x02}}
	contract := mtrp.Zone{Kind: mtrp.ZoneTrustContract, ID: [16]byte{0x01, 0x89}}

	if err := link.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Without a grant nothing is admitted (fail closed).
	if !link.ZoneRevoked(granted) {
		t.Fatal("a zone was admitted before any grant")
	}
	if err := link.PollGrant(t.Context()); err == nil {
		t.Fatal("a missing grant was not reported")
	}

	generation := link.Generation()
	core.setGrant(t, mtrp.RelayGrant{
		Relay: relay.Public(), Sequence: 5, IssuedAt: t0, ExpiresAt: t0.Add(10 * time.Minute),
		Networks: [][16]byte{granted.ID},
	}, signing, relay.Public())
	if err := link.PollGrant(t.Context()); err != nil {
		t.Fatal(err)
	}
	if asked, _ := core.asked.Load().(string); asked != relay.Public().String() {
		t.Fatalf("asked for %q", asked)
	}
	if link.ZoneRevoked(granted) || !link.ZoneRevoked(other) || !link.ZoneRevoked(contract) {
		t.Fatal("the grant is not enforced")
	}
	if link.Generation() == generation {
		t.Fatal("a new grant did not make the relay rescan its sessions")
	}
	if !mtrp.IsRevoked(mtrp.Ticket{Zones: []mtrp.Zone{other}}, link) ||
		mtrp.IsRevoked(mtrp.Ticket{Zones: []mtrp.Zone{granted, other}}, link) {
		t.Fatal("tickets are not judged by the grant")
	}

	// An older grant, or one sealed to another relay, changes nothing.
	core.setGrant(t, mtrp.RelayGrant{Relay: relay.Public(), Sequence: 4, IssuedAt: t0, ExpiresAt: t0.Add(10 * time.Minute)},
		signing, relay.Public())
	if err := link.PollGrant(t.Context()); err != nil || link.ZoneRevoked(granted) {
		t.Fatalf("an older grant replaced the current one: %v", err)
	}
	stranger, _ := key.NewRelayPrivate()
	core.setGrant(t, mtrp.RelayGrant{Relay: relay.Public(), Sequence: 9, IssuedAt: t0, ExpiresAt: t0.Add(10 * time.Minute)},
		signing, stranger.Public())
	if err := link.PollGrant(t.Context()); err == nil || link.ZoneRevoked(granted) {
		t.Fatal("a grant sealed to another relay was applied")
	}
	// A grant signed by an untrusted key is refused.
	core.setGrant(t, mtrp.RelayGrant{Relay: relay.Public(), Sequence: 9, IssuedAt: t0, ExpiresAt: t0.Add(10 * time.Minute)},
		signer(t, 9), relay.Public())
	if err := link.PollGrant(t.Context()); err == nil || link.ZoneRevoked(granted) {
		t.Fatal("a grant signed by an untrusted key was applied")
	}

	// When the grant expires, nothing is admitted and the relay rescans.
	generation = link.Generation()
	now.Store(t0.Add(11 * time.Minute).UnixMilli())
	link.noteGrantExpiry()
	if !link.ZoneRevoked(granted) || link.Generation() == generation {
		t.Fatal("an expired grant still admits its Networks")
	}
}

func TestPrivateInterchangeNeedsItsKey(t *testing.T) {
	t.Parallel()
	relay, _ := key.NewRelayPrivate()
	other, _ := key.NewRelayPrivate()
	for name, cfg := range map[string]Config{
		"no key":    {CoreURL: "https://core.example", Bootstrap: []key.SigningPublic{signer(t, 1).Public()}, Self: relay.Public(), Private: true},
		"wrong key": {CoreURL: "https://core.example", Bootstrap: []key.SigningPublic{signer(t, 1).Public()}, Self: relay.Public(), Private: true, Key: other},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
