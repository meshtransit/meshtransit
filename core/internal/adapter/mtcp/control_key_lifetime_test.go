package mtcp

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/platform/clientip"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const testKeyLifetime = 365 * 24 * time.Hour

func keyDocumentNotAfters(t *testing.T, f *fixture) []time.Time {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.http.URL+sharedmtcp.KeyPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var document struct {
		Keys []struct {
			NotAfter time.Time `json:"not_after"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	notAfters := make([]time.Time, 0, len(document.Keys))
	for _, entry := range document.Keys {
		notAfters = append(notAfters, entry.NotAfter)
	}
	return notAfters
}

// Auto-renewal design §2: a key with a lifetime is announced as valid for
// that long from now, at every answer, so it never expires while control
// runs — even past the lifetime it started with.
func TestKeyDocumentRollsAKeyLifetime(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0).UTC()}
	f := newFixture(t, func(options *Options) {
		options.Now = clock.Now
		options.Keys = []ControlKey{{Private: options.Keys[0].Private, Lifetime: testKeyLifetime}}
	})
	if got := keyDocumentNotAfters(t, f); len(got) != 1 || !got[0].Equal(clock.Now().Add(testKeyLifetime)) {
		t.Fatalf("not_after = %v, want now + lifetime", got)
	}
	clock.advance(400 * 24 * time.Hour)
	if got := keyDocumentNotAfters(t, f); len(got) != 1 || !got[0].Equal(clock.Now().Add(testKeyLifetime)) {
		t.Fatalf("not_after after 400 days = %v, want the new now + lifetime", got)
	}
}

// A fixed expiry stays as configured; the next key may roll while the
// current one is fixed.
func TestKeyDocumentMixesFixedAndRollingKeys(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0).UTC()}
	next, err := key.NewControlPrivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	fixed := clock.Now().Add(30 * 24 * time.Hour)
	f := newFixture(t, func(options *Options) {
		options.Now = clock.Now
		options.Keys = []ControlKey{
			{Private: options.Keys[0].Private, NotAfter: fixed},
			{Private: next, Lifetime: testKeyLifetime},
		}
	})
	got := keyDocumentNotAfters(t, f)
	if len(got) != 2 || !got[0].Equal(fixed) || !got[1].Equal(clock.Now().Add(testKeyLifetime)) {
		t.Fatalf("not_after = %v", got)
	}
}

// A key has exactly one expiry: a fixed date or a lifetime.
func TestControlKeyNeedsExactlyOneExpiry(t *testing.T) {
	control, err := key.NewControlPrivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := clientip.NewResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Everything else valid, so only the key's expiry decides.
	options := func(controlKey ControlKey) Options {
		return Options{
			Keys: []ControlKey{controlKey}, ClientIPs: resolver, Handler: &recordingHandler{},
			Logger: slog.New(slog.DiscardHandler), Metrics: NewMetrics(), Capabilities: []string{"map.zstd", "disco.v2"},
		}
	}
	for _, controlKey := range []ControlKey{
		{Private: control, NotAfter: time.Now().Add(time.Hour)},
		{Private: control, Lifetime: time.Hour},
	} {
		if _, err := NewServer(options(controlKey)); err != nil {
			t.Fatalf("NewServer(%+v) error = %v, want none", controlKey, err)
		}
	}
	for _, controlKey := range []ControlKey{
		{Private: control},
		{Private: control, NotAfter: time.Now().Add(time.Hour), Lifetime: time.Hour},
		{Private: control, Lifetime: -time.Hour},
	} {
		if _, err := NewServer(options(controlKey)); !errors.Is(err, ErrInvalidServer) {
			t.Errorf("NewServer(%+v) error = %v, want ErrInvalidServer", controlKey, err)
		}
	}
}

// KeyUpdate announces the dates at the moment it is sent.
func TestKeyUpdateDatesAreTakenWhenSent(t *testing.T) {
	control, err := key.NewControlPrivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_900_000_000, 0)
	updates := controlKeyUpdates([]ControlKey{{Private: control, Lifetime: testKeyLifetime}}, now)
	if len(updates) != 1 || updates[0].GetNotAfterMs() != now.Add(testKeyLifetime).UnixMilli() {
		t.Fatalf("updates = %v", updates)
	}
}

// The expiry gauge is read at scrape time, so a rolling key never looks
// expired to monitoring.
func TestExpiryGaugeRollsWithTheKey(t *testing.T) {
	metrics := NewMetrics()
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0).UTC()}
	newFixture(t, func(options *Options) {
		options.Now = clock.Now
		options.Metrics = metrics
		options.Keys = []ControlKey{{Private: options.Keys[0].Private, Lifetime: testKeyLifetime}}
	})
	clock.advance(500 * 24 * time.Hour)
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics.Collectors()...)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "meshtransit_mtcp_control_key_not_after_timestamp_seconds" {
			if got := family.GetMetric()[0].GetGauge().GetValue(); got != float64(clock.Now().Add(testKeyLifetime).Unix()) {
				t.Fatalf("gauge = %v, want now + lifetime", got)
			}
			return
		}
	}
	t.Fatal("gauge not exported")
}
