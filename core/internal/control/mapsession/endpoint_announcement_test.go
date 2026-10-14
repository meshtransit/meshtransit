package mapsession

import (
	"errors"
	"testing"
	"time"
)

func TestServiceOptionsBoundTheAnnounceInterval(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		ttl, interval time.Duration
		valid         bool
	}{
		{ttl: 30 * time.Second, interval: 0, valid: true}, // the 5 s default
		{ttl: 30 * time.Second, interval: time.Second, valid: true},
		{ttl: 30 * time.Second, interval: 29 * time.Second, valid: true},
		{ttl: 30 * time.Second, interval: 999 * time.Millisecond},
		{ttl: 60 * time.Second, interval: 31 * time.Second},
		// A deferred change must be announced before the endpoints expire.
		{ttl: 30 * time.Second, interval: 30 * time.Second},
		{ttl: 3 * time.Second, interval: 0},
		{ttl: 3 * time.Second, interval: 2 * time.Second, valid: true},
	} {
		options := ServiceOptions{EndpointTTL: test.ttl, EndpointTimeout: time.Millisecond,
			EndpointAnnounceInterval: test.interval}
		if options.isValid() != test.valid {
			t.Errorf("TTL %s, interval %s: valid = %t", test.ttl, test.interval, !test.valid)
		}
	}
}

func TestObserveSessionEndpointsReturnsTheAnnouncement(t *testing.T) {
	t.Parallel()
	snapshot := snapshotFixture(t)
	_, request := authenticatedRequestFixture(t, snapshot)
	set, _ := withEndpointSetFixture(t, request).EndpointSet()
	deferred := EndpointAnnouncement{Deferred: true, RetryAfter: 4 * time.Second}
	observer := &recordingEndpointObserver{accepted: true, announcement: deferred}
	service := newServiceFixture(t, &recordingSnapshotStore{snapshot: snapshot}, observer)

	got, err := service.ObserveSessionEndpoints(t.Context(), snapshot, set, 0, false)
	if err != nil || got != deferred || observer.interval != DefaultEndpointAnnounceInterval {
		t.Fatalf("ObserveSessionEndpoints() = %+v, %v (interval %s)", got, err, observer.interval)
	}
	// A store answer that does not fit the interval is refused.
	for _, invalid := range []EndpointAnnouncement{
		{Deferred: true},
		{Deferred: true, RetryAfter: maximumEndpointAnnounceInterval + time.Millisecond},
		{RetryAfter: time.Second},
	} {
		observer.announcement = invalid
		if _, err := service.ObserveSessionEndpoints(t.Context(), snapshot, set, 0, false); !errors.Is(err,
			errEndpointAnnouncement) {
			t.Errorf("%+v: error = %v", invalid, err)
		}
	}
}

func TestFlushSessionEndpointsFlushesTheSessionsDevice(t *testing.T) {
	t.Parallel()
	snapshot := snapshotFixture(t)
	observer := &recordingEndpointObserver{flushResult: EndpointAnnouncement{Deferred: true, RetryAfter: time.Second}}
	service := newServiceFixture(t, &recordingSnapshotStore{snapshot: snapshot}, observer)

	got, err := service.FlushSessionEndpoints(t.Context(), snapshot)
	if err != nil || got != observer.flushResult || len(observer.flushes) != 1 ||
		observer.flushes[0].NodeID() != snapshot.NodeID() ||
		observer.flushes[0].Generation() != snapshot.SessionGeneration() ||
		observer.interval != DefaultEndpointAnnounceInterval {
		t.Fatalf("FlushSessionEndpoints() = %+v, %v; flushes %+v", got, err, observer.flushes)
	}
	observer.err = errors.New("redis down")
	if _, err := service.FlushSessionEndpoints(t.Context(), snapshot); !errors.Is(err, ErrEndpointFlush) ||
		errors.Is(err, ErrOpen) {
		t.Fatalf("store failure: %v", err)
	}
	// An announcement outside the contract is refused.
	observer.err = nil
	observer.flushResult = EndpointAnnouncement{Deferred: true, RetryAfter: time.Hour}
	if _, err := service.FlushSessionEndpoints(t.Context(), snapshot); !errors.Is(err, errEndpointAnnouncement) {
		t.Fatalf("invalid announcement: %v", err)
	}
}
