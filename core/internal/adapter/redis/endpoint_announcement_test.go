package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/control/mapsession"
)

func TestEndpointAnnouncementMapping(t *testing.T) {
	t.Parallel()
	interval := 5 * time.Second
	for _, test := range []struct {
		status, retry int64
		want          mapsession.EndpointAnnouncement
		valid         bool
	}{
		{status: endpointsStale, valid: true},
		{status: endpointsAnnounced, valid: true},
		{status: endpointsUnchanged, valid: true},
		{status: endpointsPending, retry: 3200, valid: true,
			want: mapsession.EndpointAnnouncement{Deferred: true, RetryAfter: 3200 * time.Millisecond}},
		{status: endpointsPending, retry: 0},
		{status: endpointsPending, retry: 5001},
		{status: endpointsAnnounced, retry: 10},
		{status: -1},
		{status: 4},
	} {
		got, _, valid := endpointAnnouncement(test.status, test.retry, interval)
		if valid != test.valid || got != test.want {
			t.Errorf("status %d retry %d: %+v, %t", test.status, test.retry, got, valid)
		}
	}
}

func TestObserveEndpointsRefusesAnIntervalPastTheTTL(t *testing.T) {
	t.Parallel()
	client := &Client{observeEndpoints: func(context.Context, endpointObservation) (int64, int64, error) {
		t.Fatal("called with an interval the endpoints would outlive")
		return 0, 0, nil
	}}
	observation := testEndpointObservation(t, 7) // a 30 s TTL
	for _, interval := range []time.Duration{0, 30 * time.Second, time.Minute} {
		if _, _, err := client.ObserveEndpoints(t.Context(), testNetworkScope(t), observation, interval); !errors.Is(
			err, ErrInvalidOptions) {
			t.Errorf("interval %s: %v", interval, err)
		}
	}
}

func TestObserveEndpointsReportsDeferral(t *testing.T) {
	t.Parallel()
	client := &Client{observeEndpoints: func(context.Context, endpointObservation) (int64, int64, error) {
		return endpointsPending, 1500, nil
	}}
	accepted, announcement, err := client.ObserveEndpoints(t.Context(), testNetworkScope(t),
		testEndpointObservation(t, 7), 5*time.Second)
	if err != nil || !accepted || !announcement.Deferred || announcement.RetryAfter != 1500*time.Millisecond {
		t.Fatalf("ObserveEndpoints() = (%t, %+v, %v)", accepted, announcement, err)
	}
}

func TestFlushEndpoints(t *testing.T) {
	t.Parallel()
	observation := testEndpointObservation(t, 7)
	scope := testNetworkScope(t)
	for _, test := range []struct {
		status, retry int64
		err           error
		want          mapsession.EndpointAnnouncement
		wantErr       error
	}{
		{status: endpointsAnnounced},
		{status: endpointsUnchanged},
		{status: endpointsPending, retry: 800, want: mapsession.EndpointAnnouncement{Deferred: true,
			RetryAfter: 800 * time.Millisecond}},
		// The flush script never answers a stale generation.
		{status: endpointsStale, wantErr: ErrObserveEndpoints},
		{status: -1, wantErr: ErrObserveEndpoints},
		{err: errors.New("redis down"), wantErr: ErrObserveEndpoints},
	} {
		var gotKey string
		var gotGeneration int64
		var gotWakeup []byte
		client := &Client{flushEndpoints: func(_ context.Context, key string, generation int64, channel string,
			wakeup []byte, interval time.Duration) (int64, int64, error) {
			gotKey, gotGeneration, gotWakeup = key, generation, append([]byte(nil), wakeup...)
			if channel != connectivityChangedChannel || interval != 5*time.Second {
				t.Errorf("channel %q interval %s", channel, interval)
			}
			return test.status, test.retry, test.err
		}}
		got, err := client.FlushEndpoints(t.Context(), scope, observation.NodeID(), 7, 5*time.Second)
		if (test.wantErr == nil) != (err == nil) || (test.wantErr != nil && !errors.Is(err, test.wantErr)) ||
			got != test.want {
			t.Errorf("status %d: (%+v, %v)", test.status, got, err)
			continue
		}
		if gotKey != endpointKey(observation.NodeID()) || gotGeneration != 7 {
			t.Errorf("flushed %q generation %d", gotKey, gotGeneration)
		}
		change, err := decodeConnectivityWakeup(gotWakeup)
		if err != nil || change.Key().NodeID() != observation.NodeID() || change.Key().Generation() != 7 ||
			change.Kind() != mapsession.ConnectivityChangeEndpoints {
			t.Errorf("flush wakeup = %+v, %v", change, err)
		}
	}
}
