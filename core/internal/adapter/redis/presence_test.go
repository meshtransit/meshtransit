package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
)

func TestClientAcquiresAndRenewsExactPresenceLease(t *testing.T) {
	t.Parallel()

	lease := testPresenceLease(t, 7, "control-a")
	ctx := t.Context()
	var acquireKey, renewKey, releaseKey string
	var acquireEndpointKey, renewEndpointKey, releaseEndpointKey string
	var acquireGeneration, renewGeneration, releaseGeneration int64
	var acquireReplica, renewReplica, releaseReplica string
	var acquireTTL, renewTTL time.Duration
	var acquireChannel, releaseChannel string
	var acquireWakeup, releaseWakeup []byte
	client := &Client{
		acquirePresence: func(
			gotContext context.Context,
			key string,
			gotEndpointKey string,
			generation int64,
			replicaID string,
			ttl time.Duration,
			channel string,
			wakeup []byte,
		) (int64, int64, error) {
			if gotContext != ctx {
				t.Fatal("AcquirePresence() did not propagate context")
			}
			acquireKey, acquireEndpointKey = key, gotEndpointKey
			acquireGeneration, acquireReplica, acquireTTL = generation, replicaID, ttl
			acquireChannel, acquireWakeup = channel, append([]byte(nil), wakeup...)
			return 1, 0, nil
		},
		renewPresence: func(
			gotContext context.Context,
			key string,
			gotEndpointKey string,
			generation int64,
			replicaID string,
			ttl time.Duration,
		) (int64, error) {
			if gotContext != ctx {
				t.Fatal("RenewPresence() did not propagate context")
			}
			renewKey, renewEndpointKey = key, gotEndpointKey
			renewGeneration, renewReplica, renewTTL = generation, replicaID, ttl
			return 1, nil
		},
		releasePresence: func(
			gotContext context.Context,
			key string,
			gotEndpointKey string,
			generation int64,
			replicaID string,
			channel string,
			wakeup []byte,
		) (int64, error) {
			if gotContext != ctx {
				t.Fatal("ReleasePresence() did not propagate context")
			}
			releaseKey, releaseEndpointKey = key, gotEndpointKey
			releaseGeneration, releaseReplica = generation, replicaID
			releaseChannel, releaseWakeup = channel, append([]byte(nil), wakeup...)
			return 1, nil
		},
	}
	scope := testNetworkScope(t)
	acquired, err := client.AcquirePresence(ctx, scope, lease)
	if err != nil || !acquired {
		t.Fatalf("AcquirePresence() = (%t, %v), want true", acquired, err)
	}
	renewed, err := client.RenewPresence(ctx, lease)
	if err != nil || !renewed {
		t.Fatalf("RenewPresence() = (%t, %v), want true", renewed, err)
	}
	released, err := client.ReleasePresence(ctx, scope, lease)
	if err != nil || !released {
		t.Fatalf("ReleasePresence() = (%t, %v), want true", released, err)
	}
	wantKey := presenceKeyPrefix + lease.NodeID().String()
	wantEndpointKey := endpointKeyPrefix + lease.NodeID().String()
	if acquireKey != wantKey || renewKey != wantKey || releaseKey != wantKey ||
		acquireEndpointKey != wantEndpointKey || renewEndpointKey != wantEndpointKey ||
		releaseEndpointKey != wantEndpointKey || acquireGeneration != 7 ||
		renewGeneration != 7 || releaseGeneration != 7 ||
		acquireReplica != "control-a" || renewReplica != "control-a" ||
		releaseReplica != "control-a" ||
		acquireTTL != 30*time.Second || renewTTL != 30*time.Second ||
		acquireChannel != connectivityChangedChannel ||
		releaseChannel != connectivityChangedChannel {
		t.Fatalf(
			"presence arguments = acquire(%q,%d,%q,%s) renew(%q,%d,%q,%s) release(%q,%d,%q)",
			acquireKey,
			acquireGeneration,
			acquireReplica,
			acquireTTL,
			renewKey,
			renewGeneration,
			renewReplica,
			renewTTL,
			releaseKey,
			releaseGeneration,
			releaseReplica,
		)
	}
	for name, payload := range map[string][]byte{
		"acquire": acquireWakeup,
		"release": releaseWakeup,
	} {
		change, err := decodeConnectivityWakeup(payload)
		if err != nil || change.NetworkID() != scope.NetworkID() ||
			change.Key().NodeID() != lease.NodeID() ||
			change.Key().Generation() != lease.Generation() ||
			change.Kind() != mapsession.ConnectivityChangePresence {
			t.Fatalf("%s wakeup = (%+v, %v), want lease-bound hint", name, change, err)
		}
	}
}

func TestClientTreatsPresenceFenceRejectionAsSuccessfulResult(t *testing.T) {
	t.Parallel()

	client := &Client{
		acquirePresence: func(
			context.Context,
			string,
			string,
			int64,
			string,
			time.Duration,
			string,
			[]byte,
		) (int64, int64, error) {
			return 0, 0, nil
		},
		renewPresence: func(
			context.Context,
			string,
			string,
			int64,
			string,
			time.Duration,
		) (int64, error) {
			return 0, nil
		},
		releasePresence: func(
			context.Context,
			string,
			string,
			int64,
			string,
			string,
			[]byte,
		) (int64, error) {
			return 0, nil
		},
	}
	lease := testPresenceLease(t, 7, "control-a")
	if acquired, err := client.AcquirePresence(
		t.Context(),
		testNetworkScope(t),
		lease,
	); err != nil || acquired {
		t.Fatalf("AcquirePresence() = (%t, %v), want clean rejection", acquired, err)
	}
	if renewed, err := client.RenewPresence(t.Context(), lease); err != nil || renewed {
		t.Fatalf("RenewPresence() = (%t, %v), want clean rejection", renewed, err)
	}
	if released, err := client.ReleasePresence(
		t.Context(),
		testNetworkScope(t),
		lease,
	); err != nil || released {
		t.Fatalf("ReleasePresence() = (%t, %v), want clean rejection", released, err)
	}
}

func TestClientRejectsMalformedPresenceResultsAndTransportErrors(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("redis unavailable")
	lease := testPresenceLease(t, 7, "control-a")
	tests := []struct {
		name    string
		result  int64
		err     error
		want    error
		renew   bool
		release bool
	}{
		{name: "malformed acquire", result: -1, want: ErrAcquirePresence},
		{name: "acquire transport", err: wantErr, want: wantErr},
		{name: "malformed renew", result: -1, want: ErrRenewPresence, renew: true},
		{name: "renew transport", err: wantErr, want: wantErr, renew: true},
		{name: "malformed release", result: -1, want: ErrReleasePresence, release: true},
		{name: "release transport", err: wantErr, want: wantErr, release: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &Client{
				acquirePresence: func(
					context.Context,
					string,
					string,
					int64,
					string,
					time.Duration,
					string,
					[]byte,
				) (int64, int64, error) {
					return test.result, 0, test.err
				},
				renewPresence: func(
					context.Context,
					string,
					string,
					int64,
					string,
					time.Duration,
				) (int64, error) {
					return test.result, test.err
				},
				releasePresence: func(
					context.Context,
					string,
					string,
					int64,
					string,
					string,
					[]byte,
				) (int64, error) {
					return test.result, test.err
				},
			}
			var err error
			if test.release {
				_, err = client.ReleasePresence(t.Context(), testNetworkScope(t), lease)
			} else if test.renew {
				_, err = client.RenewPresence(t.Context(), lease)
			} else {
				_, err = client.AcquirePresence(t.Context(), testNetworkScope(t), lease)
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("presence operation error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestClientRejectsInvalidPresenceLeaseBeforeRedis(t *testing.T) {
	t.Parallel()

	acquires, renews, releases := 0, 0, 0
	client := &Client{
		acquirePresence: func(
			context.Context,
			string,
			string,
			int64,
			string,
			time.Duration,
			string,
			[]byte,
		) (int64, int64, error) {
			acquires++
			return 1, 0, nil
		},
		renewPresence: func(
			context.Context,
			string,
			string,
			int64,
			string,
			time.Duration,
		) (int64, error) {
			renews++
			return 1, nil
		},
		releasePresence: func(
			context.Context,
			string,
			string,
			int64,
			string,
			string,
			[]byte,
		) (int64, error) {
			releases++
			return 1, nil
		},
	}
	if _, err := client.AcquirePresence(
		t.Context(),
		testNetworkScope(t),
		node.PresenceLease{},
	); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("AcquirePresence() error = %v, want invalid options", err)
	}
	if _, err := client.RenewPresence(
		t.Context(),
		node.PresenceLease{},
	); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("RenewPresence() error = %v, want invalid options", err)
	}
	if _, err := client.ReleasePresence(
		t.Context(),
		testNetworkScope(t),
		node.PresenceLease{},
	); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("ReleasePresence() error = %v, want invalid options", err)
	}
	if acquires != 0 || renews != 0 || releases != 0 {
		t.Fatalf("Redis calls = (%d,%d,%d), want (0,0,0)", acquires, renews, releases)
	}
}

func testPresenceLease(t *testing.T, generation int64, replicaID string) node.PresenceLease {
	t.Helper()
	var value [16]byte
	value[0] = 1
	value[6] = 0x70
	value[8] = 0x80
	nodeID, err := node.NewID(value)
	if err != nil {
		t.Fatalf("node.NewID() error = %v", err)
	}
	lease, err := node.NewPresenceLease(nodeID, generation, replicaID, 30*time.Second)
	if err != nil {
		t.Fatalf("node.NewPresenceLease() error = %v", err)
	}
	return lease
}

func TestClientReportsPresenceChurn(t *testing.T) {
	t.Parallel()
	lease := testPresenceLease(t, 7, "control-a")
	for name, test := range map[string]struct {
		status, retryMS int64
		churn           bool
	}{
		"churn":                 {status: 2, retryMS: 12_000, churn: true},
		"churn without a wait":  {status: 2, retryMS: 0},
		"churn past the window": {status: 2, retryMS: presenceTransferWindow.Milliseconds() + 1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client := &Client{acquirePresence: func(context.Context, string, string, int64, string, time.Duration,
				string, []byte) (int64, int64, error) {
				return test.status, test.retryMS, nil
			}}
			acquired, err := client.AcquirePresence(t.Context(), testNetworkScope(t), lease)
			var churn *mapsession.PresenceChurnError
			switch {
			case acquired:
				t.Fatal("a refused move acquired the lease")
			case test.churn && (!errors.As(err, &churn) || churn.RetryAfter != 12*time.Second):
				t.Fatalf("AcquirePresence() error = %v, want a 12 s churn refusal", err)
			case !test.churn && !errors.Is(err, ErrAcquirePresence):
				t.Fatalf("AcquirePresence() error = %v, want ErrAcquirePresence", err)
			}
		})
	}
}
