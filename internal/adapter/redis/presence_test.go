package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/node"
)

func TestClientClaimsAndReleasesExactPresenceLease(t *testing.T) {
	t.Parallel()

	lease := testPresenceLease(t, 7, "control-a")
	ctx := t.Context()
	var claimKey, releaseKey, claimEndpointKey, releaseEndpointKey string
	var claimGeneration, releaseGeneration int64
	var claimReplica, releaseReplica string
	var claimTTL time.Duration
	client := &Client{
		claimPresence: func(
			gotContext context.Context,
			key string,
			gotEndpointKey string,
			generation int64,
			replicaID string,
			ttl time.Duration,
		) (int64, error) {
			if gotContext != ctx {
				t.Fatal("ClaimPresence() did not propagate context")
			}
			claimKey, claimEndpointKey = key, gotEndpointKey
			claimGeneration, claimReplica, claimTTL = generation, replicaID, ttl
			return 1, nil
		},
		releasePresence: func(
			gotContext context.Context,
			key string,
			gotEndpointKey string,
			generation int64,
			replicaID string,
		) (int64, error) {
			if gotContext != ctx {
				t.Fatal("ReleasePresence() did not propagate context")
			}
			releaseKey, releaseEndpointKey = key, gotEndpointKey
			releaseGeneration, releaseReplica = generation, replicaID
			return 1, nil
		},
	}
	claimed, err := client.ClaimPresence(ctx, lease)
	if err != nil || !claimed {
		t.Fatalf("ClaimPresence() = (%t, %v), want true", claimed, err)
	}
	released, err := client.ReleasePresence(ctx, lease)
	if err != nil || !released {
		t.Fatalf("ReleasePresence() = (%t, %v), want true", released, err)
	}
	wantKey := presenceKeyPrefix + lease.NodeID().String()
	wantEndpointKey := endpointKeyPrefix + lease.NodeID().String()
	if claimKey != wantKey || releaseKey != wantKey ||
		claimEndpointKey != wantEndpointKey || releaseEndpointKey != wantEndpointKey ||
		claimGeneration != 7 || releaseGeneration != 7 ||
		claimReplica != "control-a" || releaseReplica != "control-a" ||
		claimTTL != 30*time.Second {
		t.Fatalf(
			"presence arguments = claim(%q,%d,%q,%s) release(%q,%d,%q)",
			claimKey,
			claimGeneration,
			claimReplica,
			claimTTL,
			releaseKey,
			releaseGeneration,
			releaseReplica,
		)
	}
}

func TestClientTreatsPresenceFenceRejectionAsSuccessfulResult(t *testing.T) {
	t.Parallel()

	client := &Client{
		claimPresence: func(context.Context, string, string, int64, string, time.Duration) (int64, error) {
			return 0, nil
		},
		releasePresence: func(context.Context, string, string, int64, string) (int64, error) {
			return 0, nil
		},
	}
	lease := testPresenceLease(t, 7, "control-a")
	if claimed, err := client.ClaimPresence(t.Context(), lease); err != nil || claimed {
		t.Fatalf("ClaimPresence() = (%t, %v), want clean rejection", claimed, err)
	}
	if released, err := client.ReleasePresence(t.Context(), lease); err != nil || released {
		t.Fatalf("ReleasePresence() = (%t, %v), want clean rejection", released, err)
	}
}

func TestClientRejectsMalformedPresenceResultsAndTransportErrors(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("redis unavailable")
	lease := testPresenceLease(t, 7, "control-a")
	tests := []struct {
		name   string
		result int64
		err    error
		want   error
	}{
		{name: "malformed", result: -1, want: ErrClaimPresence},
		{name: "transport", err: wantErr, want: wantErr},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &Client{claimPresence: func(
				context.Context,
				string,
				string,
				int64,
				string,
				time.Duration,
			) (int64, error) {
				return test.result, test.err
			}}
			if _, err := client.ClaimPresence(t.Context(), lease); !errors.Is(err, test.want) {
				t.Fatalf("ClaimPresence() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestClientRejectsInvalidPresenceLeaseBeforeRedis(t *testing.T) {
	t.Parallel()

	calls := 0
	client := &Client{claimPresence: func(
		context.Context,
		string,
		string,
		int64,
		string,
		time.Duration,
	) (int64, error) {
		calls++
		return 1, nil
	}}
	if _, err := client.ClaimPresence(t.Context(), node.PresenceLease{}); !errors.Is(
		err,
		ErrInvalidOptions,
	) {
		t.Fatalf("ClaimPresence() error = %v, want invalid options", err)
	}
	if calls != 0 {
		t.Fatalf("Redis calls = %d, want 0", calls)
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
