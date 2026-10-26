package redis

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	redisclient "github.com/redis/go-redis/v9"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
)

func testGatewayLease(t *testing.T) node.PresenceLease {
	t.Helper()
	holder, err := node.NewPresenceHolder()
	if err != nil {
		t.Fatal(err)
	}
	lease, err := testPresenceLease(t, 4, "control-a").WithGateway(holder, [32]byte{0xab})
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

type gatewayScriptCall struct {
	script *redisclient.Script
	keys   []string
	args   []any
}

func gatewayScriptAnswering(values []int64, err error, calls *[]gatewayScriptCall) gatewayScriptFunc {
	return func(_ context.Context, script *redisclient.Script, keys []string, args ...any) ([]int64, error) {
		*calls = append(*calls, gatewayScriptCall{script: script, keys: keys, args: args})
		return values, err
	}
}

func TestAcquireGatewayPresenceMapsTheScript(t *testing.T) {
	t.Parallel()
	lease := testGatewayLease(t)
	tests := []struct {
		name   string
		values []int64
		err    error
		want   mapsession.GatewayClaim
		churn  time.Duration
		failed bool
	}{
		{name: "claimed", values: []int64{1, 0, 0}, want: mapsession.GatewayClaim{Claimed: true}},
		{name: "fight", values: []int64{1, 0, 1}, want: mapsession.GatewayClaim{Claimed: true, Fight: true}},
		{name: "newer generation holds it", values: []int64{0, 0, 0}},
		{name: "churn", values: []int64{2, 4000, 0}, churn: 4 * time.Second},
		{name: "malformed lease", values: []int64{-1, 0, 0}, failed: true},
		{name: "short answer", values: []int64{1, 0}, failed: true},
		{name: "fight out of range", values: []int64{1, 0, 2}, failed: true},
		{name: "refused with a fight", values: []int64{0, 0, 1}, failed: true},
		{name: "churn beyond the window", values: []int64{2, presenceTransferWindow.Milliseconds() + 1, 0},
			failed: true},
		{name: "transport", err: errors.New("down"), failed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var calls []gatewayScriptCall
			client := &Client{gatewayScript: gatewayScriptAnswering(test.values, test.err, &calls)}
			claim, err := client.AcquireGatewayPresence(t.Context(), testNetworkScope(t), lease, 10*time.Minute)
			var churn *mapsession.PresenceChurnError
			switch {
			case test.failed:
				if !errors.Is(err, ErrGatewayPresence) {
					t.Fatalf("AcquireGatewayPresence() = (%+v, %v), want ErrGatewayPresence", claim, err)
				}
			case test.churn > 0:
				if !errors.As(err, &churn) || churn.RetryAfter != test.churn {
					t.Fatalf("AcquireGatewayPresence() error = %v, want churn %s", err, test.churn)
				}
			case err != nil || claim != test.want:
				t.Fatalf("AcquireGatewayPresence() = (%+v, %v), want %+v", claim, err, test.want)
			}
			if len(calls) != 1 || calls[0].script != acquireGatewayPresenceScript || len(calls[0].keys) != 3 ||
				calls[0].keys[2] != gatewayContestKeyPrefix+"ab"+strings.Repeat("00", 31) ||
				calls[0].args[7] != lease.Holder().String() || calls[0].args[8] != int64(600000) {
				t.Fatalf("script call = %+v", calls)
			}
		})
	}
}

func TestGatewayPresenceRefusesNodeLeases(t *testing.T) {
	t.Parallel()
	var calls []gatewayScriptCall
	client := &Client{gatewayScript: gatewayScriptAnswering([]int64{1}, nil, &calls)}
	nodeLease := testPresenceLease(t, 4, "control-a")
	ctx, scope := t.Context(), testNetworkScope(t)
	if _, err := client.AcquireGatewayPresence(ctx, scope, nodeLease, time.Minute); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("AcquireGatewayPresence() = %v", err)
	}
	if _, err := client.AcquireGatewayPresence(ctx, scope, testGatewayLease(t), time.Millisecond); !errors.Is(err,
		ErrInvalidOptions) {
		t.Errorf("AcquireGatewayPresence() with a tiny window = %v", err)
	}
	if _, err := client.RenewGatewayPresence(ctx, nodeLease); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("RenewGatewayPresence() = %v", err)
	}
	if _, err := client.ReleaseGatewayPresence(ctx, scope, nodeLease); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("ReleaseGatewayPresence() = %v", err)
	}
	if _, err := client.HandOffGatewayPresence(ctx, nodeLease); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("HandOffGatewayPresence() = %v", err)
	}
	if _, err := client.CheckGatewayRotation(ctx, nodeLease); !errors.Is(err, ErrInvalidOptions) {
		t.Errorf("CheckGatewayRotation() = %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("Redis was called %d times", len(calls))
	}
}

func TestGatewayPresenceFlagsMapTheScripts(t *testing.T) {
	t.Parallel()
	lease := testGatewayLease(t)
	run := func(client *Client) (bool, error) {
		return client.RenewGatewayPresence(t.Context(), lease)
	}
	release := func(client *Client) (bool, error) {
		return client.ReleaseGatewayPresence(t.Context(), testNetworkScope(t), lease)
	}
	handOff := func(client *Client) (bool, error) {
		return client.HandOffGatewayPresence(t.Context(), lease)
	}
	for name, call := range map[string]func(*Client) (bool, error){"renew": run, "release": release,
		"handoff": handOff} {
		for _, test := range []struct {
			values []int64
			err    error
			want   bool
			failed bool
		}{
			{values: []int64{1}, want: true},
			{values: []int64{0}},
			{values: []int64{2}, failed: true},
			{values: []int64{}, failed: true},
			{err: errors.New("down"), failed: true},
		} {
			var calls []gatewayScriptCall
			got, err := call(&Client{gatewayScript: gatewayScriptAnswering(test.values, test.err, &calls)})
			if test.failed != errors.Is(err, ErrGatewayPresence) || (!test.failed && got != test.want) {
				t.Errorf("%s %v: (%t, %v)", name, test.values, got, err)
			}
			if len(calls) != 1 || !containsArg(calls[0].args, lease.Holder().String()) {
				t.Errorf("%s: the holder was not sent: %+v", name, calls)
			}
		}
	}
}

func TestCheckGatewayRotationMapsTheScript(t *testing.T) {
	t.Parallel()
	lease := testGatewayLease(t)
	for _, test := range []struct {
		values []int64
		err    error
		want   mapsession.GatewayRotationState
	}{
		{values: []int64{1}, want: mapsession.GatewayRotationHeld},
		{values: []int64{2}, want: mapsession.GatewayRotationContested},
		{values: []int64{3}, want: mapsession.GatewayRotationNotHeld},
		{values: []int64{0}},
		{values: []int64{4}},
		{values: []int64{1, 1}},
		{err: errors.New("down")},
	} {
		var calls []gatewayScriptCall
		client := &Client{gatewayScript: gatewayScriptAnswering(test.values, test.err, &calls)}
		got, err := client.CheckGatewayRotation(t.Context(), lease)
		if test.want == 0 {
			if !errors.Is(err, ErrGatewayPresence) {
				t.Errorf("%v: (%v, %v), want ErrGatewayPresence", test.values, got, err)
			}
			continue
		}
		if err != nil || got != test.want {
			t.Errorf("%v: (%v, %v), want %v", test.values, got, err, test.want)
		}
		if len(calls[0].keys) != 2 || calls[0].keys[1] != gatewayContestKey(lease) {
			t.Errorf("keys = %v", calls[0].keys)
		}
	}
}

// The contest key cannot be a Node's presence key: a Node ID is a UUID.
func TestGatewayContestKeyIsNoPresenceKey(t *testing.T) {
	t.Parallel()
	lease := testGatewayLease(t)
	if key := gatewayContestKey(lease); key == presenceKey(lease) ||
		!strings.HasPrefix(key, presenceKeyPrefix+"gateway-contest:") ||
		strings.HasPrefix(presenceKeyForNode(lease.NodeID()), gatewayContestKeyPrefix) {
		t.Fatalf("contest key %q, presence key %q", key, presenceKey(lease))
	}
}

func containsArg(args []any, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}
