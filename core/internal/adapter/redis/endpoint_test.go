package redis

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/workspace"
)

func TestEndpointSetPayloadRoundTrip(t *testing.T) {
	t.Parallel()

	observation := testEndpointObservation(t, 7)
	payload, err := encodeEndpointSet(observation.Set())
	if err != nil {
		t.Fatalf("encodeEndpointSet() error = %v", err)
	}
	decoded, err := decodeEndpointSet(payload)
	if err != nil {
		t.Fatalf("decodeEndpointSet() error = %v", err)
	}
	if decoded.DiscoveryKey() != observation.Set().DiscoveryKey() ||
		!slices.Equal(decoded.Endpoints(), observation.Set().Endpoints()) {
		t.Fatalf("decodeEndpointSet() = %+v, want source set", decoded)
	}
}

func TestClientObservesAndLoadsGenerationFencedEndpoints(t *testing.T) {
	t.Parallel()

	observation := testEndpointObservation(t, 7)
	ctx := t.Context()
	var observedEndpointKey, observedPresenceKey, loadedKey string
	var observedGeneration, loadedGeneration int64
	var observedPreferredRelayPresence int64
	var observedPreferredRelay int
	var observedTTL time.Duration
	var observedPayload []byte
	var observedChannel string
	var observedWakeup []byte
	var observedInterval, observedSpacing time.Duration
	var observedDisco string
	client := &Client{
		observeEndpoints: func(gotContext context.Context, call endpointObservation) (int64, int64, error) {
			if gotContext != ctx {
				t.Fatal("ObserveEndpoints() did not propagate context")
			}
			observedEndpointKey, observedPresenceKey = call.endpointKey, call.presenceKey
			observedGeneration, observedTTL = call.generation, call.ttl
			observedPreferredRelayPresence = call.preferredRelayPresent
			observedPreferredRelay = call.preferredRelay
			observedPayload = append([]byte(nil), call.payload...)
			observedChannel = call.channel
			observedWakeup = append([]byte(nil), call.wakeup...)
			observedInterval, observedDisco, observedSpacing = call.interval, call.discoveryKey, call.discoSpacing
			return 1, 0, nil
		},
		loadEndpoints: func(
			gotContext context.Context,
			key string,
			generation int64,
		) ([]byte, error) {
			if gotContext != ctx {
				t.Fatal("LoadEndpoints() did not propagate context")
			}
			loadedKey, loadedGeneration = key, generation
			return append([]byte(nil), observedPayload...), nil
		},
	}
	scope := testNetworkScope(t)
	accepted, announcement, err := client.ObserveEndpoints(ctx, scope, observation, 5*time.Second)
	if err != nil || !accepted || announcement.Deferred {
		t.Fatalf("ObserveEndpoints() = (%t, %+v, %v), want announced", accepted, announcement, err)
	}
	disco := observation.Set().DiscoveryKey().Bytes()
	if observedInterval != 5*time.Second || observedSpacing != discoAnnounceSpacing ||
		observedDisco != hex.EncodeToString(disco[:]) {
		t.Fatalf("announce arguments = %s, %s, %q", observedInterval, observedSpacing, observedDisco)
	}
	set, found, err := client.LoadEndpoints(ctx, observation.NodeID(), observation.Generation())
	if err != nil || !found {
		t.Fatalf("LoadEndpoints() = (%+v, %t, %v), want endpoint set", set, found, err)
	}
	wantEndpointKey := endpointKeyPrefix + observation.NodeID().String()
	wantPresenceKey := presenceKeyPrefix + observation.NodeID().String()
	if observedEndpointKey != wantEndpointKey || loadedKey != wantEndpointKey ||
		observedPresenceKey != wantPresenceKey || observedGeneration != 7 || loadedGeneration != 7 ||
		observedPreferredRelayPresence != 1 || observedPreferredRelay != 3 ||
		observedTTL != 30*time.Second || set.DiscoveryKey() != observation.Set().DiscoveryKey() ||
		!slices.Equal(set.Endpoints(), observation.Set().Endpoints()) ||
		observedChannel != connectivityChangedChannel {
		t.Fatalf("endpoint arguments or round trip did not preserve observation")
	}
	change, err := decodeConnectivityWakeup(observedWakeup)
	if err != nil || change.NetworkID() != scope.NetworkID() ||
		change.Key().NodeID() != observation.NodeID() ||
		change.Key().Generation() != observation.Generation() ||
		change.Kind() != mapsession.ConnectivityChangeEndpoints {
		t.Fatalf("endpoint wakeup = (%+v, %v), want observation-bound hint", change, err)
	}
}

func TestClientTreatsStaleAndMissingEndpointsAsCleanResults(t *testing.T) {
	t.Parallel()

	observation := testEndpointObservation(t, 7)
	client := &Client{
		observeEndpoints: func(context.Context, endpointObservation) (int64, int64, error) {
			return 0, 0, nil
		},
		loadEndpoints: func(context.Context, string, int64) ([]byte, error) {
			return nil, nil
		},
	}
	if accepted, _, err := client.ObserveEndpoints(
		t.Context(),
		testNetworkScope(t),
		observation,
		5*time.Second,
	); err != nil || accepted {
		t.Fatalf("ObserveEndpoints() = (%t, %v), want clean rejection", accepted, err)
	}
	if _, found, err := client.LoadEndpoints(t.Context(), observation.NodeID(), 8); err != nil || found {
		t.Fatalf("LoadEndpoints() = (_, %t, %v), want clean miss", found, err)
	}
}

func TestClientLoadsBoundedGenerationFencedConnectivity(t *testing.T) {
	t.Parallel()

	observation := testEndpointObservation(t, 7)
	first, err := mapsession.NewConnectivityKey(observation.NodeID(), 7)
	if err != nil {
		t.Fatalf("mapsession.NewConnectivityKey(first) error = %v", err)
	}
	secondNodeID, err := node.ParseID("01890f00-0000-7000-8000-000000000702")
	if err != nil {
		t.Fatalf("node.ParseID(second) error = %v", err)
	}
	second, err := mapsession.NewConnectivityKey(secondNodeID, 8)
	if err != nil {
		t.Fatalf("mapsession.NewConnectivityKey(second) error = %v", err)
	}
	payload, err := encodeEndpointSet(observation.Set())
	if err != nil {
		t.Fatalf("encodeEndpointSet() error = %v", err)
	}
	client := &Client{loadConnectivity: func(
		ctx context.Context,
		keys []string,
		generations []int64,
	) ([]any, error) {
		if ctx != t.Context() || len(keys) != 4 ||
			!slices.Equal(generations, []int64{7, 8}) ||
			keys[0] != endpointKey(first.NodeID()) || keys[1] != presenceKeyForNode(first.NodeID()) ||
			keys[2] != endpointKey(second.NodeID()) || keys[3] != presenceKeyForNode(second.NodeID()) {
			t.Fatalf("LoadConnectivity() Redis input = (%v, %v)", keys, generations)
		}
		return []any{
			string(payload), "1", "3", int64(1),
			nil, nil, nil, int64(0),
		}, nil
	}}
	values, err := client.LoadConnectivity(t.Context(), []mapsession.ConnectivityKey{first, second})
	if err != nil {
		t.Fatalf("LoadConnectivity() error = %v", err)
	}
	set, found := values[0].EndpointSet()
	preferredRelay, preferredRelayPresent := values[0].PreferredRelay()
	if len(values) != 2 || values[0].Key() != first || !values[0].Online() || !found ||
		!set.Equal(observation.Set()) || preferredRelay != 3 || !preferredRelayPresent ||
		values[1].Key() != second || values[1].Online() {
		t.Fatalf("LoadConnectivity() = %+v, want online report then clean offline miss", values)
	}
	if _, found := values[1].EndpointSet(); found {
		t.Fatal("LoadConnectivity() cache miss exposed an endpoint set")
	}
}

func TestClientChunksConnectivityProjectionLoads(t *testing.T) {
	t.Parallel()

	keys := make([]mapsession.ConnectivityKey, maximumConnectivityLoadBatch+1)
	for index := range keys {
		nodeID, err := node.ParseID(fmt.Sprintf(
			"01890f00-0000-7000-8000-%012d",
			index+1,
		))
		if err != nil {
			t.Fatalf("node.ParseID(%d) error = %v", index, err)
		}
		keys[index], err = mapsession.NewConnectivityKey(nodeID, int64(index+1))
		if err != nil {
			t.Fatalf("mapsession.NewConnectivityKey(%d) error = %v", index, err)
		}
	}
	calls := 0
	client := &Client{loadConnectivity: func(
		_ context.Context,
		redisKeys []string,
		generations []int64,
	) ([]any, error) {
		calls++
		if len(redisKeys) != len(generations)*2 || len(generations) > maximumConnectivityLoadBatch {
			t.Fatalf("connectivity batch = %d keys for %d generations", len(redisKeys), len(generations))
		}
		result := make([]any, len(generations)*4)
		for index := range generations {
			result[index*4+3] = int64(0)
		}
		return result, nil
	}}
	values, err := client.LoadConnectivity(t.Context(), keys)
	if err != nil || len(values) != len(keys) || calls != 2 {
		t.Fatalf("LoadConnectivity() = (%d values, %v) after %d calls, want 129 values in 2 batches", len(values), err, calls)
	}
}

func TestClientRejectsCorruptConnectivityProjection(t *testing.T) {
	t.Parallel()

	observation := testEndpointObservation(t, 7)
	key, err := mapsession.NewConnectivityKey(observation.NodeID(), 7)
	if err != nil {
		t.Fatalf("mapsession.NewConnectivityKey() error = %v", err)
	}
	for _, result := range [][]any{
		{nil},
		{nil, nil, nil, "online"},
		{[]byte("{}"), nil, nil, int64(1)},
		{nil, "1", nil, int64(0)},
		{nil, "2", "3", int64(0)},
	} {
		client := &Client{loadConnectivity: func(context.Context, []string, []int64) ([]any, error) {
			return result, nil
		}}
		if _, err := client.LoadConnectivity(
			t.Context(),
			[]mapsession.ConnectivityKey{key},
		); !errors.Is(err, ErrLoadConnectivity) {
			t.Fatalf("LoadConnectivity(%v) error = %v, want ErrLoadConnectivity", result, err)
		}
	}
}

func TestClientRejectsInvalidEndpointInputsAndResults(t *testing.T) {
	t.Parallel()

	observation := testEndpointObservation(t, 7)
	wantErr := errors.New("redis unavailable")
	for _, test := range []struct {
		name   string
		result int64
		err    error
		want   error
	}{
		{name: "malformed result", result: -1, want: ErrObserveEndpoints},
		{name: "transport error", err: wantErr, want: wantErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &Client{observeEndpoints: func(context.Context, endpointObservation) (int64, int64, error) {
				return test.result, 0, test.err
			}}
			if _, _, err := client.ObserveEndpoints(
				t.Context(),
				testNetworkScope(t),
				observation,
				5*time.Second,
			); !errors.Is(err, test.want) {
				t.Fatalf("ObserveEndpoints() error = %v, want %v", err, test.want)
			}
		})
	}

	client := &Client{
		observeEndpoints: func(context.Context, endpointObservation) (int64, int64, error) {
			t.Fatal("ObserveEndpoints() called for invalid observation")
			return 0, 0, nil
		},
		loadEndpoints: func(context.Context, string, int64) ([]byte, error) {
			t.Fatal("LoadEndpoints() called for invalid identity")
			return nil, nil
		},
	}
	if _, _, err := client.ObserveEndpoints(
		t.Context(),
		testNetworkScope(t),
		node.EndpointObservation{},
		5*time.Second,
	); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("ObserveEndpoints(zero) error = %v, want ErrInvalidOptions", err)
	}
	if _, _, err := client.LoadEndpoints(t.Context(), node.ID{}, 7); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("LoadEndpoints(zero id) error = %v, want ErrInvalidOptions", err)
	}
}

func testNetworkScope(t testing.TB) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	return scope
}

func TestDecodeEndpointSetRejectsCorruptPayload(t *testing.T) {
	t.Parallel()

	for _, payload := range [][]byte{
		nil,
		[]byte(`{"version":2,"discovery_key":"11","endpoints":[]}`),
		[]byte(`{"version":1,"discovery_key":"1111111111111111111111111111111111111111111111111111111111111111","endpoints":[],"unknown":true}`),
		[]byte(`{"version":1,"discovery_key":"1111111111111111111111111111111111111111111111111111111111111111","endpoints":[]} {}`),
	} {
		if _, err := decodeEndpointSet(payload); !errors.Is(err, ErrLoadEndpoints) {
			t.Fatalf("decodeEndpointSet(%q) error = %v, want ErrLoadEndpoints", payload, err)
		}
	}
}

func TestDecodeEndpointSetDropsUndistributedEndpoints(t *testing.T) {
	t.Parallel()
	// An older replica may have stored an overlay address; the rest of the
	// report is still used.
	payload := []byte(`{"version":1,"discovery_key":"1111111111111111111111111111111111111111111111111111111111111111",` +
		`"endpoints":[{"address":"100.64.0.9:41641","source":1},{"address":"198.51.100.7:41641","source":2}]}`)
	set, err := decodeEndpointSet(payload)
	if err != nil {
		t.Fatalf("decodeEndpointSet() error = %v", err)
	}
	if endpoints := set.Endpoints(); len(endpoints) != 1 ||
		endpoints[0].Address() != netip.MustParseAddrPort("198.51.100.7:41641") {
		t.Fatalf("decodeEndpointSet() = %+v, want only the public endpoint", endpoints)
	}
	// A malformed endpoint still makes the payload corrupt.
	malformed := []byte(`{"version":1,"discovery_key":"1111111111111111111111111111111111111111111111111111111111111111",` +
		`"endpoints":[{"address":"198.51.100.7:0","source":2}]}`)
	if _, err := decodeEndpointSet(malformed); !errors.Is(err, ErrLoadEndpoints) {
		t.Fatalf("decodeEndpointSet(port 0) error = %v, want ErrLoadEndpoints", err)
	}
}

func testEndpointObservation(t testing.TB, generation int64) node.EndpointObservation {
	t.Helper()
	nodeID, err := node.ParseID("01890f00-0000-7000-8000-000000000701")
	if err != nil {
		t.Fatalf("node.ParseID() error = %v", err)
	}
	discoveryKey, err := node.NewDiscoveryKey([32]byte{1})
	if err != nil {
		t.Fatalf("node.NewDiscoveryKey() error = %v", err)
	}
	first, _ := node.NewEndpoint(netip.MustParseAddrPort("192.0.2.10:41641"), node.EndpointSourceSTUN)
	second, _ := node.NewEndpoint(netip.MustParseAddrPort("10.0.0.2:41641"), node.EndpointSourceLocal)
	set, err := node.NewEndpointSet(discoveryKey, []node.Endpoint{first, second})
	if err != nil {
		t.Fatalf("node.NewEndpointSet() error = %v", err)
	}
	observation, err := node.NewEndpointObservation(nodeID, generation, set, 30*time.Second)
	if err != nil {
		t.Fatalf("node.NewEndpointObservation() error = %v", err)
	}
	observation, err = observation.WithPreferredRelay(3)
	if err != nil {
		t.Fatalf("EndpointObservation.WithPreferredRelay() error = %v", err)
	}
	return observation
}
