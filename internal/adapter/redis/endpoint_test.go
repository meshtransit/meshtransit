package redis

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/node"
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
	var observedTTL time.Duration
	var observedPayload []byte
	client := &Client{
		observeEndpoints: func(
			gotContext context.Context,
			endpointKey string,
			presenceKey string,
			generation int64,
			payload []byte,
			ttl time.Duration,
		) (int64, error) {
			if gotContext != ctx {
				t.Fatal("ObserveEndpoints() did not propagate context")
			}
			observedEndpointKey, observedPresenceKey = endpointKey, presenceKey
			observedGeneration, observedTTL = generation, ttl
			observedPayload = append([]byte(nil), payload...)
			return 1, nil
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
	accepted, err := client.ObserveEndpoints(ctx, observation)
	if err != nil || !accepted {
		t.Fatalf("ObserveEndpoints() = (%t, %v), want accepted", accepted, err)
	}
	set, found, err := client.LoadEndpoints(ctx, observation.NodeID(), observation.Generation())
	if err != nil || !found {
		t.Fatalf("LoadEndpoints() = (%+v, %t, %v), want endpoint set", set, found, err)
	}
	wantEndpointKey := endpointKeyPrefix + observation.NodeID().String()
	wantPresenceKey := presenceKeyPrefix + observation.NodeID().String()
	if observedEndpointKey != wantEndpointKey || loadedKey != wantEndpointKey ||
		observedPresenceKey != wantPresenceKey || observedGeneration != 7 || loadedGeneration != 7 ||
		observedTTL != 30*time.Second || set.DiscoveryKey() != observation.Set().DiscoveryKey() ||
		!slices.Equal(set.Endpoints(), observation.Set().Endpoints()) {
		t.Fatalf("endpoint arguments or round trip did not preserve observation")
	}
}

func TestClientTreatsStaleAndMissingEndpointsAsCleanResults(t *testing.T) {
	t.Parallel()

	observation := testEndpointObservation(t, 7)
	client := &Client{
		observeEndpoints: func(context.Context, string, string, int64, []byte, time.Duration) (int64, error) {
			return 0, nil
		},
		loadEndpoints: func(context.Context, string, int64) ([]byte, error) {
			return nil, nil
		},
	}
	if accepted, err := client.ObserveEndpoints(t.Context(), observation); err != nil || accepted {
		t.Fatalf("ObserveEndpoints() = (%t, %v), want clean rejection", accepted, err)
	}
	if _, found, err := client.LoadEndpoints(t.Context(), observation.NodeID(), 8); err != nil || found {
		t.Fatalf("LoadEndpoints() = (_, %t, %v), want clean miss", found, err)
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
			client := &Client{observeEndpoints: func(
				context.Context,
				string,
				string,
				int64,
				[]byte,
				time.Duration,
			) (int64, error) {
				return test.result, test.err
			}}
			if _, err := client.ObserveEndpoints(t.Context(), observation); !errors.Is(err, test.want) {
				t.Fatalf("ObserveEndpoints() error = %v, want %v", err, test.want)
			}
		})
	}

	client := &Client{
		observeEndpoints: func(context.Context, string, string, int64, []byte, time.Duration) (int64, error) {
			t.Fatal("ObserveEndpoints() called for invalid observation")
			return 0, nil
		},
		loadEndpoints: func(context.Context, string, int64) ([]byte, error) {
			t.Fatal("LoadEndpoints() called for invalid identity")
			return nil, nil
		},
	}
	if _, err := client.ObserveEndpoints(t.Context(), node.EndpointObservation{}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("ObserveEndpoints(zero) error = %v, want ErrInvalidOptions", err)
	}
	if _, _, err := client.LoadEndpoints(t.Context(), node.ID{}, 7); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("LoadEndpoints(zero id) error = %v, want ErrInvalidOptions", err)
	}
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
	return observation
}
