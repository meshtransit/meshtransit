package redis

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/shared/policydigest"
)

func testDeliveryNode(t *testing.T) node.ID {
	t.Helper()
	id, err := node.ParseID("01890f00-0000-7000-8000-000000000301")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestClientRecordsAndTouchesDeliveryUnderOneKey(t *testing.T) {
	t.Parallel()
	nodeID := testDeliveryNode(t)
	delivered := time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)
	var gotKey, gotSessionKey string
	var gotRecord deliveryRecord
	var gotTTL time.Duration
	var touchKey string
	var touchArgs []int64
	client := &Client{
		recordDelivery: func(_ context.Context, key, sessionKey string, record deliveryRecord,
			ttl time.Duration) (int64, error) {
			gotKey, gotSessionKey, gotTTL, gotRecord = key, sessionKey, ttl, record
			return 1, nil
		},
		touchDelivery: func(_ context.Context, key string, generation, seenAt int64, _ time.Duration) (int64, error) {
			touchKey, touchArgs = key, []int64{generation, seenAt}
			return 0, nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	filter := testFilterDigest(t, 7)
	delivery := mapsession.Delivery{NodeID: nodeID, NodeKey: testNodeKey, MachineFingerprint: testMachine,
		SessionGeneration: 4, NetworkRevision: 9, PolicyRevision: 3, DeliveredAt: delivered, Filter: filter}
	if err := client.RecordDelivery(t.Context(), delivery); err != nil {
		t.Fatalf("RecordDelivery() error = %v", err)
	}
	wantKey := "meshtransit:v1:delivery:node:" + nodeID.String()
	want := deliveryRecord{nodeID: nodeID.String(), machine: hex.EncodeToString(testMachine[:]), generation: 4,
		networkRevision: 9, policyRevision: 3, deliveredAt: delivered.UnixMilli(),
		filterDigest: filter.Digest().String(), filterGrants: "7"}
	if gotKey != wantKey || gotSessionKey != sessionKeyForNodeKey(testNodeKey) ||
		!strings.HasPrefix(gotSessionKey, deliveryKeyPrefix) || gotTTL != deliveryTTL || gotRecord != want {
		t.Fatalf("record = %s %s %+v %s", gotKey, gotSessionKey, gotRecord, gotTTL)
	}
	delivery.Filter = mapsession.FilterDigest{}
	if err := client.RecordDelivery(t.Context(), delivery); err != nil || gotRecord.filterDigest != "" ||
		gotRecord.filterGrants != "" {
		t.Fatalf("record without filter = %+v, %v", gotRecord, err)
	}
	if err := client.TouchDelivery(t.Context(), nodeID, 4, delivered.Add(time.Minute)); err != nil {
		t.Fatalf("TouchDelivery() error = %v", err)
	}
	if touchKey != wantKey || touchArgs[0] != 4 || touchArgs[1] != delivered.Add(time.Minute).UnixMilli() {
		t.Fatalf("touch = %s %v", touchKey, touchArgs)
	}
}

func TestClientRejectsInvalidDeliveriesBeforeRedis(t *testing.T) {
	t.Parallel()
	called := false
	client := &Client{
		recordDelivery: func(context.Context, string, string, deliveryRecord, time.Duration) (int64, error) {
			called = true
			return 1, nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	if err := client.RecordDelivery(t.Context(), mapsession.Delivery{}); !errors.Is(err, ErrInvalidOptions) || called {
		t.Fatalf("RecordDelivery(invalid) error = %v called = %t", err, called)
	}
}

func TestClientLoadsObservationsInOrder(t *testing.T) {
	t.Parallel()
	known, unknown := testDeliveryNode(t), testDeliveryNode(t)
	unknown[15] = 0x02
	var gotKeys []string
	client := &Client{
		loadDeliveries: func(_ context.Context, keys []string) ([]any, error) {
			gotKeys = keys
			return []any{
				"4", "9", "3", "1759924800000", "1759924860000", testDigestText, "7",
				testDigestText, "7", "1759924801000", "1759924802000", testPathsText, testConnectivityText, "1",
				"", "", "", "", "", "", "", "", "", "", "", "", "", "0",
			}, nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	observations, err := client.LoadObservations(t.Context(), []node.ID{known, unknown})
	if err != nil {
		t.Fatalf("LoadObservations() error = %v", err)
	}
	if len(gotKeys) != 4 || gotKeys[0] != deliveryKeyForNode(known) || gotKeys[1] != presenceKeyForNode(known) {
		t.Fatalf("keys = %v", gotKeys)
	}
	first, second := observations[0], observations[1]
	if !first.Known || !first.Online || first.NetworkRevision != 9 || first.PolicyRevision != 3 ||
		first.SessionGeneration != 4 || first.SeenAt.Sub(first.DeliveredAt) != time.Minute ||
		first.Filter.Digest.String() != testDigestText || first.Filter.Grants != 7 || first.Enforced != first.Filter ||
		first.ReportedAt.Sub(first.AppliedAt) != time.Second {
		t.Fatalf("first = %+v", first)
	}
	if first.Paths == nil || len(first.Paths.Peers) != 2 || first.Paths.Interval != time.Minute ||
		first.Paths.Peers[0].Kind != distribution.PathRelay || first.Paths.Peers[0].RelayCode != "sgp" ||
		first.Paths.Peers[0].RelayReason != distribution.RelayNoResponse || first.Paths.Peers[1].DirectBytes != 900 {
		t.Fatalf("first paths = %+v", first.Paths)
	}
	if c := first.Connectivity; c == nil || c.NAT == nil || c.NAT.Mapping != distribution.NATMappingAddressAndPortDependent ||
		c.NAT.SequentialStep != 2 || !c.IPv6Global || c.IPv6STUN || c.PortMapping == nil ||
		c.PortMapping.Protocol != distribution.PortMappingProtocolUPnP || c.PortMapping.State != distribution.PortMappingMapped {
		t.Fatalf("first connectivity = %+v", first.Connectivity)
	}
	if second.Known || second.Online {
		t.Fatalf("second = %+v", second)
	}
}

func TestClientRejectsCorruptObservations(t *testing.T) {
	t.Parallel()
	id := testDeliveryNode(t)
	valid := []string{"4", "9", "3", "1759924800000", "1759924860000", testDigestText, "7",
		testDigestText, "7", "1759924801000", "1759924802000", "", "", "0"}
	with := func(index int, value any) []any {
		raw := make([]any, len(valid))
		for position, field := range valid {
			raw[position] = field
		}
		raw[index] = value
		return raw
	}
	for name, raw := range map[string][]any{
		"short":                {"4", "9"},
		"partial record":       {"", "9", "", "", "", "", "", "", "", "", "", "", "", "0"},
		"bad number":           with(0, "x"),
		"bad presence":         with(13, "2"),
		"bad connectivity":     with(12, `{"at":1,"nat":{"map":"teleport","filter":"unknown","alloc":"unknown"}}`),
		"stun without v6":      with(12, `{"at":1,"v6stun":true}`),
		"connectivity no time": with(12, `{"v6":true}`),
		"bad paths":            with(11, `{"at":1,"interval_s":60,"peers":[{"id":"x","kind":"direct"}]}`),
		"paths kind":           with(11, `{"at":1,"interval_s":60,"peers":[{"id":"`+testPathPeer+`","kind":"teleport"}]}`),
		"paths no time":        with(11, `{"interval_s":60,"peers":[]}`),
		"seen before":          with(4, "1759924700000"),
		"non string":           with(0, int64(4)),
		"bad digest":           with(5, "sha256:00"),
		"digest alone":         with(6, ""),
		"bad grants":           with(8, "-1"),
		"applied late":         with(9, "1759924803000"),
		"report no times":      with(10, ""),
	} {
		client := &Client{
			loadDeliveries: func(context.Context, []string) ([]any, error) { return raw, nil },
			metrics:        newRedisMetrics(1, nil),
		}
		if _, err := client.LoadObservations(t.Context(), []node.ID{id}); !errors.Is(err, ErrLoadDeliveries) {
			t.Errorf("%s: error = %v, want ErrLoadDeliveries", name, err)
		}
	}
}

const testConnectivityText = `{"at":1759924830000,"nat":{"map":"address_and_port_dependent",` +
	`"filter":"address_and_port_dependent","alloc":"sequential","step":2},"v6":true,` +
	`"pm":{"proto":"upnp","state":"mapped","exp":1759932030000}}`

const testDigestText = "sha256:5714d8784aeeb16d13dade4978798461062af395740fd19a493c8a88b5cea897"

const (
	testPathPeer  = "01890f90-0000-7000-8000-0000000000b1"
	testPathsText = `{"at":1759924830000,"interval_s":60,"peers":[` +
		`{"id":"01890f90-0000-7000-8000-0000000000b1","kind":"relay","region":1,"code":"sgp","why":"no_response","relay":300},` +
		`{"id":"01890f90-0000-7000-8000-0000000000b2","kind":"direct","direct":900}]}`
)

func testFilterDigest(t *testing.T, grants int) mapsession.FilterDigest {
	t.Helper()
	digest, err := policydigest.Parse(testDigestText)
	if err != nil {
		t.Fatal(err)
	}
	filter, err := mapsession.NewFilterDigest(digest, grants)
	if err != nil {
		t.Fatal(err)
	}
	return filter
}

var (
	testNodeKey = node.Key{0x11, 0x22}
	testMachine = [32]byte{0x33, 0x44}
)

func TestClientRecordsEnforcementForItsSession(t *testing.T) {
	t.Parallel()
	nodeID := testDeliveryNode(t)
	applied := time.Date(2026, time.October, 9, 12, 0, 0, 0, time.UTC)
	session := []any{nodeID.String(), "4", hex.EncodeToString(testMachine[:])}
	var gotSessionKey, gotKey string
	var gotRecord enforcementRecord
	result := int64(1)
	client := &Client{
		loadSession: func(_ context.Context, key string) ([]any, error) {
			gotSessionKey = key
			return session, nil
		},
		recordEnforcement: func(_ context.Context, key string, record enforcementRecord, ttl time.Duration) (int64, error) {
			if ttl != deliveryTTL {
				t.Errorf("ttl = %s", ttl)
			}
			gotKey, gotRecord = key, record
			return result, nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	enforcement := mapsession.Enforcement{NodeKey: testNodeKey, MachineFingerprint: testMachine,
		Filter: testFilterDigest(t, 3), AppliedAt: applied, ReportedAt: applied.Add(time.Second)}
	stored, err := client.RecordEnforcement(t.Context(), enforcement)
	want := enforcementRecord{generation: 4, digest: testDigestText, grants: 3, appliedAt: applied.UnixMilli(),
		reportedAt: applied.Add(time.Second).UnixMilli()}
	if err != nil || !stored || gotSessionKey != sessionKeyForNodeKey(testNodeKey) ||
		gotKey != deliveryKeyForNode(nodeID) || gotRecord != want {
		t.Fatalf("RecordEnforcement() = %t, %v; %s %+v", stored, err, gotKey, gotRecord)
	}
	result = 0
	if stored, err := client.RecordEnforcement(t.Context(), enforcement); err != nil || stored {
		t.Fatalf("stale session RecordEnforcement() = %t, %v", stored, err)
	}
	result = 1
	other := enforcement
	other.MachineFingerprint = [32]byte{0x55}
	gotKey = ""
	if stored, err := client.RecordEnforcement(t.Context(), other); err != nil || stored || gotKey != "" {
		t.Fatalf("other machine RecordEnforcement() = %t, %v, wrote %q", stored, err, gotKey)
	}
	session = []any{nil, nil, nil}
	if stored, err := client.RecordEnforcement(t.Context(), enforcement); err != nil || stored {
		t.Fatalf("unknown session RecordEnforcement() = %t, %v", stored, err)
	}
	session = []any{"not-an-id", "4", hex.EncodeToString(testMachine[:])}
	if _, err := client.RecordEnforcement(t.Context(), enforcement); !errors.Is(err, ErrRecordDelivery) {
		t.Fatalf("corrupt session RecordEnforcement() error = %v", err)
	}
	if _, err := client.RecordEnforcement(t.Context(), mapsession.Enforcement{}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("invalid RecordEnforcement() error = %v", err)
	}
}

func TestClientRecordsPaths(t *testing.T) {
	t.Parallel()
	id := testDeliveryNode(t)
	peer, err := node.ParseID(testPathPeer)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	client := &Client{
		recordPaths: func(_ context.Context, key string, generation int64, encoded string, _ time.Duration) (int64, error) {
			if key != deliveryKeyForNode(id) || generation != 4 {
				t.Fatalf("key %s generation %d", key, generation)
			}
			stored = encoded
			return 1, nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	report := distribution.PathReport{ReportedAt: time.UnixMilli(1759924830000), Interval: time.Minute,
		Peers: []distribution.PeerPath{{PeerID: peer, Kind: distribution.PathRelay, RelayRegion: 1, RelayCode: "sgp",
			RelayReason: distribution.RelayNoResponse, RelayBytes: 300}}}
	if err := client.RecordPaths(t.Context(), id, 4, report); err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePaths(stored)
	if err != nil || decoded == nil || len(decoded.Peers) != 1 || decoded.Peers[0] != report.Peers[0] {
		t.Fatalf("round trip %+v, %v", decoded, err)
	}
	report.Peers[0].Kind = "teleport"
	if err := client.RecordPaths(t.Context(), id, 4, report); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("invalid report: %v", err)
	}
}

func TestClientRecordsConnectivity(t *testing.T) {
	t.Parallel()
	id := testDeliveryNode(t)
	var stored string
	client := &Client{
		recordConnectivity: func(_ context.Context, key string, generation int64, encoded string, _ time.Duration) (int64, error) {
			if key != deliveryKeyForNode(id) || generation != 4 {
				t.Fatalf("key %s generation %d", key, generation)
			}
			stored = encoded
			return 1, nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	report := distribution.Connectivity{ReportedAt: time.UnixMilli(1759924830000).UTC(), IPv6Global: true, IPv6STUN: true,
		NAT: &distribution.NATClass{Mapping: distribution.NATMappingEndpointIndependent,
			Filtering: distribution.NATFilteringAddressDependent, Allocation: distribution.NATAllocationPreserving,
			ObservedAt: time.UnixMilli(1759924800000).UTC()},
		PortMapping: &distribution.PortMapping{Protocol: distribution.PortMappingProtocolPCP,
			State: distribution.PortMappingMapped, ExpiresAt: time.UnixMilli(1759932030000).UTC()}}
	if err := client.RecordConnectivity(t.Context(), id, 4, report); err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeConnectivity(stored)
	if err != nil || decoded == nil || !decoded.SameAs(report) || !decoded.ReportedAt.Equal(report.ReportedAt) {
		t.Fatalf("round trip %+v, %v", decoded, err)
	}
	report.PortMapping.State = "teleported"
	if err := client.RecordConnectivity(t.Context(), id, 4, report); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("invalid report: %v", err)
	}
}
