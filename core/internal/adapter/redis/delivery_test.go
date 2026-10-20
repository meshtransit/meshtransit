package redis

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
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
		gotRecord.filterGrants != "" || gotRecord.peerLimit != "" {
		t.Fatalf("record without filter = %+v, %v", gotRecord, err)
	}
	routes, err := mapsession.NewRouteDigest(filter.Digest(), 2)
	if err != nil {
		t.Fatal(err)
	}
	delivery.Routes = routes
	if err := client.RecordDelivery(t.Context(), delivery); err != nil || gotRecord.routeDigest != testDigestText ||
		gotRecord.routeEntries != "2" {
		t.Fatalf("record with routes = %+v, %v", gotRecord, err)
	}
	delivery.Routes = mapsession.RouteDigest{}
	delivery.PeersSent, delivery.PeersAuthorized = 10_000, 80_000
	if err := client.RecordDelivery(t.Context(), delivery); err != nil || gotRecord.peerLimit != "10000:80000" {
		t.Fatalf("record with a peer limit = %+v, %v", gotRecord, err)
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
				testDigestText, "7", "1759924801000", "1759924802000", testPathsText, testConnectivityText,
				"10000:80000", testDigestText, "3", testDigestText, "3",
				`[["prod","failed","forward_blocked"]]`, "1759924803000",
				`[["prod","01890f00-0000-7000-8000-000000000402","local_failover"],["uat","","none"]]`, "1759924804000",
				`["01890f00-0000-7000-8000-000000000501","degraded","no_ipv6","v4"]`,
				"1",
				"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "0",
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
	if first.PeerLimit != (distribution.PeerLimit{Sent: 10_000, Authorized: 80_000}) {
		t.Fatalf("first peer limit = %+v", first.PeerLimit)
	}
	if first.Routes != (distribution.RouteSummary{Digest: first.Filter.Digest, Entries: 3}) ||
		first.EnforcedRoutes != first.Routes || len(first.RouteHealth) != 1 ||
		first.RouteHealth[0] != (distribution.SiteHealth{Ref: "prod", State: "failed", Code: "forward_blocked"}) ||
		first.RouteHealthAt.UnixMilli() != 1759924803000 {
		t.Fatalf("first routes = %+v %+v %+v at %v", first.Routes, first.EnforcedRoutes, first.RouteHealth, first.RouteHealthAt)
	}
	if len(first.RouteSelection) != 2 || first.RouteSelectionAt.UnixMilli() != 1759924804000 ||
		first.RouteSelection[0] != (distribution.SiteRouter{Ref: "prod", Router: "01890f00-0000-7000-8000-000000000402",
			Via: distribution.ViaLocalFailover}) || first.RouteSelection[1].Via != distribution.ViaNone {
		t.Fatalf("first selection = %+v at %v", first.RouteSelection, first.RouteSelectionAt)
	}
	if first.ExitHealth == nil || *first.ExitHealth != (distribution.ExitHealth{
		Ref: "01890f00-0000-7000-8000-000000000501", State: "degraded", Code: "no_ipv6", Families: "v4"}) {
		t.Fatalf("first exit health = %+v", first.ExitHealth)
	}
	if second.Known || second.Online {
		t.Fatalf("second = %+v", second)
	}
}

func TestDecodeRoutesRefusesMalformedFields(t *testing.T) {
	t.Parallel()
	for name, test := range map[string][2]string{
		"digest without entries": {testDigestText, ""},
		"entries without digest": {"", "3"},
		"bad digest":             {"sha256:00", "3"},
		"too many entries":       {testDigestText, "4097"},
	} {
		if _, err := decodeRouteSummary(test[0], test[1]); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	for _, text := range []string{"{", `[["a","b"]]`, `"x"`} {
		if _, err := decodeRouteHealth(text); err == nil {
			t.Errorf("route health %q was accepted", text)
		}
	}
	if health, err := decodeRouteHealth(""); err != nil || health != nil {
		t.Fatalf("empty route health = %v, %v", health, err)
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
	withRoutes := enforcement
	withRoutes.Routes, _ = mapsession.NewRouteDigest(enforcement.Filter.Digest(), 5)
	if stored, err := client.RecordEnforcement(t.Context(), withRoutes); err != nil || !stored ||
		gotRecord.routeDigest != testDigestText || gotRecord.routeEntries != "5" {
		t.Fatalf("RecordEnforcement() with routes = %t, %v; %+v", stored, err, gotRecord)
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

func TestClientRecordsRouteHealthForItsSession(t *testing.T) {
	t.Parallel()
	nodeID := testDeliveryNode(t)
	session := []any{nodeID.String(), "4", hex.EncodeToString(testMachine[:])}
	var gotKey, gotEncoded string
	var gotGeneration, gotAt int64
	var gotFailed bool
	var gotExit string
	client := &Client{
		loadSession: func(context.Context, string) ([]any, error) { return session, nil },
		recordRouteHealth: func(_ context.Context, key string, generation int64, encoded string, at int64,
			_ time.Duration, failed bool, exit string) (int64, error) {
			gotKey, gotGeneration, gotEncoded, gotAt, gotFailed, gotExit = key, generation, encoded, at, failed, exit
			return 1, nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	reported := time.UnixMilli(1759924803000)
	health := mapsession.RouteHealth{NodeKey: testNodeKey, MachineFingerprint: testMachine, ReportedAt: reported,
		Sites: []mapsession.SiteHealth{
			{Ref: "prod", State: mapsession.RouteHealthFailed, Code: "forward_blocked"},
			{Ref: "uat", State: mapsession.RouteHealthOK, Code: "ok"},
		}}
	stored, err := client.RecordRouteHealth(t.Context(), health)
	if err != nil || !stored || gotKey != deliveryKeyForNode(nodeID) || gotGeneration != 4 || !gotFailed ||
		gotAt != reported.UnixMilli() || gotEncoded != `[["prod","failed","forward_blocked"],["uat","ok","ok"]]` {
		t.Fatalf("RecordRouteHealth() = %t, %v; %s %d %s", stored, err, gotKey, gotGeneration, gotEncoded)
	}
	decoded, err := decodeRouteHealth(gotEncoded)
	if err != nil || len(decoded) != 2 || decoded[0] != (distribution.SiteHealth{Ref: "prod", State: "failed", Code: "forward_blocked"}) {
		t.Fatalf("round trip = %+v, %v", decoded, err)
	}
	healthy := health
	healthy.Sites = []mapsession.SiteHealth{{Ref: "prod", State: mapsession.RouteHealthOK, Code: "ok"}}
	if stored, err := client.RecordRouteHealth(t.Context(), healthy); err != nil || !stored || gotFailed {
		t.Fatalf("healthy report = %t, %v, failed %t", stored, err, gotFailed)
	}
	other := health
	other.MachineFingerprint = [32]byte{0x55}
	gotKey = ""
	if stored, err := client.RecordRouteHealth(t.Context(), other); err != nil || stored || gotKey != "" {
		t.Fatalf("other machine = %t, %v, wrote %q", stored, err, gotKey)
	}
	invalid := health
	invalid.Sites = []mapsession.SiteHealth{{Ref: "prod", State: mapsession.RouteHealthFailed}}
	if _, err := client.RecordRouteHealth(t.Context(), invalid); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("invalid health = %v", err)
	}
	if gotExit != "" {
		t.Fatalf("a report without exit health stored %q", gotExit)
	}
	// An exit node's pool health is stored with it; a failed pool does not
	// wake the Site election.
	exitOnly := health
	exitOnly.Sites = nil
	exitOnly.Exit = &mapsession.ExitHealth{Ref: "pool", State: mapsession.RouteHealthFailed, Code: "egress_failed",
		Families: mapsession.ExitFamiliesBoth}
	if stored, err := client.RecordRouteHealth(t.Context(), exitOnly); err != nil || !stored || gotFailed ||
		gotExit != `["pool","failed","egress_failed","both"]` || gotEncoded != "[]" {
		t.Fatalf("exit health = %t, %v, failed %t, %q %q", stored, err, gotFailed, gotExit, gotEncoded)
	}
	if decoded, err := decodeExitHealth(gotExit); err != nil || decoded == nil || decoded.Families != "both" {
		t.Fatalf("exit round trip = %+v, %v", decoded, err)
	}
	for _, text := range []string{"{", `["pool","failed","","v4"]`, `["pool","teleport","x","v4"]`, `["pool","ok","ok","v9"]`} {
		if _, err := decodeExitHealth(text); err == nil {
			t.Errorf("exit health %q was accepted", text)
		}
	}
	exitOnly.Exit = &mapsession.ExitHealth{Ref: "pool", State: mapsession.RouteHealthOK}
	if _, err := client.RecordRouteHealth(t.Context(), exitOnly); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("invalid exit health = %v", err)
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

func TestDecodePeerLimitRejectsMalformedValues(t *testing.T) {
	t.Parallel()
	for _, text := range []string{"10", "a:b", "5:5", "0:3", "7:3"} {
		if _, err := decodePeerLimit(text); err == nil {
			t.Errorf("decodePeerLimit(%q) accepted a malformed value", text)
		}
	}
}

func TestClientRecordsRouteSelectionAndCountsRouters(t *testing.T) {
	t.Parallel()
	nodeID := testDeliveryNode(t)
	session := []any{nodeID.String(), "4", hex.EncodeToString(testMachine[:])}
	router, _ := node.ParseID("01890f00-0000-7000-8000-000000000402")
	var gotKey, gotEncoded, gotNode string
	var gotGeneration int64
	client := &Client{
		loadSession: func(context.Context, string) ([]any, error) { return session, nil },
		recordRouteSelection: func(_ context.Context, key string, generation int64, encoded string, _ int64,
			nodeText string,
		) (int64, error) {
			gotKey, gotGeneration, gotEncoded, gotNode = key, generation, encoded, nodeText
			return 1, nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	selection := mapsession.RouteSelection{NodeKey: testNodeKey, MachineFingerprint: testMachine,
		ReportedAt: time.UnixMilli(1759924803000), Sites: []mapsession.SiteSelection{
			{Ref: "prod", Router: router, Reason: mapsession.RouteSelectionLocalFailover},
			{Ref: "uat", Reason: mapsession.RouteSelectionNone},
		}}
	stored, err := client.RecordRouteSelection(t.Context(), selection)
	if err != nil || !stored || gotKey != deliveryKeyForNode(nodeID) || gotGeneration != 4 || gotNode != nodeID.String() ||
		gotEncoded != `[["prod","01890f00-0000-7000-8000-000000000402","local_failover"],["uat","","none"]]` {
		t.Fatalf("RecordRouteSelection() = %t, %v; %s %d %s", stored, err, gotKey, gotGeneration, gotEncoded)
	}
	invalid := selection
	invalid.Sites = []mapsession.SiteSelection{{Ref: "prod", Reason: mapsession.RouteSelectionPrimary}}
	if _, err := client.RecordRouteSelection(t.Context(), invalid); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("a primary without a router = %v", err)
	}

	now := time.UnixMilli(1759924900000)
	fresh, stale := strconv.FormatInt(now.Add(-time.Minute).UnixMilli(), 10), strconv.FormatInt(now.Add(-time.Hour).UnixMilli(), 10)
	lingering := strconv.FormatInt(now.Add(-5*time.Minute).UnixMilli(), 10)
	client.loadSiteSelection = func(_ context.Context, key string, _ int) (map[string]string, error) {
		if key != siteSelectionPrefix+"prod" {
			t.Fatalf("read %q", key)
		}
		return map[string]string{"n1": "r1|primary|" + fresh, "n2": "r1|primary|" + fresh,
			"n3": "r2|local_failover|" + fresh, "n4": "r1|primary|" + stale, "n5": "|none|" + fresh,
			"n6": "malformed", "n7": "r1|primary|" + lingering}, nil
	}
	var pruned []string
	client.pruneSiteSelection = func(_ context.Context, _ string, fields []string) error {
		pruned = fields
		return nil
	}
	uses, err := client.CountSiteRouters(t.Context(), "prod", now)
	if err != nil || len(uses) != 2 || uses["r1"] != (distribution.RouterUse{Clients: 2}) ||
		uses["r2"] != (distribution.RouterUse{Clients: 1, LocalFailover: 1}) {
		t.Fatalf("CountSiteRouters() = %+v, %v", uses, err)
	}
	// Entries past the prune age go; one only stale for counting stays.
	slices.Sort(pruned)
	if !slices.Equal(pruned, []string{"n4", "n6"}) {
		t.Fatalf("pruned %v", pruned)
	}
}

// A record an older Core reset keeps exit health without its time: it is
// read as none, not as a corrupt record.
func TestDecodeObservationDropsExitHealthWithoutItsTime(t *testing.T) {
	t.Parallel()
	fields := []string{"4", "9", "3", "1759924800000", "1759924860000", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", `["pool","ok","ok","v4"]`, "1"}
	observation, err := decodeObservation(fields)
	if err != nil || !observation.Known || observation.ExitHealth != nil {
		t.Fatalf("decodeObservation() = %+v, %v", observation, err)
	}
}
