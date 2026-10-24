package redis

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/dnsdigest"
)

func testNetworkID(t *testing.T) network.ID {
	t.Helper()
	id, err := network.ParseID("01890f00-0000-7000-8000-00000000d1b3")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A delivery with DNS evidence names its Network and the zones it holds,
// for the DNS index; one without carries neither.
func TestRecordDeliveryNamesTheZonesItHolds(t *testing.T) {
	t.Parallel()
	var got deliveryRecord
	client := &Client{
		recordDelivery: func(_ context.Context, _, _ string, record deliveryRecord, _ time.Duration) (int64, error) {
			got = record
			return 1, nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	nodeID, err := node.ParseID("01890f00-0000-7000-8000-00000000d1b4")
	if err != nil {
		t.Fatal(err)
	}
	raw, routes, err := dnsdigest.Compute([]dnsdigest.Route{{Suffix: ".", Unavailable: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := mapsession.NewDNSDigest(raw, routes)
	if err != nil {
		t.Fatal(err)
	}
	delivery := mapsession.Delivery{Network: testNetworkID(t), NodeID: nodeID, NodeKey: testNodeKey,
		MachineFingerprint: testMachine, SessionGeneration: 2, NetworkRevision: 3, DeliveredAt: time.Now(),
		DNS: digest.WithZones([]string{"corp.internal", ".", "corp.internal"})}
	if err := client.RecordDelivery(t.Context(), delivery); err != nil {
		t.Fatal(err)
	}
	if got.dnsNetwork != testNetworkID(t).String() || got.dnsZones != `[".","corp.internal"]` || got.dnsDigest == "" {
		t.Fatalf("record %+v", got)
	}
	delivery.DNS = digest
	if err := client.RecordDelivery(t.Context(), delivery); err != nil || got.dnsZones != "[]" {
		t.Fatalf("no zones: %+v, %v", got, err)
	}
	delivery.DNS = mapsession.DNSDigest{}
	if err := client.RecordDelivery(t.Context(), delivery); err != nil || got.dnsNetwork != "" || got.dnsZones != "" {
		t.Fatalf("without DNS evidence: %+v, %v", got, err)
	}
}

func applicationEntry(sent, enforced, reason string, delivered, seen time.Time) string {
	routes := func(digest string) string {
		if digest == "" {
			return ""
		}
		return "2"
	}
	return sent + "|" + routes(sent) + "|" + enforced + "|" + routes(enforced) + "|" + reason + "|" +
		strconv.FormatInt(delivered.UnixMilli(), 10) + "|" + strconv.FormatInt(seen.UnixMilli(), 10)
}

// A zone's count reads the Devices that hold it from its hash, a page at a
// time, and their application from the Network's; it drops the entries of
// Devices that left the index, and leaves alone what it cannot read.
// A Device the count would call offline counts only while the zone is
// still sent to it; when that cannot be read, it counts as before, and its
// entries stay in the index either way (TD-CORE-87).
func TestLoadDNSZoneApplicationAsksReceivers(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	settled := now.Add(-time.Hour)
	stillThere, err := node.ParseID("01890f00-0000-7000-8000-00000000d1c1")
	if err != nil {
		t.Fatal(err)
	}
	gone, err := node.ParseID("01890f00-0000-7000-8000-00000000d1c2")
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]any{
		"online":            applicationEntry(testDigestText, testDigestText, "", settled, now),
		stillThere.String(): applicationEntry(testDigestText, testDigestText, "", settled, now.Add(-time.Hour)),
		gone.String():       applicationEntry(testDigestText, testDigestText, "", settled, now.Add(-time.Hour)),
	}
	pruned := false
	client := &Client{
		loadDNSZone: func(context.Context, string, uint64, int) ([]string, uint64, error) {
			return []string{"online", stillThere.String(), gone.String()}, 0, nil
		},
		loadDNSApply: func(_ context.Context, _ string, fields []string) ([]any, error) {
			values := make([]any, len(fields))
			for index, field := range fields {
				values[index] = entries[field]
			}
			return values, nil
		},
		pruneDNSIndex: func(context.Context, string, string, []dnsIndexEntry) error {
			pruned = true
			return nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	var asked []node.ID
	receivers := func(_ context.Context, devices []node.ID) (map[node.ID]struct{}, error) {
		asked = devices
		return map[node.ID]struct{}{stillThere: {}}, nil
	}
	counts, err := client.LoadDNSZoneApplication(t.Context(), testNetworkID(t), ".", now, receivers)
	if err != nil {
		t.Fatal(err)
	}
	if counts != (distribution.DNSZoneApplication{Enforced: 1, Offline: 1}) || len(asked) != 2 || pruned {
		t.Fatalf("counts %+v, asked %v, pruned %v", counts, asked, pruned)
	}
	failing := func(context.Context, []node.ID) (map[node.ID]struct{}, error) {
		return nil, errors.New("database down")
	}
	counts, err = client.LoadDNSZoneApplication(t.Context(), testNetworkID(t), ".", now, failing)
	if err != nil || counts != (distribution.DNSZoneApplication{Enforced: 1, Offline: 2}) {
		t.Fatalf("receivers down: %+v %v", counts, err)
	}
}

// Receivers are asked a batch at a time, and not again once they failed.
func TestCountReceiversBatches(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	offline := distribution.DNSApplication{SeenAt: now.Add(-time.Hour)}
	entries := make([]offlineDNSEntry, distribution.DNSZoneReceiversBatch+500)
	for index := range entries {
		entries[index] = offlineDNSEntry{node: node.ID(testPublicID(t, index)), application: offline}
	}
	var sizes []int
	keepNone := func(_ context.Context, devices []node.ID) (map[node.ID]struct{}, error) {
		sizes = append(sizes, len(devices))
		return map[node.ID]struct{}{}, nil
	}
	var counts distribution.DNSZoneApplication
	if !countReceivers(t.Context(), &counts, entries, keepNone, now) ||
		!slices.Equal(sizes, []int{distribution.DNSZoneReceiversBatch, 500}) || counts.Offline != 0 {
		t.Fatalf("sizes %v counts %+v", sizes, counts)
	}
	calls := 0
	failing := func(context.Context, []node.ID) (map[node.ID]struct{}, error) {
		calls++
		return nil, errors.New("database down")
	}
	counts = distribution.DNSZoneApplication{}
	if countReceivers(t.Context(), &counts, entries, failing, now) || calls != 1 || counts.Offline != len(entries) {
		t.Fatalf("calls %d counts %+v", calls, counts)
	}
}

func TestLoadDNSZoneApplication(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	settled := now.Add(-time.Hour)
	other := "sha256:" + string(slices.Repeat([]byte("a"), 64))
	gone := applicationEntry(testDigestText, testDigestText, "", settled, now.Add(-dnsIndexTTL-time.Hour))
	entries := map[string]any{
		"enforced": applicationEntry(testDigestText, testDigestText, "", settled, now),
		"off":      applicationEntry(testDigestText, "", distribution.DNSReasonUserOff, settled, now),
		"mismatch": applicationEntry(testDigestText, other, "", settled, now),
		"offline":  applicationEntry(testDigestText, testDigestText, "", settled, now.Add(-time.Hour)),
		"gone":     gone,
		"future":   "x|y",
	}
	pages := [][]string{{"enforced", "off", "mismatch"}, {"offline", "gone", "future", "missing", "enforced"}}
	var pruned []dnsIndexEntry
	var zoneKey, applyKey, pruneZone, pruneApply string
	var cursors []uint64
	client := &Client{
		loadDNSZone: func(_ context.Context, key string, cursor uint64, count int) ([]string, uint64, error) {
			zoneKey, cursors = key, append(cursors, cursor)
			if count != dnsApplyBatch {
				t.Errorf("count %d", count)
			}
			if cursor == 0 {
				return slices.Clone(pages[0]), 7, nil
			}
			return slices.Clone(pages[1]), 0, nil
		},
		loadDNSApply: func(_ context.Context, key string, fields []string) ([]any, error) {
			applyKey = key
			values := make([]any, len(fields))
			for index, field := range fields {
				values[index] = entries[field]
			}
			return values, nil
		},
		pruneDNSIndex: func(_ context.Context, zone, apply string, stale []dnsIndexEntry) error {
			pruneZone, pruneApply, pruned = zone, apply, stale
			return nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	networkID := testNetworkID(t)
	counts, err := client.LoadDNSZoneApplication(t.Context(), networkID, ".", now, nil)
	if err != nil {
		t.Fatal(err)
	}
	// "enforced" is listed twice by the scan and counted once.
	want := distribution.DNSZoneApplication{Enforced: 1, UserOff: 1, Mismatch: 1, Offline: 1}
	if counts != want || zoneKey != dnsZoneKey(networkID, ".") || applyKey != dnsApplyKey(networkID) ||
		!slices.Equal(cursors, []uint64{0, 7}) {
		t.Fatalf("counts %+v (want %+v), keys %q %q, cursors %v", counts, want, zoneKey, applyKey, cursors)
	}
	if pruneZone != zoneKey || pruneApply != applyKey ||
		!slices.Equal(pruned, []dnsIndexEntry{{node: "gone", apply: gone}, {node: "missing"}}) {
		t.Fatalf("pruned %+v", pruned)
	}
	client.loadDNSZone = func(context.Context, string, uint64, int) ([]string, uint64, error) {
		return nil, 0, errors.New("redis down")
	}
	if _, err := client.LoadDNSZoneApplication(t.Context(), networkID, ".", now, nil); !errors.Is(err, ErrLoadDNSIndex) {
		t.Fatalf("redis down: %v", err)
	}
	if _, err := client.LoadDNSZoneApplication(t.Context(), network.ID{}, ".", now, nil); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("no Network: %v", err)
	}
}

func TestCountResolverHealth(t *testing.T) {
	t.Parallel()
	now := time.Now()
	resolvers := []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53"), netip.MustParseAddrPort("100.64.0.9:5335")}
	var gotKeys []string
	var gotSince int64
	client := &Client{
		countDNSHealth: func(_ context.Context, keys []string, since int64) ([]int64, error) {
			gotKeys, gotSince = keys, since
			return []int64{3, 0, 0, 1, 0, 0, 2, 1, 0, 4}, nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	networkID := testNetworkID(t)
	counts, err := client.CountResolverHealth(t.Context(), networkID, resolvers, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotKeys) != 10 || gotKeys[0] != dnsHealthKey(networkID, resolvers[0], distribution.ResolverOK) ||
		gotKeys[9] != dnsHealthKey(networkID, resolvers[1], distribution.ResolverIdle) ||
		gotSince != now.Add(-distribution.DNSHealthStale).UnixMilli() {
		t.Fatalf("keys %v since %d", gotKeys, gotSince)
	}
	if counts[0] != (distribution.ResolverHealthCount{Resolver: resolvers[0], OK: 3, Refusing: 1}) ||
		counts[1] != (distribution.ResolverHealthCount{Resolver: resolvers[1], Broken: 2, Stopped: 1, Idle: 4}) {
		t.Fatalf("counts %+v", counts)
	}
	if counts, err := client.CountResolverHealth(t.Context(), networkID, nil, now); err != nil || counts != nil {
		t.Fatalf("no resolvers: %v, %v", counts, err)
	}
	if _, err := client.CountResolverHealth(t.Context(), networkID,
		[]netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), 0)}, now); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("no port: %v", err)
	}
}

// testPublicID is a distinct UUIDv7 for index.
func testPublicID(t *testing.T, index int) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(fmt.Sprintf("01890f00-0000-7000-8000-%012x", index+1))
	if err != nil {
		t.Fatal(err)
	}
	return id
}
