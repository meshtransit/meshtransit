package redis

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/shared/dnsdigest"
)

func TestClientRecordsDNSHealthForItsSession(t *testing.T) {
	t.Parallel()
	nodeID := testDeliveryNode(t)
	session := []any{nodeID.String(), "4", hex.EncodeToString(testMachine[:])}
	var gotKey, gotEncoded string
	var gotGeneration, gotAt int64
	client := &Client{
		loadSession: func(context.Context, string) ([]any, error) { return session, nil },
		recordDNSHealth: func(_ context.Context, key string, generation int64, encoded string, at int64,
			ttl time.Duration) (int64, error) {
			if ttl != deliveryTTL {
				t.Errorf("ttl = %s", ttl)
			}
			gotKey, gotGeneration, gotEncoded, gotAt = key, generation, encoded, at
			return 1, nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	reported := time.UnixMilli(1792737000000)
	health := mapsession.DNSHealth{NodeKey: testNodeKey, MachineFingerprint: testMachine, ReportedAt: reported,
		Resolvers: []mapsession.ResolverHealth{
			{Resolver: netip.MustParseAddrPort("100.64.0.21:5335"), State: mapsession.ResolverOK,
				LastOK: time.UnixMilli(1792736990000)},
			{Resolver: netip.MustParseAddrPort("[2001:db8::53]:53"), State: mapsession.ResolverIdle},
		}}
	stored, err := client.RecordDNSHealth(t.Context(), health)
	if err != nil || !stored || gotKey != deliveryKeyForNode(nodeID) || gotGeneration != 4 ||
		gotAt != reported.UnixMilli() ||
		gotEncoded != `[["100.64.0.21:5335","ok","1792736990000"],["[2001:db8::53]:53","idle","0"]]` {
		t.Fatalf("RecordDNSHealth() = %t, %v; %s %d %s", stored, err, gotKey, gotGeneration, gotEncoded)
	}
	other := health
	other.MachineFingerprint = [32]byte{0x55}
	gotKey = ""
	if stored, err := client.RecordDNSHealth(t.Context(), other); err != nil || stored || gotKey != "" {
		t.Fatalf("other machine = %t, %v, wrote %q", stored, err, gotKey)
	}
	invalid := health
	invalid.Resolvers = append(invalid.Resolvers, invalid.Resolvers[0])
	if _, err := client.RecordDNSHealth(t.Context(), invalid); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("invalid health = %v", err)
	}
}

// The DNS digest sent and the one a node applied, with its reason, reach
// the delivery and enforcement records.
func TestClientRecordsDNSDigests(t *testing.T) {
	t.Parallel()
	nodeID := testDeliveryNode(t)
	raw, routes, err := dnsdigest.Compute([]dnsdigest.Route{{Suffix: "."}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dns, err := mapsession.NewDNSDigest(raw, routes)
	if err != nil {
		t.Fatal(err)
	}
	var gotDelivery deliveryRecord
	var gotEnforcement enforcementRecord
	session := []any{nodeID.String(), "4", hex.EncodeToString(testMachine[:])}
	client := &Client{
		recordDelivery: func(_ context.Context, _, _ string, record deliveryRecord, _ time.Duration) (int64, error) {
			gotDelivery = record
			return 1, nil
		},
		loadSession: func(context.Context, string) ([]any, error) { return session, nil },
		recordEnforcement: func(_ context.Context, _ string, record enforcementRecord, _ time.Duration) (int64, error) {
			gotEnforcement = record
			return 1, nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	at := time.Date(2026, time.October, 23, 12, 0, 0, 0, time.UTC)
	delivery := mapsession.Delivery{NodeID: nodeID, NodeKey: testNodeKey, MachineFingerprint: testMachine,
		SessionGeneration: 4, NetworkRevision: 9, DeliveredAt: at, DNS: dns}
	if err := client.RecordDelivery(t.Context(), delivery); err != nil || gotDelivery.dnsDigest != raw.String() ||
		gotDelivery.dnsRoutes != "1" {
		t.Fatalf("delivery = %+v, %v", gotDelivery, err)
	}
	enforcement := mapsession.Enforcement{NodeKey: testNodeKey, MachineFingerprint: testMachine,
		Filter: testFilterDigest(t, 1), DNS: dns, AppliedAt: at, ReportedAt: at}
	if stored, err := client.RecordEnforcement(t.Context(), enforcement); err != nil || !stored ||
		gotEnforcement.dnsDigest != raw.String() || gotEnforcement.dnsRoutes != "1" || gotEnforcement.dnsReason != "" {
		t.Fatalf("enforcement = %+v, %t, %v", gotEnforcement, stored, err)
	}
	enforcement.DNS, enforcement.DNSReason = mapsession.DNSDigest{}, mapsession.DNSUserOff
	if stored, err := client.RecordEnforcement(t.Context(), enforcement); err != nil || !stored ||
		gotEnforcement.dnsDigest != "" || gotEnforcement.dnsReason != mapsession.DNSUserOff {
		t.Fatalf("enforcement without DNS = %+v, %t, %v", gotEnforcement, stored, err)
	}
}
