//go:build integration

package integration

import (
	"context"
	"net/netip"
	"testing"
	"time"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/shared/dnsdigest"
)

// assertRedisDNSEvidence qualifies the DNS evidence of the delivery Lua
// scripts against real Redis (DNS design D1b §8, §9): the DNS digest sent,
// the one applied and its reason, and resolver health are stored for the
// session generation that owns the record, read back, and gone with a new
// generation.
func assertRedisDNSEvidence(ctx context.Context, t *testing.T, client *redisadapter.Client) {
	t.Helper()
	nodeID, err := node.ParseID("01890f00-0000-7000-8000-000000013501")
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, machine := node.Key{0x13, 0x50}, [32]byte{0x13, 0x51}
	raw, routes, err := dnsdigest.Compute([]dnsdigest.Route{{Suffix: ".", Unavailable: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := mapsession.NewDNSDigest(raw, routes)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Millisecond)
	deliver := func(generation int64, dns mapsession.DNSDigest) {
		t.Helper()
		if err := client.RecordDelivery(ctx, mapsession.Delivery{NodeID: nodeID, NodeKey: nodeKey,
			MachineFingerprint: machine, SessionGeneration: generation, NetworkRevision: 3, PolicyRevision: 1,
			DeliveredAt: at, DNS: dns}); err != nil {
			t.Fatalf("RecordDelivery(%d) error = %v", generation, err)
		}
	}
	load := func() distribution.Observation {
		t.Helper()
		observations, err := client.LoadObservations(ctx, []node.ID{nodeID})
		if err != nil || len(observations) != 1 {
			t.Fatalf("LoadObservations() = %v, %v", observations, err)
		}
		return observations[0]
	}
	deliver(4, digest)
	filter, err := mapsession.NewFilterDigest(raw, 1)
	if err != nil {
		t.Fatal(err)
	}
	if stored, err := client.RecordEnforcement(ctx, mapsession.Enforcement{NodeKey: nodeKey,
		MachineFingerprint: machine, Filter: filter, DNS: digest, AppliedAt: at, ReportedAt: at}); err != nil || !stored {
		t.Fatalf("RecordEnforcement() = %t, %v", stored, err)
	}
	resolver := netip.MustParseAddrPort("100.64.0.21:5335")
	if stored, err := client.RecordDNSHealth(ctx, mapsession.DNSHealth{NodeKey: nodeKey, MachineFingerprint: machine,
		ReportedAt: at, Resolvers: []mapsession.ResolverHealth{{Resolver: resolver, State: mapsession.ResolverRefusing}},
	}); err != nil || !stored {
		t.Fatalf("RecordDNSHealth() = %t, %v", stored, err)
	}
	observation := load()
	if observation.DNS.Digest != raw || observation.DNS != observation.EnforcedDNS || observation.DNSReason != "" ||
		len(observation.DNSHealth) != 1 || observation.DNSHealth[0].Resolver != resolver ||
		observation.DNSHealth[0].State != distribution.ResolverRefusing || !observation.DNSHealthAt.Equal(at) {
		t.Fatalf("DNS evidence = %+v", observation)
	}
	if stored, err := client.RecordEnforcement(ctx, mapsession.Enforcement{NodeKey: nodeKey,
		MachineFingerprint: machine, Filter: filter, DNSReason: mapsession.DNSUserOff, AppliedAt: at,
		ReportedAt: at}); err != nil || !stored {
		t.Fatalf("RecordEnforcement(user_off) = %t, %v", stored, err)
	}
	if observation := load(); !observation.EnforcedDNS.IsZero() || observation.DNSReason != distribution.DNSReasonUserOff {
		t.Fatalf("after user_off = %+v", observation)
	}
	// A new generation starts without the node's evidence.
	deliver(5, mapsession.DNSDigest{})
	if observation := load(); !observation.DNS.IsZero() || !observation.EnforcedDNS.IsZero() ||
		observation.DNSReason != "" || observation.DNSHealth != nil {
		t.Fatalf("new generation kept DNS evidence = %+v", observation)
	}
	// Health for another machine is refused.
	if stored, err := client.RecordDNSHealth(ctx, mapsession.DNSHealth{NodeKey: nodeKey, MachineFingerprint: [32]byte{1},
		ReportedAt: at}); err != nil || stored {
		t.Fatalf("RecordDNSHealth(other machine) = %t, %v", stored, err)
	}
}
