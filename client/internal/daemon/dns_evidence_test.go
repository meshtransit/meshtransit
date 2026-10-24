package daemon

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/dnsdigest"
	"meshtransit.net/shared/policydigest"
)

// The digest meshd reports is DNS digest v1 of the map as the node kept it:
// the vector of docs/protocol/dns-digest-v1.md.
func TestDigestDNSIsTheSpecVector(t *testing.T) {
	t.Parallel()
	config := &networkmap.DNSConfig{
		Routes: []networkmap.DNSRoute{
			{Suffix: "073438549244.296056403058.mesh.internal"},
			{Suffix: "corp.internal", FailOpen: true, Resolvers: []networkmap.DNSResolver{
				{Address: netip.MustParseAddrPort("100.64.0.21:5335")},
				{Address: netip.MustParseAddrPort("192.0.2.53:53")},
			}},
			{Suffix: ".", Unavailable: true},
		},
		SearchDomains: []string{"073438549244.296056403058.mesh.internal", "corp.internal"},
		// Records and the host's resolvers are no part of the digest.
		Resolvers: []networkmap.DNSResolver{{Address: netip.MustParseAddrPort("1.1.1.1:53")}},
	}
	digest, routes, err := digestDNS(config)
	const want = "sha256:e0ade8e76caf31f2f615616fa198aeb45a96511e0161cb2d055923f995c63504"
	if err != nil || digest.String() != want || routes != 3 {
		t.Fatalf("digestDNS = %s over %d routes, %v; want %s", digest, routes, err, want)
	}
	empty, _, err := digestDNS(nil)
	none, _, _ := dnsdigest.Compute(nil, nil)
	if err != nil || empty != none {
		t.Fatalf("digestDNS(nil) = %s, %v", empty, err)
	}
}

type userChoiceDNS struct {
	DNSController
	meshDNS bool
}

func (dns *userChoiceDNS) UsesMeshDNS() bool { return dns.meshDNS }

func TestAppliedDNSEvidence(t *testing.T) {
	t.Parallel()
	snapshot := networkmap.Snapshot{DNS: &networkmap.DNSConfig{Routes: []networkmap.DNSRoute{{
		Suffix:    "corp.internal",
		Resolvers: []networkmap.DNSResolver{{Address: netip.MustParseAddrPort("192.0.2.53:53")}},
	}}}}
	applied := (&Service{dns: &userChoiceDNS{meshDNS: true}}).appliedDNSEvidence(snapshot)
	if !applied.known || applied.digest.IsZero() || applied.routes != 1 || applied.reason != "" {
		t.Fatalf("applied evidence %+v", applied)
	}
	off := (&Service{dns: &userChoiceDNS{meshDNS: false}}).appliedDNSEvidence(snapshot)
	if off != (dnsEvidence{known: true, reason: dnsReasonUserOff}) {
		t.Fatalf("evidence with DNS turned off %+v", off)
	}
	invalid := networkmap.Snapshot{DNS: &networkmap.DNSConfig{Routes: []networkmap.DNSRoute{{Suffix: "Not Canonical"}}}}
	if got := (&Service{}).appliedDNSEvidence(invalid); got.known {
		t.Fatalf("evidence of a configuration the digest cannot represent %+v", got)
	}
}

func TestWithDNSEvidence(t *testing.T) {
	t.Parallel()
	report := controlplane.EnforcementReport{Digest: policydigest.Digest{1}}
	if got := withDNSEvidence(report, dnsEvidence{}); got.DNSKnown {
		t.Fatalf("unknown evidence reported %+v", got)
	}
	got := withDNSEvidence(report, dnsEvidence{known: true, digest: dnsdigest.Digest{2}, routes: 3})
	if !got.DNSKnown || got.DNSDigest != (dnsdigest.Digest{2}) || got.DNSRoutes != 3 || got.Digest != report.Digest {
		t.Fatalf("report %+v", got)
	}
}

// New evidence is handed to Core at once; the same evidence again is not.
func TestRecordDNSEvidenceRepublishesOnChange(t *testing.T) {
	t.Parallel()
	service := &Service{}
	republished := 0
	service.setDNSRepublish(func() { republished++ })
	evidence := dnsEvidence{known: true, reason: dnsReasonApplyFailed}
	service.recordDNSEvidence(evidence)
	service.recordDNSEvidence(evidence)
	if republished != 1 || service.currentDNSEvidence() != evidence {
		t.Fatalf("republished %d times, evidence %+v", republished, service.currentDNSEvidence())
	}
	service.setDNSRepublish(nil)
	service.recordDNSEvidence(dnsEvidence{})
	if republished != 1 || service.currentDNSEvidence().known {
		t.Fatal("evidence went to a session that ended")
	}
}

func TestInfrastructureNames(t *testing.T) {
	t.Parallel()
	snapshot := networkmap.Snapshot{Relays: map[int]networkmap.RelayRegion{
		1: {Nodes: []networkmap.RelayNode{{HostName: "relay-sg.meshtransit.net"}, {IPv4: "203.0.113.9"}}},
		2: {Nodes: []networkmap.RelayNode{{HostName: "relay-sg.meshtransit.net"}, {HostName: "relay-de.meshtransit.net"}}},
	}}
	got := infrastructureNames("https://control.meshtransit.net:443/path", snapshot)
	want := []string{"control.meshtransit.net", "relay-de.meshtransit.net", "relay-sg.meshtransit.net"}
	if slices.Sort(got[1:]); !slices.Equal(got, want) {
		t.Fatalf("infrastructure names %v, want %v", got, want)
	}
	if got := infrastructureNames("://", networkmap.Snapshot{}); len(got) != 0 {
		t.Fatalf("names of an invalid control URL %v", got)
	}
}

type measuredDNS struct{ health []controlplane.ResolverHealth }

func (dns measuredDNS) ResolverHealth() ([]controlplane.ResolverHealth, bool) {
	return dns.health, true
}

func TestPublishDNSHealthOffersTheLatest(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("waits for the first interval")
	}
	health := []controlplane.ResolverHealth{{
		Resolver: netip.MustParseAddrPort("1.1.1.1:53"),
		State:    controlplane.ResolverOK,
	}}
	updates := make(chan []controlplane.ResolverHealth, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); publishDNSHealth(ctx, measuredDNS{health}, updates) }()
	select {
	case got := <-updates:
		if !slices.Equal(got, health) {
			t.Fatalf("published %v", got)
		}
	case <-time.After(dnsHealthInterval + 5*time.Second):
		t.Fatal("no resolver health after the first interval")
	}
	cancel()
	<-done
}

// A DNS controller that applies the last map again on a change of its own
// (Android) has the evidence recorded and handed to Core at once.
func TestReappliedDNSRecordsTheChoice(t *testing.T) {
	t.Parallel()
	dns := &userChoiceDNS{meshDNS: false}
	service := &Service{dns: dns}
	service.syncState.state = ControlSessionSynchronized
	republished := 0
	service.setDNSRepublish(func() { republished++ })
	snapshot := networkmap.Snapshot{DNS: &networkmap.DNSConfig{SearchDomains: []string{"corp.internal"}}}
	service.reappliedDNS(snapshot, false, nil)
	if got := service.currentDNSEvidence(); got != (dnsEvidence{known: true, reason: dnsReasonUserOff}) ||
		service.syncState.dns != DNSInactive {
		t.Fatalf("turned off: %+v, status %q", got, service.syncState.dns)
	}
	dns.meshDNS = true
	service.reappliedDNS(snapshot, true, nil)
	if got := service.currentDNSEvidence(); !got.known || got.digest.IsZero() || got.reason != "" ||
		service.syncState.dns != DNSConfigured {
		t.Fatalf("turned on: %+v, status %q", got, service.syncState.dns)
	}
	service.reappliedDNS(snapshot, false, errors.New("host refused"))
	if got := service.currentDNSEvidence(); got.reason != dnsReasonApplyFailed || republished != 3 ||
		service.syncState.dns != DNSFailed || service.currentDNSFailure(DNSFailed) != "host refused" {
		t.Fatalf("failed: %+v, republished %d, status %q", got, republished, service.syncState.dns)
	}
}
