package mapsession

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/shared/dnsdigest"
)

type recordingDNSHealthRecorder struct {
	recordingEnforcementRecorder
	dnsHealth []DNSHealth
}

func (recorder *recordingDNSHealthRecorder) RecordDNSHealth(ctx context.Context, health DNSHealth) (bool, error) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if _, bounded := ctx.Deadline(); !bounded {
		return false, errors.New("unbounded dns health record")
	}
	recorder.dnsHealth = append(recorder.dnsHealth, health)
	return !recorder.stale, nil
}

func testDNSDigest(t *testing.T) DNSDigest {
	t.Helper()
	raw, routes, err := dnsdigest.Compute([]dnsdigest.Route{{Suffix: "."}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := NewDNSDigest(raw, routes)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// An enforcement report carries a DNS digest with no reason, or a known
// reason with no digest (mtcp-v1 §8.4).
func TestReportEnforcementDNSEvidence(t *testing.T) {
	t.Parallel()
	initial, _, _ := authorityDeltaSnapshotsFixture(t)
	service := newStreamServiceFixture(t, &streamSnapshotOpener{snapshots: []Snapshot{initial}}, &streamPresenceStore{})
	machine, _ := authenticatedRequestFixture(t, initial)
	filter, _ := revisionDigest(initial)
	recorder := &recordingEnforcementRecorder{}
	recorded, err := service.WithEnforcementRecorder(recorder)
	if err != nil {
		t.Fatal(err)
	}
	digest := testDNSDigest(t)
	for name, evidence := range map[string]struct {
		dns    DNSDigest
		reason string
		valid  bool
	}{
		"digest":         {dns: digest, valid: true},
		"user off":       {reason: DNSUserOff, valid: true},
		"apply failed":   {reason: DNSApplyFailed, valid: true},
		"none":           {valid: true},
		"digest, reason": {dns: digest, reason: DNSUserOff},
		"unknown reason": {reason: "made_up"},
	} {
		err := recorded.ReportEnforcement(t.Context(), machine, ClientEnforcement{
			NodeKey: initial.NodeKey(), Filter: filter, AppliedAt: time.Now(), DNS: evidence.dns, DNSReason: evidence.reason,
		})
		if evidence.valid != (err == nil) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
	if _, err := NewDNSDigest(dnsdigest.Digest{}, 0); !errors.Is(err, ErrInvalidEnforcementReport) {
		t.Fatalf("NewDNSDigest(zero) error = %v", err)
	}
}

func TestReportDNSHealthNeedsARecorderThatTakesIt(t *testing.T) {
	t.Parallel()
	initial, _, _ := authorityDeltaSnapshotsFixture(t)
	service := newStreamServiceFixture(t, &streamSnapshotOpener{snapshots: []Snapshot{initial}}, &streamPresenceStore{})
	machine, _ := authenticatedRequestFixture(t, initial)
	resolvers := []ResolverHealth{
		{Resolver: netip.MustParseAddrPort("100.64.0.21:5335"), State: ResolverOK, LastOK: time.Now().Add(time.Hour)},
		{Resolver: netip.MustParseAddrPort("192.0.2.53:53"), State: ResolverIdle},
	}
	enforcementOnly, err := service.WithEnforcementRecorder(&recordingEnforcementRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if err := enforcementOnly.ReportDNSHealth(t.Context(), machine, initial.NodeKey(), resolvers); !errors.Is(err,
		ErrEnforcementUnavailable) {
		t.Fatalf("with an enforcement-only recorder = %v", err)
	}
	recorder := &recordingDNSHealthRecorder{}
	recorded, err := service.WithEnforcementRecorder(recorder)
	if err != nil {
		t.Fatal(err)
	}
	if err := recorded.ReportDNSHealth(t.Context(), machine, initial.NodeKey(), resolvers); err != nil {
		t.Fatal(err)
	}
	stored := recorder.dnsHealth
	if len(stored) != 1 || stored[0].NodeKey != initial.NodeKey() || len(stored[0].Resolvers) != 2 ||
		stored[0].Resolvers[0].LastOK.After(stored[0].ReportedAt) || resolvers[0].LastOK.Equal(stored[0].Resolvers[0].LastOK) {
		t.Fatalf("stored = %+v", stored)
	}
	for name, invalid := range map[string][]ResolverHealth{
		"twice":         {resolvers[0], resolvers[0]},
		"unknown state": {{Resolver: resolvers[0].Resolver, State: ResolverIdle + 1}},
		"no port":       {{Resolver: netip.AddrPortFrom(resolvers[0].Resolver.Addr(), 0), State: ResolverOK}},
		"too many":      make([]ResolverHealth, MaximumResolverHealth+1),
	} {
		if err := recorded.ReportDNSHealth(t.Context(), machine, initial.NodeKey(), invalid); !errors.Is(err,
			ErrInvalidDNSHealth) {
			t.Errorf("%s: %v", name, err)
		}
	}
	recorder.stale = true
	if err := recorded.ReportDNSHealth(t.Context(), machine, initial.NodeKey(), resolvers); !errors.Is(err,
		ErrNoEnforcementStream) {
		t.Fatalf("stale session = %v", err)
	}
}

// digestStreamSink is a recording sink that reports a settable DNS digest.
type digestStreamSink struct {
	recordingStreamSink
	dnsMu sync.Mutex
	dns   DNSDigest
}

func (sink *digestStreamSink) SentDNSDigest() DNSDigest {
	sink.dnsMu.Lock()
	defer sink.dnsMu.Unlock()
	return sink.dns
}

func (sink *digestStreamSink) setDNS(digest DNSDigest) {
	sink.dnsMu.Lock()
	defer sink.dnsMu.Unlock()
	sink.dns = digest
}

// A delivery records the DNS digest of what the sink sent, and a refresh
// without a new revision records again only when that digest changed (a
// resolver Device went offline): a connectivity wakeup that leaves DNS as it
// was records nothing.
func TestStreamServiceRecordsTheDNSDigestTheSinkSent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		base, peer := snapshotWithAuthorizedPeerFixture(t)
		selfKey, err := NewConnectivityKey(base.NodeID(), base.SessionGeneration())
		if err != nil {
			t.Fatal(err)
		}
		self, err := NewConnectivity(ConnectivityParams{Key: selfKey})
		if err != nil {
			t.Fatal(err)
		}
		peerKey, err := NewConnectivityKey(peer.NodeID(), peer.SessionGeneration())
		if err != nil {
			t.Fatal(err)
		}
		offline, err := NewConnectivity(ConnectivityParams{Key: peerKey})
		if err != nil {
			t.Fatal(err)
		}
		initial, err := base.WithConnectivity([]Connectivity{self, offline})
		if err != nil {
			t.Fatal(err)
		}
		online := connectivityFixture(t, peer.NodeID(), peer.SessionGeneration(), 4, "198.51.100.2:41641", true)
		advanced, err := base.WithConnectivity([]Connectivity{self, online})
		if err != nil {
			t.Fatal(err)
		}
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, advanced, advanced}}
		connectivity := newStreamConnectivityWatcher()
		base2 := newStreamServiceWithWatchersFixture(t, opener, &streamPresenceStore{}, newStreamRevisionWatcher(),
			connectivity)
		deliveries := &recordingDeliveryRecorder{}
		service, err := base2.WithDeliveryRecorder(deliveries)
		if err != nil {
			t.Fatal(err)
		}
		first := testDNSDigest(t)
		raw, routes, err := dnsdigest.Compute([]dnsdigest.Route{{Suffix: ".", Unavailable: true}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		second, err := NewDNSDigest(raw, routes)
		if err != nil {
			t.Fatal(err)
		}
		sink := &digestStreamSink{dns: first}
		machine, request := authenticatedRequestFixture(t, initial)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, sink) }()
		synctest.Wait()
		wake := func() {
			t.Helper()
			change, err := NewConnectivityChanged(initial.Scope().NetworkID(), peer.NodeID(), peer.SessionGeneration(),
				ConnectivityChangeEndpoints)
			if err != nil {
				t.Fatal(err)
			}
			connectivity.send(t, change)
			synctest.Wait()
		}
		sink.setDNS(second)
		wake()
		wake() // the digest stays: nothing more is recorded
		recorded, _ := deliveries.state()
		if len(recorded) != 2 || recorded[0].DNS != first || recorded[1].DNS != second ||
			recorded[1].NetworkRevision != recorded[0].NetworkRevision {
			t.Fatalf("deliveries = %+v", recorded)
		}
		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v", err)
		}
	})
}
