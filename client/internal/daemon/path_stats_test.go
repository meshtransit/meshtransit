package daemon

import (
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/networkmap"
)

func TestPathStatsSampler(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_800_000_000, 0)
	sampler := newPathStatsSampler(start)
	sampler.observe(networkmap.Snapshot{Peers: []networkmap.Node{
		{ID: 1, StableID: "direct-peer", Endpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.1:41641")}},
		{ID: 2, StableID: "relayed-peer", Endpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.2:41641")}},
		{ID: 3, StableID: "no-candidates"},
	}})
	sampler.sample([]dataplane.PeerPathStat{
		{PeerID: 1, Path: dataplane.PeerPathDirectUDP, TxBytes: 1000, RxBytes: 2000},
		{PeerID: 2, Path: dataplane.PeerPathRelayed, RelayRegion: 1, RelaySince: start, TxBytes: 10, RxBytes: 20},
		{PeerID: 3, Path: dataplane.PeerPathRelayed, RelayRegion: 1, RelaySince: start},
		{PeerID: 9, Path: dataplane.PeerPathDirectUDP}, // not in the map
	}, start.Add(10*time.Second))
	// The first sample only sets the baseline; the second carries traffic.
	sampler.sample([]dataplane.PeerPathStat{
		{PeerID: 1, Path: dataplane.PeerPathDirectUDP, TxBytes: 1500, RxBytes: 2600},
		{PeerID: 2, Path: dataplane.PeerPathRelayed, RelayRegion: 1, RelaySince: start, TxBytes: 110, RxBytes: 220},
		{PeerID: 3, Path: dataplane.PeerPathRelayed, RelayRegion: 1, RelaySince: start},
	}, start.Add(60*time.Second))
	report := sampler.report(start.Add(60 * time.Second))
	if report.Interval != time.Minute || !report.IntervalStart.Equal(start) || len(report.Peers) != 3 {
		t.Fatalf("report %+v", report)
	}
	byID := map[string]controlplane.PeerPathStats{}
	for _, peer := range report.Peers {
		byID[peer.DeviceID] = peer
	}
	direct, relayed, none := byID["direct-peer"], byID["relayed-peer"], byID["no-candidates"]
	if direct.Path != controlplane.PathDirect || direct.DirectTxBytes != 500 || direct.DirectRxBytes != 600 ||
		direct.RelayTxBytes != 0 {
		t.Fatalf("direct peer %+v", direct)
	}
	if relayed.Path != controlplane.PathRelay || relayed.RelayRegion != 1 || relayed.RelayTxBytes != 100 ||
		relayed.RelayReason != controlplane.RelayNoResponse {
		t.Fatalf("relayed peer %+v", relayed)
	}
	if none.RelayReason != controlplane.RelayNoCandidates {
		t.Fatalf("peer without candidates %+v", none)
	}
	// A new interval starts at zero; a counter that went back (a new tunnel)
	// counts nothing instead of wrapping.
	sampler.sample([]dataplane.PeerPathStat{{PeerID: 1, Path: dataplane.PeerPathDirectUDP, TxBytes: 5, RxBytes: 5}},
		start.Add(70*time.Second))
	next := sampler.report(start.Add(120 * time.Second))
	for _, peer := range next.Peers {
		if peer.DirectTxBytes != 0 || peer.RelayTxBytes != 0 {
			t.Fatalf("next interval %+v", peer)
		}
	}
	// A peer that leaves the map leaves the report.
	sampler.observe(networkmap.Snapshot{Peers: []networkmap.Node{{ID: 1, StableID: "direct-peer"}}})
	if got := sampler.report(start.Add(180 * time.Second)); len(got.Peers) != 1 {
		t.Fatalf("after the map changed: %d peers", len(got.Peers))
	}
}

func TestRelayBootstrapReason(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_800_000_000, 0)
	sampler := newPathStatsSampler(start)
	sampler.observe(networkmap.Snapshot{Peers: []networkmap.Node{
		{ID: 1, StableID: "peer", Endpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.1:41641")}},
	}})
	sampler.sample([]dataplane.PeerPathStat{{
		PeerID: 1, Path: dataplane.PeerPathRelayed, RelayRegion: 2,
		RelaySince: start,
	}}, start.Add(5*time.Second))
	if reason := sampler.report(start.Add(10 * time.Second)).Peers[0].RelayReason; reason != controlplane.RelayBootstrap {
		t.Fatalf("reason %v, want bootstrap", reason)
	}
}
