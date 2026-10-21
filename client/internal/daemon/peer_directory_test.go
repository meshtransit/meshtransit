package daemon

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/peerprobe"
)

type fakeMeasurer struct {
	roundTrip peerprobe.RoundTrip
	err       error
	measured  []uint64
}

func (m *fakeMeasurer) MeasureRoundTrip(_ context.Context, peerID uint64) (peerprobe.RoundTrip, error) {
	m.measured = append(m.measured, peerID)
	return m.roundTrip, m.err
}

func directorySnapshot() networkmap.Snapshot {
	return networkmap.Snapshot{
		Relays: map[int]networkmap.RelayRegion{1: {ID: 1, Code: "sin"}, 2: {ID: 2, Code: "fra"}},
		Peers: []networkmap.Node{
			{
				ID: 10, StableID: "dev-direct", Name: "poc-01.mesh.example", HomeRelay: 1, DiscoveryKey: "disco:10",
				Addresses:   []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32"), netip.MustParsePrefix("fd7a::10/128")},
				OnlineKnown: true, Online: true,
			},
			{
				ID: 11, StableID: "dev-relay", Name: "poc-02.mesh.example", HomeRelay: 2, OnlineKnown: true,
				DiscoveryKey: "disco:11",
			},
			{ID: 12, StableID: "dev-lazy", Name: "laptop.mesh.example", HomeRelay: 1, Online: true},
			{ID: 13, StableID: "dev-pending", Name: "phone.mesh.example"},
			{ID: 14, Name: "no-stable-id"},
			{ID: 15, StableID: "dev-direct", Name: "duplicate"},
		},
	}
}

func TestPeerViewsJoinTheMapWithThePaths(t *testing.T) {
	t.Parallel()

	directory := newPeerDirectory(directorySnapshot())
	views := peerViews(directory, []dataplane.PeerPathStat{
		{PeerID: 10, Path: dataplane.PeerPathDirectUDP, RxBytes: 100, TxBytes: 50},
		{PeerID: 11, Path: dataplane.PeerPathRelayed, RelayRegion: 2},
		{PeerID: 13, Path: dataplane.PeerPathUnknown},
		{PeerID: 99, Path: dataplane.PeerPathDirectUDP},
	})
	want := []PeerView{
		{
			DeviceID: "dev-direct", Name: "poc-01.mesh.example", Addresses: []string{"100.64.0.10", "fd7a::10"},
			OnlineKnown: true, Online: true, Path: PeerPathDirect, RxBytes: 100, TxBytes: 50, Measurable: true,
		},
		{
			DeviceID: "dev-relay", Name: "poc-02.mesh.example", Addresses: []string{}, OnlineKnown: true,
			Path: PeerPathRelay, RelayRegion: "fra", Measurable: true,
		},
		// Online without OnlineKnown is not reported as online.
		{DeviceID: "dev-lazy", Name: "laptop.mesh.example", Addresses: []string{}, Path: PeerPathInactive},
		{DeviceID: "dev-pending", Name: "phone.mesh.example", Addresses: []string{}, Path: PeerPathPending},
	}
	if !slices.EqualFunc(views, want, peerViewEqual) {
		t.Fatalf("peerViews() =\n%#v\nwant\n%#v", views, want)
	}
	// Views are copies: changing one leaves the directory alone.
	views[0].Addresses[0] = "changed"
	if again := peerViews(directory, nil); again[0].Addresses[0] != "100.64.0.10" {
		t.Fatalf("the directory changed through a view: %v", again[0].Addresses)
	}
	if views := peerViews(nil, nil); views == nil || len(views) != 0 {
		t.Fatalf("peerViews(nil) = %#v, want an empty list", views)
	}
}

func peerViewEqual(a, b PeerView) bool {
	return a.DeviceID == b.DeviceID && a.Name == b.Name && slices.Equal(a.Addresses, b.Addresses) &&
		a.OnlineKnown == b.OnlineKnown && a.Online == b.Online && a.Path == b.Path &&
		a.RelayRegion == b.RelayRegion && a.RxBytes == b.RxBytes && a.TxBytes == b.TxBytes &&
		a.Measurable == b.Measurable
}

func TestPingPeerMeasuresAPeerOfTheCurrentMap(t *testing.T) {
	t.Parallel()

	service := &Service{}
	if _, err := service.PingPeer(t.Context(), "dev-direct"); !errors.Is(err, ErrPeerTestUnavailable) {
		t.Fatalf("without a session: error = %v", err)
	}
	measurer := &fakeMeasurer{roundTrip: peerprobe.RoundTrip{Duration: 12 * time.Millisecond}}
	service.peerSession.setDirectory(newPeerDirectory(directorySnapshot()))
	service.peerSession.setMeasurer(measurer)

	ping, err := service.PingPeer(t.Context(), "dev-direct")
	if err != nil || ping != (PeerPing{RoundTrip: 12 * time.Millisecond, Path: PeerPathDirect}) {
		t.Fatalf("PingPeer(direct) = %#v, %v", ping, err)
	}
	// A relayed sample names the peer's home relay region.
	measurer.roundTrip = peerprobe.RoundTrip{Duration: 80 * time.Millisecond, Relayed: true}
	ping, err = service.PingPeer(t.Context(), "dev-relay")
	if err != nil || ping != (PeerPing{RoundTrip: 80 * time.Millisecond, Path: PeerPathRelay, RelayRegion: "fra"}) {
		t.Fatalf("PingPeer(relay) = %#v, %v", ping, err)
	}
	if !slices.Equal(measurer.measured, []uint64{10, 11}) {
		t.Fatalf("measured peers %v", measurer.measured)
	}
	if _, err := service.PingPeer(t.Context(), "dev-unknown"); !errors.Is(err, ErrPeerNotFound) {
		t.Fatalf("unknown Device: error = %v", err)
	}
	// No discovery key: no disco with it, so no measurement at all.
	if _, err := service.PingPeer(t.Context(), "dev-pending"); !errors.Is(err, ErrPeerNotMeasurable) {
		t.Fatalf("Device without a discovery key: error = %v", err)
	}
	if !slices.Equal(measurer.measured, []uint64{10, 11}) {
		t.Fatalf("a peer that cannot be measured was measured: %v", measurer.measured)
	}
	measurer.err = peerprobe.ErrNoAnswer
	if _, err := service.PingPeer(t.Context(), "dev-direct"); !errors.Is(err, peerprobe.ErrNoAnswer) {
		t.Fatalf("no answer: error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := service.PingPeer(ctx, "dev-direct"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: error = %v", err)
	}
}

func TestPeersListsTheCurrentMap(t *testing.T) {
	t.Parallel()

	service := &Service{}
	views, err := service.Peers(t.Context())
	if err != nil || len(views) != 0 {
		t.Fatalf("Peers() without a map = %#v, %v", views, err)
	}
	service.peerSession.setDirectory(newPeerDirectory(directorySnapshot()))
	views, err = service.Peers(t.Context())
	if err != nil || len(views) != 4 || views[0].DeviceID != "dev-direct" {
		t.Fatalf("Peers() = %#v, %v", views, err)
	}
}
