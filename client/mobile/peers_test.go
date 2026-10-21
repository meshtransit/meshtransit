package mobile

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/client/internal/peerprobe"
)

func TestPeerListPutsOnlineDevicesFirstThenByName(t *testing.T) {
	t.Parallel()

	list := newPeerList([]daemon.PeerView{
		{DeviceID: "c", Name: "zeta.mesh.example", OnlineKnown: true, Online: true, Path: daemon.PeerPathDirect},
		{DeviceID: "a", Name: "Alpha.mesh.example", OnlineKnown: true, Path: daemon.PeerPathInactive},
		{
			DeviceID: "b", Name: "beta.mesh.example", OnlineKnown: true, Online: true,
			Path: daemon.PeerPathRelay, RelayRegion: "sin", Addresses: []string{"100.64.0.2"}, Measurable: true,
		},
		{DeviceID: "d", Name: "gamma", Path: daemon.PeerPathPending},
	})
	encoded, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"peers":[` +
		`{"id":"b","name":"beta","addresses":["100.64.0.2"],"online":"online","path":"relay","relay":"sin",` +
		`"measurable":true},` +
		`{"id":"c","name":"zeta","addresses":[],"online":"online","path":"direct","measurable":false},` +
		`{"id":"d","name":"gamma","addresses":[],"online":"unknown","path":"pending","measurable":false},` +
		`{"id":"a","name":"Alpha","addresses":[],"online":"offline","path":"inactive","measurable":false}` +
		`],"total":4,"truncated":false}`
	if string(encoded) != want {
		t.Fatalf("peer list =\n%s\nwant\n%s", encoded, want)
	}
}

func TestPeerListIsBounded(t *testing.T) {
	t.Parallel()

	views := make([]daemon.PeerView, maxListedPeers+5)
	for index := range views {
		views[index] = daemon.PeerView{DeviceID: fmt.Sprint(index), Name: fmt.Sprintf("device-%05d", index)}
	}
	list := newPeerList(views)
	if len(list.Peers) != maxListedPeers || list.Total != maxListedPeers+5 || !list.Truncated {
		t.Fatalf("peers %d total %d truncated %v", len(list.Peers), list.Total, list.Truncated)
	}
	if empty := newPeerList(nil); empty.Peers == nil || empty.Total != 0 || empty.Truncated {
		t.Fatalf("empty list = %#v", empty)
	}
}

func TestPeerPingReportsLostSamplesAsAnswers(t *testing.T) {
	t.Parallel()

	sample, err := newPeerPing(daemon.PeerPing{RoundTrip: 1500 * time.Microsecond, Path: daemon.PeerPathDirect}, nil)
	if err != nil || sample != (peerPing{Answered: true, RoundTripMicros: 1500, Path: "direct"}) {
		t.Fatalf("answered sample = %#v, %v", sample, err)
	}
	for _, lost := range []error{
		peerprobe.ErrNoAnswer, peerprobe.ErrInactive, peerprobe.ErrNoPath,
		fmt.Errorf("%w: network is unreachable", peerprobe.ErrSendFailed), pathdiscovery.ErrSocketChanged,
		pathdiscovery.ErrPeerProbeCapacity,
	} {
		wrapped := fmt.Errorf("measuring: %w", lost)
		if sample, err := newPeerPing(daemon.PeerPing{}, wrapped); err != nil || sample != (peerPing{}) {
			t.Fatalf("newPeerPing(%v) = %#v, %v; want a lost sample", lost, sample, err)
		}
	}
	encoded, err := json.Marshal(peerPing{})
	if err != nil || string(encoded) != `{"answered":false,"roundTripMicros":0}` {
		t.Fatalf("lost sample JSON = %s, %v", encoded, err)
	}
	for _, failure := range []error{
		daemon.ErrPeerNotFound, daemon.ErrPeerTestUnavailable, daemon.ErrPeerNotMeasurable,
		peerprobe.ErrMeasurementBusy, peerprobe.ErrUnknownPeer, peerprobe.ErrNoRelay,
	} {
		if _, err := newPeerPing(daemon.PeerPing{}, failure); !errors.Is(err, failure) {
			t.Fatalf("newPeerPing(%v) error = %v", failure, err)
		}
	}
}
