package legacyts2021

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/util/zstdframe"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/node"
)

func TestEncodeConnectivityDeltaMapResponseReplacesChangedPeerOnly(t *testing.T) {
	t.Parallel()

	current, next, _ := mapConnectivityDeltaSnapshotsFixture(t)
	delta, err := mapsession.NewConnectivityDelta(current, next)
	if err != nil {
		t.Fatalf("mapsession.NewConnectivityDelta() error = %v", err)
	}
	fields, response := decodeConnectivityDeltaFixture(t, delta)
	if len(fields) != 1 || fields["PeersChanged"] == nil || fields["Node"] != nil ||
		fields["Peers"] != nil || fields["PacketFilter"] != nil {
		t.Fatalf("connectivity delta fields = %v, want only PeersChanged", fields)
	}
	if len(response.PeersChanged) != 1 || response.PeersChanged[0].ID != 702 ||
		response.PeersChanged[0].DiscoKey.IsZero() ||
		response.PeersChanged[0].Online == nil || !*response.PeersChanged[0].Online ||
		!slices.Equal(response.PeersChanged[0].Endpoints, []netip.AddrPort{
			netip.MustParseAddrPort("198.51.100.3:41641"),
		}) {
		t.Fatalf("PeersChanged = %+v, want complete online peer replacement", response.PeersChanged)
	}
}

func TestEncodeConnectivityDeltaMapResponseWithdrawsPeerEndpoints(t *testing.T) {
	t.Parallel()

	_, current, peer := mapConnectivityDeltaSnapshotsFixture(t)
	self, found := current.ConnectivityFor(current.NodeID())
	if !found {
		t.Fatal("current snapshot omitted self connectivity")
	}
	withoutEndpoints := mapConnectivityWithoutEndpointsFixture(
		t,
		peer.NodeID(),
		peer.SessionGeneration(),
		false,
	)
	next, err := current.WithConnectivity([]mapsession.Connectivity{self, withoutEndpoints})
	if err != nil {
		t.Fatalf("WithConnectivity(withdrawal) error = %v", err)
	}
	delta, err := mapsession.NewConnectivityDelta(current, next)
	if err != nil {
		t.Fatalf("mapsession.NewConnectivityDelta() error = %v", err)
	}
	_, response := decodeConnectivityDeltaFixture(t, delta)
	if len(response.PeersChanged) != 1 || len(response.PeersChanged[0].Endpoints) != 0 ||
		!response.PeersChanged[0].DiscoKey.IsZero() ||
		response.PeersChanged[0].Online == nil || *response.PeersChanged[0].Online {
		t.Fatalf("withdrawal peer = %+v, want offline replacement without endpoints", response.PeersChanged)
	}
}

func TestEncodeConnectivityDeltaMapResponseReplacesSelfOnly(t *testing.T) {
	t.Parallel()

	current, _, peer := mapConnectivityDeltaSnapshotsFixture(t)
	peerConnectivity, found := current.ConnectivityFor(peer.NodeID())
	if !found {
		t.Fatal("current snapshot omitted peer connectivity")
	}
	selfAfter := mapConnectivityFixture(
		t,
		current.NodeID(),
		current.SessionGeneration(),
		3,
		"198.51.100.4:41641",
		true,
	)
	next, err := current.WithConnectivity([]mapsession.Connectivity{selfAfter, peerConnectivity})
	if err != nil {
		t.Fatalf("WithConnectivity(self update) error = %v", err)
	}
	delta, err := mapsession.NewConnectivityDelta(current, next)
	if err != nil {
		t.Fatalf("mapsession.NewConnectivityDelta() error = %v", err)
	}
	fields, response := decodeConnectivityDeltaFixture(t, delta)
	if len(fields) != 1 || fields["Node"] == nil || fields["PeersChanged"] != nil ||
		response.Node == nil || !slices.Equal(response.Node.Endpoints, []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.4:41641"),
	}) {
		t.Fatalf("self connectivity delta = fields %v response %+v", fields, response)
	}
}

func TestEncodeConnectivityDeltaMapResponseRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	if _, err := EncodeConnectivityDeltaMapResponse(mapsession.ConnectivityDelta{}, 142); err == nil {
		t.Fatal("EncodeConnectivityDeltaMapResponse(zero delta) error = nil")
	}
	current, next, _ := mapConnectivityDeltaSnapshotsFixture(t)
	delta, err := mapsession.NewConnectivityDelta(current, next)
	if err != nil {
		t.Fatalf("mapsession.NewConnectivityDelta() error = %v", err)
	}
	if _, err := EncodeConnectivityDeltaMapResponse(delta, 0); err == nil {
		t.Fatal("EncodeConnectivityDeltaMapResponse(zero capability) error = nil")
	}
}

func mapConnectivityDeltaSnapshotsFixture(
	t *testing.T,
) (mapsession.Snapshot, mapsession.Snapshot, mapsession.PeerCandidate) {
	t.Helper()
	base := mapSnapshotWithAuthorizedCandidateFixture(t)
	peer := base.AuthorizedPeers()[0]
	self := mapConnectivityFixture(
		t,
		base.NodeID(),
		base.SessionGeneration(),
		3,
		"198.51.100.1:41641",
		true,
	)
	peerBefore := mapConnectivityFixture(
		t,
		peer.NodeID(),
		peer.SessionGeneration(),
		4,
		"198.51.100.2:41641",
		false,
	)
	peerAfter := mapConnectivityFixture(
		t,
		peer.NodeID(),
		peer.SessionGeneration(),
		4,
		"198.51.100.3:41641",
		true,
	)
	current, err := base.WithConnectivity([]mapsession.Connectivity{self, peerBefore})
	if err != nil {
		t.Fatalf("WithConnectivity(current) error = %v", err)
	}
	next, err := base.WithConnectivity([]mapsession.Connectivity{self, peerAfter})
	if err != nil {
		t.Fatalf("WithConnectivity(next) error = %v", err)
	}
	return current, next, peer
}

func mapConnectivityWithoutEndpointsFixture(
	t testing.TB,
	nodeID node.ID,
	generation int64,
	online bool,
) mapsession.Connectivity {
	t.Helper()
	key, err := mapsession.NewConnectivityKey(nodeID, generation)
	if err != nil {
		t.Fatalf("mapsession.NewConnectivityKey() error = %v", err)
	}
	connectivity, err := mapsession.NewConnectivity(mapsession.ConnectivityParams{
		Key:    key,
		Online: online,
	})
	if err != nil {
		t.Fatalf("mapsession.NewConnectivity() error = %v", err)
	}
	return connectivity
}

func decodeConnectivityDeltaFixture(
	t testing.TB,
	delta mapsession.ConnectivityDelta,
) (map[string]json.RawMessage, tailcfg.MapResponse) {
	t.Helper()
	encoded, err := EncodeConnectivityDeltaMapResponse(delta, 142)
	if err != nil {
		t.Fatalf("EncodeConnectivityDeltaMapResponse() error = %v", err)
	}
	if len(encoded) < 5 || int(binary.LittleEndian.Uint32(encoded[:4])) != len(encoded)-4 {
		t.Fatalf("encoded delta frame length = %d", len(encoded))
	}
	document, err := zstdframe.AppendDecode(
		nil,
		encoded[4:],
		zstdframe.MaxDecodedSize(maxMapResponseBytes),
	)
	if err != nil {
		t.Fatalf("decode zstd connectivity delta: %v", err)
	}
	fields := make(map[string]json.RawMessage)
	if err := json.Unmarshal(document, &fields); err != nil {
		t.Fatalf("decode connectivity delta fields: %v", err)
	}
	var response tailcfg.MapResponse
	if err := json.Unmarshal(document, &response); err != nil {
		t.Fatalf("decode connectivity delta response: %v", err)
	}
	return fields, response
}
