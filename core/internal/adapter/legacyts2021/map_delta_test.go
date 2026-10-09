package legacyts2021

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/util/zstdframe"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

func TestEncodeAuthorityDeltaMapResponseAddsPeerAndPolicyAtomically(t *testing.T) {
	t.Parallel()

	current, next, peer := mapAuthorityDeltaSnapshotsFixture(t)
	delta, err := mapsession.NewAuthorityDelta(current, next)
	if err != nil {
		t.Fatalf("mapsession.NewAuthorityDelta() error = %v", err)
	}
	fields, response := decodeAuthorityDeltaFixture(t, delta)
	if len(fields) != 3 || fields["PeersChanged"] == nil || fields["PacketFilter"] == nil ||
		string(fields["DNSConfig"]) != "{}" ||
		fields["Node"] != nil || fields["Peers"] != nil || fields["PeersRemoved"] != nil {
		t.Fatalf("authority delta fields = %v, want PeersChanged + PacketFilter + complete DNSConfig", fields)
	}
	if len(response.PeersChanged) != 1 ||
		response.PeersChanged[0].ID != tailcfg.NodeID(peer.NumericNodeID()) ||
		response.PeersChanged[0].Online == nil || !*response.PeersChanged[0].Online ||
		len(response.PacketFilter) != 2 {
		t.Fatalf("authority delta response = %+v", response)
	}
}

func TestEncodeAuthorityDeltaMapResponseRevokesPeerAndClearsPolicy(t *testing.T) {
	t.Parallel()

	_, current, peer := mapAuthorityDeltaSnapshotsFixture(t)
	self, found := current.ConnectivityFor(current.NodeID())
	if !found {
		t.Fatal("current snapshot omitted self connectivity")
	}
	emptyPolicy, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    current.Scope(),
		Revision: current.PacketPolicy().Revision() + 1,
		Rules:    nil,
	})
	if err != nil {
		t.Fatalf("policy.NewSnapshot() error = %v", err)
	}
	nextParams := mapSnapshotParams(current)
	nextParams.NetworkRevision++
	nextParams.PacketPolicy = emptyPolicy
	nextParams.Connectivity = []mapsession.Connectivity{self}
	next, err := mapsession.NewSnapshot(nextParams)
	if err != nil {
		t.Fatalf("mapsession.NewSnapshot() error = %v", err)
	}
	delta, err := mapsession.NewAuthorityDelta(current, next)
	if err != nil {
		t.Fatalf("mapsession.NewAuthorityDelta() error = %v", err)
	}

	fields, response := decodeAuthorityDeltaFixture(t, delta)
	if len(fields) != 3 || fields["PeersRemoved"] == nil || fields["PacketFilter"] == nil ||
		string(fields["PacketFilter"]) != "[]" || string(fields["DNSConfig"]) != "{}" || fields["PeersChanged"] != nil ||
		fields["Peers"] != nil || fields["Node"] != nil {
		t.Fatalf("revocation delta fields = %v, want PeersRemoved + explicit empty PacketFilter", fields)
	}
	if !slices.Equal(response.PeersRemoved, []tailcfg.NodeID{
		tailcfg.NodeID(peer.NumericNodeID()),
	}) || response.PacketFilter == nil || len(response.PacketFilter) != 0 {
		t.Fatalf("revocation response = %+v", response)
	}
}

func TestEncodeAuthorityDeltaMapResponseReplacesPolicyWithoutPeerChurn(t *testing.T) {
	t.Parallel()

	_, current, _ := mapAuthorityDeltaSnapshotsFixture(t)
	rules := current.PacketPolicy().Rules()
	if len(rules) != 3 {
		t.Fatalf("fixture policy rules = %d, want 3", len(rules))
	}
	packetPolicy, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    current.Scope(),
		Revision: current.PacketPolicy().Revision() + 1,
		Rules:    []policy.Rule{rules[1]},
	})
	if err != nil {
		t.Fatalf("policy.NewSnapshot() error = %v", err)
	}
	nextParams := mapSnapshotParams(current)
	nextParams.NetworkRevision++
	nextParams.PacketPolicy = packetPolicy
	nextParams.Connectivity = currentConnectivityFixture(t, current)
	next, err := mapsession.NewSnapshot(nextParams)
	if err != nil {
		t.Fatalf("mapsession.NewSnapshot() error = %v", err)
	}
	delta, err := mapsession.NewAuthorityDelta(current, next)
	if err != nil {
		t.Fatalf("mapsession.NewAuthorityDelta() error = %v", err)
	}

	fields, response := decodeAuthorityDeltaFixture(t, delta)
	if len(fields) != 2 || fields["PacketFilter"] == nil || string(fields["DNSConfig"]) != "{}" || fields["Node"] != nil ||
		fields["PeersChanged"] != nil || fields["PeersRemoved"] != nil ||
		fields["Peers"] != nil || len(response.PacketFilter) != 1 {
		t.Fatalf("policy-only authority delta = fields %v response %+v", fields, response)
	}
}

func TestEncodeAuthorityDeltaMapResponseRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	if _, err := EncodeAuthorityDeltaMapResponse(mapsession.AuthorityDelta{}, 142); err == nil {
		t.Fatal("EncodeAuthorityDeltaMapResponse(zero delta) error = nil")
	}
	current, next, _ := mapAuthorityDeltaSnapshotsFixture(t)
	delta, err := mapsession.NewAuthorityDelta(current, next)
	if err != nil {
		t.Fatalf("mapsession.NewAuthorityDelta() error = %v", err)
	}
	if _, err := EncodeAuthorityDeltaMapResponse(delta, 0); err == nil {
		t.Fatal("EncodeAuthorityDeltaMapResponse(zero capability) error = nil")
	}
}

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

func mapAuthorityDeltaSnapshotsFixture(
	t *testing.T,
) (mapsession.Snapshot, mapsession.Snapshot, mapsession.PeerCandidate) {
	t.Helper()

	initial := mapSnapshotWithCandidateFixture(t)
	self := mapConnectivityWithoutEndpointsFixture(
		t,
		initial.NodeID(),
		initial.SessionGeneration(),
		false,
	)
	current, err := initial.WithConnectivity([]mapsession.Connectivity{self})
	if err != nil {
		t.Fatalf("WithConnectivity(current) error = %v", err)
	}

	authorized := mapSnapshotWithInboundPolicyFixture(t)
	peer := authorized.AuthorizedPeers()[0]
	peerConnectivity := mapConnectivityFixture(
		t,
		peer.NodeID(),
		peer.SessionGeneration(),
		4,
		"198.51.100.2:41641",
		true,
	)
	nextParams := mapSnapshotParams(authorized)
	nextParams.NetworkRevision = current.NetworkRevision() + 1
	nextParams.Connectivity = []mapsession.Connectivity{self, peerConnectivity}
	next, err := mapsession.NewSnapshot(nextParams)
	if err != nil {
		t.Fatalf("mapsession.NewSnapshot(next) error = %v", err)
	}
	return current, next, peer
}

func currentConnectivityFixture(
	t testing.TB,
	snapshot mapsession.Snapshot,
) []mapsession.Connectivity {
	t.Helper()
	values := make([]mapsession.Connectivity, 0, len(snapshot.AuthorizedPeers())+1)
	self, found := snapshot.ConnectivityFor(snapshot.NodeID())
	if !found {
		t.Fatal("snapshot omitted self connectivity")
	}
	values = append(values, self)
	for _, peer := range snapshot.AuthorizedPeers() {
		connectivity, peerFound := snapshot.ConnectivityFor(peer.NodeID())
		if !peerFound {
			t.Fatalf("snapshot omitted peer %s connectivity", peer.NodeID().String())
		}
		values = append(values, connectivity)
	}
	return values
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

func decodeAuthorityDeltaFixture(
	t testing.TB,
	delta mapsession.AuthorityDelta,
) (map[string]json.RawMessage, tailcfg.MapResponse) {
	t.Helper()
	encoded, err := EncodeAuthorityDeltaMapResponse(delta, 142)
	if err != nil {
		t.Fatalf("EncodeAuthorityDeltaMapResponse() error = %v", err)
	}
	if len(encoded) < 5 || int(binary.LittleEndian.Uint32(encoded[:4])) != len(encoded)-4 {
		t.Fatalf("encoded authority delta frame length = %d", len(encoded))
	}
	document, err := zstdframe.AppendDecode(
		nil,
		encoded[4:],
		zstdframe.MaxDecodedSize(maxMapResponseBytes),
	)
	if err != nil {
		t.Fatalf("decode zstd authority delta: %v", err)
	}
	fields := make(map[string]json.RawMessage)
	if err := json.Unmarshal(document, &fields); err != nil {
		t.Fatalf("decode authority delta fields: %v", err)
	}
	var response tailcfg.MapResponse
	if err := json.Unmarshal(document, &response); err != nil {
		t.Fatalf("decode authority delta response: %v", err)
	}
	return fields, response
}
