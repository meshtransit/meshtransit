package mapsession

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
)

func TestSnapshotOwnsCanonicalAuthorizedConnectivity(t *testing.T) {
	t.Parallel()

	snapshot, peer := snapshotWithAuthorizedPeerFixture(t)
	selfConnectivity := connectivityFixture(
		t,
		snapshot.NodeID(),
		snapshot.SessionGeneration(),
		3,
		"198.51.100.1:41641",
		true,
	)
	peerConnectivity := connectivityFixture(
		t,
		peer.NodeID(),
		peer.SessionGeneration(),
		4,
		"198.51.100.2:41641",
		true,
	)
	enriched, err := snapshot.WithConnectivity([]Connectivity{peerConnectivity, selfConnectivity})
	if err != nil {
		t.Fatalf("WithConnectivity() error = %v", err)
	}
	for key, want := range map[node.ID]Connectivity{
		snapshot.NodeID(): selfConnectivity,
		peer.NodeID():     peerConnectivity,
	} {
		got, found := enriched.ConnectivityFor(key)
		if !found || !got.equal(want) {
			t.Fatalf("ConnectivityFor(%s) = (%+v, %t), want exact projection", key, got, found)
		}
	}
}

func TestSnapshotRejectsUnauthorizedOrUnfencedConnectivity(t *testing.T) {
	t.Parallel()

	snapshot, peer := snapshotWithAuthorizedPeerFixture(t)
	denied := peerCandidateFixture(
		t,
		snapshot,
		"01890f00-0000-7000-8000-000000000703",
		3,
	)
	for _, test := range []struct {
		name         string
		connectivity Connectivity
	}{
		{
			name: "wrong self generation",
			connectivity: connectivityFixture(
				t,
				snapshot.NodeID(),
				snapshot.SessionGeneration()+1,
				3,
				"198.51.100.1:41641",
				true,
			),
		},
		{
			name: "unauthorized peer",
			connectivity: connectivityFixture(
				t,
				denied.NodeID(),
				denied.SessionGeneration(),
				5,
				"198.51.100.3:41641",
				true,
			),
		},
		{
			name: "wrong peer generation",
			connectivity: connectivityFixture(
				t,
				peer.NodeID(),
				peer.SessionGeneration()+1,
				4,
				"198.51.100.2:41641",
				true,
			),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := snapshot.WithConnectivity([]Connectivity{test.connectivity}); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("WithConnectivity() error = %v, want ErrInvalidSnapshot", err)
			}
		})
	}
}

func TestNewConnectivityDeltaSelectsOnlyWireVisibleChanges(t *testing.T) {
	t.Parallel()

	base, peer := snapshotWithAuthorizedPeerFixture(t)
	self := connectivityFixture(
		t,
		base.NodeID(),
		base.SessionGeneration(),
		3,
		"198.51.100.1:41641",
		true,
	)
	peerBefore := connectivityFixture(
		t,
		peer.NodeID(),
		peer.SessionGeneration(),
		4,
		"198.51.100.2:41641",
		false,
	)
	peerAfter := connectivityFixture(
		t,
		peer.NodeID(),
		peer.SessionGeneration(),
		4,
		"198.51.100.3:41641",
		true,
	)
	current, err := base.WithConnectivity([]Connectivity{self, peerBefore})
	if err != nil {
		t.Fatalf("WithConnectivity(current) error = %v", err)
	}
	next, err := base.WithConnectivity([]Connectivity{self, peerAfter})
	if err != nil {
		t.Fatalf("WithConnectivity(next) error = %v", err)
	}

	delta, err := NewConnectivityDelta(current, next)
	if err != nil {
		t.Fatalf("NewConnectivityDelta() error = %v", err)
	}
	changedPeers := delta.ChangedPeers()
	if !delta.IsValid() || delta.SelfChanged() || len(changedPeers) != 1 ||
		changedPeers[0].NodeID() != peer.NodeID() || delta.Snapshot().NodeID() != base.NodeID() {
		t.Fatalf("ConnectivityDelta = %+v peers=%+v, want only changed peer", delta, changedPeers)
	}
	changedPeers[0] = PeerCandidate{}
	if delta.ChangedPeers()[0].NodeID() != peer.NodeID() {
		t.Fatal("ConnectivityDelta exposed mutable peer storage")
	}
}

func TestNewConnectivityDeltaIncludesPreferredRelayChange(t *testing.T) {
	t.Parallel()

	base, peer := snapshotWithAuthorizedPeerFixture(t)
	self := connectivityFixture(
		t,
		base.NodeID(),
		base.SessionGeneration(),
		3,
		"198.51.100.1:41641",
		true,
	)
	set, present := self.EndpointSet()
	if !present {
		t.Fatal("self connectivity omitted endpoint set")
	}
	selfBefore, err := NewConnectivity(ConnectivityParams{
		Key:                   self.Key(),
		EndpointSet:           set,
		EndpointSetPresent:    true,
		PreferredRelay:        1,
		PreferredRelayPresent: true,
		Online:                self.Online(),
	})
	if err != nil {
		t.Fatalf("NewConnectivity(before) error = %v", err)
	}
	selfAfter, err := NewConnectivity(ConnectivityParams{
		Key:                   self.Key(),
		EndpointSet:           set,
		EndpointSetPresent:    true,
		PreferredRelay:        3,
		PreferredRelayPresent: true,
		Online:                self.Online(),
	})
	if err != nil {
		t.Fatalf("NewConnectivity(after) error = %v", err)
	}
	peerConnectivity := connectivityFixture(
		t,
		peer.NodeID(),
		peer.SessionGeneration(),
		4,
		"198.51.100.2:41641",
		true,
	)
	current, err := base.WithConnectivity([]Connectivity{selfBefore, peerConnectivity})
	if err != nil {
		t.Fatalf("WithConnectivity(current) error = %v", err)
	}
	next, err := base.WithConnectivity([]Connectivity{selfAfter, peerConnectivity})
	if err != nil {
		t.Fatalf("WithConnectivity(next) error = %v", err)
	}
	delta, err := NewConnectivityDelta(current, next)
	if err != nil {
		t.Fatalf("NewConnectivityDelta() error = %v", err)
	}
	if !delta.IsValid() || !delta.SelfChanged() || len(delta.ChangedPeers()) != 0 {
		t.Fatalf("ConnectivityDelta = %+v, want only self preferred-relay change", delta)
	}
}

func TestNewConnectivityDeltaRejectsAuthorityChangeOrEmptyUpdate(t *testing.T) {
	t.Parallel()

	base, peer := snapshotWithAuthorizedPeerFixture(t)
	self := connectivityFixture(
		t,
		base.NodeID(),
		base.SessionGeneration(),
		3,
		"198.51.100.1:41641",
		true,
	)
	peerConnectivity := connectivityFixture(
		t,
		peer.NodeID(),
		peer.SessionGeneration(),
		4,
		"198.51.100.2:41641",
		true,
	)
	current, err := base.WithConnectivity([]Connectivity{self, peerConnectivity})
	if err != nil {
		t.Fatalf("WithConnectivity() error = %v", err)
	}
	advancedParams := current.params()
	advancedParams.NetworkRevision++
	advanced, err := NewSnapshot(advancedParams)
	if err != nil {
		t.Fatalf("NewSnapshot(advanced) error = %v", err)
	}

	for _, test := range []struct {
		name string
		next Snapshot
	}{
		{name: "unchanged", next: current},
		{name: "authority revision", next: advanced},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewConnectivityDelta(current, test.next); !errors.Is(
				err,
				ErrInvalidConnectivityDelta,
			) {
				t.Fatalf("NewConnectivityDelta() error = %v, want ErrInvalidConnectivityDelta", err)
			}
		})
	}
}

func snapshotWithAuthorizedPeerFixture(t *testing.T) (Snapshot, PeerCandidate) {
	t.Helper()
	snapshot := snapshotFixture(t)
	peer := peerCandidateFixture(
		t,
		snapshot,
		"01890f00-0000-7000-8000-000000000702",
		2,
	)
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000801")
	if err != nil {
		t.Fatalf("policy.ParseRuleID() error = %v", err)
	}
	rule, err := policy.NewRule(policy.RuleParams{
		ID:                ruleID,
		Scope:             snapshot.Scope(),
		SourceNodeID:      snapshot.NodeID(),
		DestinationNodeID: peer.NodeID(),
		Protocol:          policy.ProtocolICMP,
	})
	if err != nil {
		t.Fatalf("policy.NewRule() error = %v", err)
	}
	packetPolicy, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    snapshot.Scope(),
		Revision: snapshot.PacketPolicy().Revision(),
		Rules:    []policy.Rule{rule},
	})
	if err != nil {
		t.Fatalf("policy.NewSnapshot() error = %v", err)
	}
	params := snapshot.params()
	params.PeerCandidates = []PeerCandidate{peer}
	params.PacketPolicy = packetPolicy
	snapshot, err = NewSnapshot(params)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	return snapshot, peer
}

func connectivityFixture(
	t testing.TB,
	nodeID node.ID,
	generation int64,
	keyByte byte,
	address string,
	online bool,
) Connectivity {
	t.Helper()
	key, err := NewConnectivityKey(nodeID, generation)
	if err != nil {
		t.Fatalf("NewConnectivityKey() error = %v", err)
	}
	discoveryKey, err := node.NewDiscoveryKey([32]byte{keyByte})
	if err != nil {
		t.Fatalf("node.NewDiscoveryKey() error = %v", err)
	}
	endpoint, err := node.NewEndpoint(
		netip.MustParseAddrPort(address),
		node.EndpointSourceSTUN,
	)
	if err != nil {
		t.Fatalf("node.NewEndpoint() error = %v", err)
	}
	set, err := node.NewEndpointSet(discoveryKey, []node.Endpoint{endpoint})
	if err != nil {
		t.Fatalf("node.NewEndpointSet() error = %v", err)
	}
	connectivity, err := NewConnectivity(ConnectivityParams{
		Key:                key,
		EndpointSet:        set,
		EndpointSetPresent: true,
		Online:             online,
	})
	if err != nil {
		t.Fatalf("NewConnectivity() error = %v", err)
	}
	return connectivity
}
