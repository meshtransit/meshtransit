package mapsession

import (
	"errors"
	"slices"
	"testing"

	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/policy"
)

func TestNewAuthorityDeltaProjectsPeerAndPolicyChanges(t *testing.T) {
	t.Parallel()

	current, next, peer := authorityDeltaSnapshotsFixture(t)
	delta, err := NewAuthorityDelta(current, next)
	if err != nil {
		t.Fatalf("NewAuthorityDelta() error = %v", err)
	}
	if !delta.IsValid() || delta.Snapshot().NetworkRevision() != current.NetworkRevision()+1 ||
		delta.SelfChanged() || !slices.Equal(delta.RemovedPeerNumericIDs(), []int64{}) {
		t.Fatalf("authority delta = %+v, want contiguous peer addition", delta)
	}
	changed := delta.ChangedPeers()
	if len(changed) != 1 || changed[0].NodeID() != peer.NodeID() ||
		changed[0].NumericNodeID() != peer.NumericNodeID() {
		t.Fatalf("changed peers = %+v, want peer %s", changed, peer.NodeID().String())
	}
}

func TestNewAuthorityDeltaProjectsPeerRevocation(t *testing.T) {
	t.Parallel()

	_, current, peer := authorityDeltaSnapshotsFixture(t)
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
	nextParams := current.params()
	nextParams.NetworkRevision++
	nextParams.PacketPolicy = emptyPolicy
	nextParams.Connectivity = []Connectivity{self}
	next, err := NewSnapshot(nextParams)
	if err != nil {
		t.Fatalf("NewSnapshot(revoked) error = %v", err)
	}

	delta, err := NewAuthorityDelta(current, next)
	if err != nil {
		t.Fatalf("NewAuthorityDelta() error = %v", err)
	}
	if !delta.IsValid() || delta.SelfChanged() || len(delta.ChangedPeers()) != 0 ||
		!slices.Equal(delta.RemovedPeerNumericIDs(), []int64{peer.NumericNodeID()}) {
		t.Fatalf("revocation delta = %+v, want peer %d removed", delta, peer.NumericNodeID())
	}
}

func TestNewAuthorityDeltaIncludesCoincidentSelfConnectivity(t *testing.T) {
	t.Parallel()

	current, next, peer := authorityDeltaSnapshotsFixture(t)
	peerConnectivity, found := next.ConnectivityFor(peer.NodeID())
	if !found {
		t.Fatal("next snapshot omitted peer connectivity")
	}
	selfAfter := connectivityFixture(
		t,
		next.NodeID(),
		next.SessionGeneration(),
		9,
		"198.51.100.9:41641",
		true,
	)
	next, err := next.WithConnectivity([]Connectivity{selfAfter, peerConnectivity})
	if err != nil {
		t.Fatalf("WithConnectivity() error = %v", err)
	}

	delta, err := NewAuthorityDelta(current, next)
	if err != nil {
		t.Fatalf("NewAuthorityDelta() error = %v", err)
	}
	if !delta.IsValid() || !delta.SelfChanged() {
		t.Fatalf("authority delta self change = %t, want true", delta.SelfChanged())
	}
}

func TestNewAuthorityDeltaRejectsUnsafeTransitions(t *testing.T) {
	t.Parallel()

	current, next, _ := authorityDeltaSnapshotsFixture(t)
	gapParams := next.params()
	gapParams.NetworkRevision++
	gap, err := NewSnapshot(gapParams)
	if err != nil {
		t.Fatalf("NewSnapshot(gap) error = %v", err)
	}
	nameParams := next.params()
	name, err := network.ParseDisplayName("Renamed Mesh")
	if err != nil {
		t.Fatalf("network.ParseDisplayName() error = %v", err)
	}
	nameParams.NetworkName = name
	renamed, err := NewSnapshot(nameParams)
	if err != nil {
		t.Fatalf("NewSnapshot(renamed) error = %v", err)
	}

	for _, test := range []struct {
		name    string
		current Snapshot
		next    Snapshot
	}{
		{name: "same revision", current: current, next: current},
		{name: "revision gap", current: current, next: gap},
		{name: "self authority changed", current: current, next: renamed},
		{
			name:    "revision only",
			current: current,
			next: func() Snapshot {
				params := current.params()
				params.NetworkRevision++
				unchanged, unchangedErr := NewSnapshot(params)
				if unchangedErr != nil {
					t.Fatalf("NewSnapshot(revision only) error = %v", unchangedErr)
				}
				return unchanged
			}(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewAuthorityDelta(test.current, test.next); !errors.Is(
				err,
				ErrInvalidAuthorityDelta,
			) {
				t.Fatalf("NewAuthorityDelta() error = %v, want ErrInvalidAuthorityDelta", err)
			}
		})
	}
}

func TestNewAuthorityDeltaRejectsAmbiguousNumericPeerTransition(t *testing.T) {
	t.Parallel()

	_, current, peer := authorityDeltaSnapshotsFixture(t)
	changedParams := peer.params()
	changedParams.NumericNodeID++
	changedPeer, err := NewPeerCandidate(changedParams)
	if err != nil {
		t.Fatalf("NewPeerCandidate(changed) error = %v", err)
	}
	addedParams := peerCandidateParamsFixture(
		t,
		current,
		"01890f00-0000-7000-8000-000000000703",
		4,
	)
	addedParams.NumericNodeID = peer.NumericNodeID()
	addedPeer, err := NewPeerCandidate(addedParams)
	if err != nil {
		t.Fatalf("NewPeerCandidate(added) error = %v", err)
	}
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000802")
	if err != nil {
		t.Fatalf("policy.ParseRuleID() error = %v", err)
	}
	addedRule, err := policy.NewRule(policy.RuleParams{
		ID:                ruleID,
		Scope:             current.Scope(),
		SourceNodeID:      current.NodeID(),
		DestinationNodeID: addedPeer.NodeID(),
		Protocol:          policy.ProtocolICMP,
	})
	if err != nil {
		t.Fatalf("policy.NewRule() error = %v", err)
	}
	rules := current.PacketPolicy().Rules()
	rules = append(rules, addedRule)
	packetPolicy, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    current.Scope(),
		Revision: current.PacketPolicy().Revision() + 1,
		Rules:    rules,
	})
	if err != nil {
		t.Fatalf("policy.NewSnapshot() error = %v", err)
	}
	self, found := current.ConnectivityFor(current.NodeID())
	if !found {
		t.Fatal("next snapshot omitted self connectivity")
	}
	changedConnectivity, found := current.ConnectivityFor(peer.NodeID())
	if !found {
		t.Fatal("next snapshot omitted existing peer connectivity")
	}
	addedConnectivity := connectivityFixture(
		t,
		addedPeer.NodeID(),
		addedPeer.SessionGeneration(),
		8,
		"198.51.100.8:41641",
		true,
	)
	ambiguousParams := current.params()
	ambiguousParams.NetworkRevision++
	ambiguousParams.PeerCandidates = []PeerCandidate{changedPeer, addedPeer}
	ambiguousParams.PacketPolicy = packetPolicy
	ambiguousParams.Connectivity = []Connectivity{
		self,
		changedConnectivity,
		addedConnectivity,
	}
	ambiguous, err := NewSnapshot(ambiguousParams)
	if err != nil {
		t.Fatalf("NewSnapshot(ambiguous) error = %v", err)
	}
	if _, err := NewAuthorityDelta(current, ambiguous); !errors.Is(
		err,
		ErrInvalidAuthorityDelta,
	) {
		t.Fatalf("NewAuthorityDelta() error = %v, want ErrInvalidAuthorityDelta", err)
	}
}

func authorityDeltaSnapshotsFixture(
	t *testing.T,
) (Snapshot, Snapshot, PeerCandidate) {
	t.Helper()

	authorized, peer := snapshotWithAuthorizedPeerFixture(t)
	emptyPolicy, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    authorized.Scope(),
		Revision: authorized.PacketPolicy().Revision() - 1,
		Rules:    nil,
	})
	if err != nil {
		t.Fatalf("policy.NewSnapshot() error = %v", err)
	}
	selfKey, err := NewConnectivityKey(
		authorized.NodeID(),
		authorized.SessionGeneration(),
	)
	if err != nil {
		t.Fatalf("NewConnectivityKey(self) error = %v", err)
	}
	self, err := NewConnectivity(ConnectivityParams{Key: selfKey})
	if err != nil {
		t.Fatalf("NewConnectivity(self) error = %v", err)
	}
	currentParams := authorized.params()
	currentParams.PacketPolicy = emptyPolicy
	currentParams.Connectivity = []Connectivity{self}
	current, err := NewSnapshot(currentParams)
	if err != nil {
		t.Fatalf("NewSnapshot(current) error = %v", err)
	}

	peerConnectivity := connectivityFixture(
		t,
		peer.NodeID(),
		peer.SessionGeneration(),
		4,
		"198.51.100.2:41641",
		true,
	)
	nextParams := authorized.params()
	nextParams.NetworkRevision = current.NetworkRevision() + 1
	nextParams.Connectivity = []Connectivity{self, peerConnectivity}
	next, err := NewSnapshot(nextParams)
	if err != nil {
		t.Fatalf("NewSnapshot(next) error = %v", err)
	}
	return current, next, peer
}
