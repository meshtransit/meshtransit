package mapsession

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
)

func TestSnapshotOwnsAddressCollection(t *testing.T) {
	snapshot := snapshotFixture(t)
	addresses := snapshot.Addresses()
	addresses[0] = netip.MustParsePrefix("100.64.0.99/32")
	if got := snapshot.Addresses()[0]; got != netip.MustParsePrefix("100.64.0.1/32") {
		t.Fatalf("snapshot address = %v after caller mutation", got)
	}
}

func TestSnapshotCanonicalizesAndOwnsPeerCandidates(t *testing.T) {
	base := snapshotFixture(t)
	first := peerCandidateFixture(t, base, "01890f00-0000-7000-8000-000000000702", 2)
	second := peerCandidateFixture(t, base, "01890f00-0000-7000-8000-000000000703", 3)
	params := base.params()
	params.PeerCandidates = []PeerCandidate{second, first}
	snapshot, err := NewSnapshot(params)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	params.PeerCandidates[0] = first
	candidates := snapshot.PeerCandidates()
	if len(candidates) != 2 || candidates[0].NodeID() != first.NodeID() ||
		candidates[1].NodeID() != second.NodeID() {
		t.Fatalf("PeerCandidates() = %+v, want canonical Node ID order", candidates)
	}
	candidates[0] = second
	if got := snapshot.PeerCandidates()[0].NodeID(); got != first.NodeID() {
		t.Fatalf("snapshot first candidate = %v after caller mutation", got)
	}
}

func TestSnapshotProjectsOnlyExplicitlyAuthorizedPeerCandidates(t *testing.T) {
	base := snapshotFixture(t)
	allowed := peerCandidateFixture(t, base, "01890f00-0000-7000-8000-000000000702", 2)
	denied := peerCandidateFixture(t, base, "01890f00-0000-7000-8000-000000000703", 3)
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000801")
	if err != nil {
		t.Fatalf("policy.ParseRuleID() error = %v", err)
	}
	rule, err := policy.NewRule(policy.RuleParams{
		ID:                ruleID,
		Scope:             base.Scope(),
		SourceNodeID:      allowed.NodeID(),
		DestinationNodeID: base.NodeID(),
		Protocol:          policy.ProtocolICMP,
	})
	if err != nil {
		t.Fatalf("policy.NewRule() error = %v", err)
	}
	packetPolicy, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    base.Scope(),
		Revision: base.PacketPolicy().Revision(),
		Rules:    []policy.Rule{rule},
	})
	if err != nil {
		t.Fatalf("policy.NewSnapshot() error = %v", err)
	}
	params := base.params()
	params.PeerCandidates = []PeerCandidate{denied, allowed}
	params.PacketPolicy = packetPolicy
	snapshot, err := NewSnapshot(params)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}

	peers := snapshot.AuthorizedPeers()
	if len(peers) != 1 || peers[0].NodeID() != allowed.NodeID() {
		t.Fatalf("AuthorizedPeers() = %+v, want only explicitly authorized peer", peers)
	}
	peers[0] = denied
	if got := snapshot.AuthorizedPeers(); len(got) != 1 || got[0].NodeID() != allowed.NodeID() {
		t.Fatal("snapshot exposed mutable authorized peer storage")
	}
}

func TestSnapshotRejectsUnsafePeerCandidateSet(t *testing.T) {
	base := snapshotFixture(t)
	valid := peerCandidateFixture(t, base, "01890f00-0000-7000-8000-000000000702", 2)
	selfNodeParams := valid.params()
	selfNodeParams.NodeID = base.NodeID()
	selfNode, err := NewPeerCandidate(selfNodeParams)
	if err != nil {
		t.Fatalf("NewPeerCandidate(self Node) error = %v", err)
	}
	selfMachineParams := valid.params()
	selfMachineParams.MachineKey = base.MachineKey()
	selfMachine, err := NewPeerCandidate(selfMachineParams)
	if err != nil {
		t.Fatalf("NewPeerCandidate(self machine) error = %v", err)
	}
	otherScopeParams := valid.params()
	otherNetworkID, err := network.ParseID("01890f00-0000-7000-8000-000000000202")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	otherScopeParams.Scope, err = network.NewScope(base.Scope().WorkspaceID(), otherNetworkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	otherScope, err := NewPeerCandidate(otherScopeParams)
	if err != nil {
		t.Fatalf("NewPeerCandidate(other scope) error = %v", err)
	}
	duplicateParams := valid.params()
	duplicateParams.MachineKey, err = node.NewMachineKey([32]byte{9})
	if err != nil {
		t.Fatalf("node.NewMachineKey() error = %v", err)
	}
	duplicateParams.NodeKey, err = node.NewKey([32]byte{109})
	if err != nil {
		t.Fatalf("node.NewKey() error = %v", err)
	}
	duplicate, err := NewPeerCandidate(duplicateParams)
	if err != nil {
		t.Fatalf("NewPeerCandidate(duplicate Node ID) error = %v", err)
	}

	for _, test := range []struct {
		name       string
		candidates []PeerCandidate
	}{
		{name: "self Node", candidates: []PeerCandidate{selfNode}},
		{name: "self machine", candidates: []PeerCandidate{selfMachine}},
		{name: "other scope", candidates: []PeerCandidate{otherScope}},
		{name: "duplicate Node", candidates: []PeerCandidate{valid, duplicate}},
	} {
		t.Run(test.name, func(t *testing.T) {
			params := base.params()
			params.PeerCandidates = test.candidates
			if _, err := NewSnapshot(params); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("NewSnapshot() error = %v, want ErrInvalidSnapshot", err)
			}
		})
	}
}

func TestSnapshotFailsClosedAboveAbsolutePeerCandidateLimit(t *testing.T) {
	params := snapshotFixture(t).params()
	params.PeerCandidates = make([]PeerCandidate, MaximumPeerCandidates+1)
	_, err := NewSnapshot(params)
	if !errors.Is(err, ErrInvalidSnapshot) || !errors.Is(err, ErrPeerCandidateLimit) {
		t.Fatalf("NewSnapshot() error = %v, want invalid snapshot and peer limit", err)
	}
}

func TestSnapshotRejectsUnsafeAuthorityState(t *testing.T) {
	valid := snapshotFixture(t)
	params := valid.params()
	for _, test := range []struct {
		name   string
		mutate func(*SnapshotParams)
	}{
		{name: "missing scope", mutate: func(value *SnapshotParams) { value.Scope = network.Scope{} }},
		{name: "missing packet policy", mutate: func(value *SnapshotParams) { value.PacketPolicy = policy.Snapshot{} }},
		{name: "zero revision", mutate: func(value *SnapshotParams) { value.NetworkRevision = 0 }},
		{name: "zero recovery epoch", mutate: func(value *SnapshotParams) { value.RecoveryEpoch = 0 }},
		{name: "zero session generation", mutate: func(value *SnapshotParams) { value.SessionGeneration = 0 }},
		{name: "zero numeric Node ID", mutate: func(value *SnapshotParams) { value.NumericNodeID = 0 }},
		{name: "unsafe numeric Node ID", mutate: func(value *SnapshotParams) { value.NumericNodeID = maximumSafeNumericID + 1 }},
		{name: "zero owner ID", mutate: func(value *SnapshotParams) { value.NumericOwnerID = 0 }},
		{name: "missing address", mutate: func(value *SnapshotParams) { value.Addresses = nil }},
		{name: "network address", mutate: func(value *SnapshotParams) {
			value.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/24")}
		}},
		{name: "duplicate address family", mutate: func(value *SnapshotParams) {
			value.Addresses = []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("100.64.0.2/32"),
			}
		}},
		{name: "expiry before creation", mutate: func(value *SnapshotParams) { value.KeyExpiry = value.CreatedAt }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := params
			candidate.Addresses = append([]netip.Prefix(nil), params.Addresses...)
			test.mutate(&candidate)
			if _, err := NewSnapshot(candidate); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("NewSnapshot() error = %v, want ErrInvalidSnapshot", err)
			}
		})
	}
}
