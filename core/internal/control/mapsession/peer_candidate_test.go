package mapsession

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

func TestPeerCandidateOwnsAddressCollection(t *testing.T) {
	params := peerCandidateParamsFixture(t, snapshotFixture(t), "01890f00-0000-7000-8000-000000000702", 2)
	candidate, err := NewPeerCandidate(params)
	if err != nil {
		t.Fatalf("NewPeerCandidate() error = %v", err)
	}
	params.Addresses[0] = netip.MustParsePrefix("100.64.0.99/32")
	addresses := candidate.Addresses()
	addresses[0] = netip.MustParsePrefix("100.64.0.98/32")
	if got := candidate.Addresses()[0]; got != netip.MustParsePrefix("100.64.0.2/32") {
		t.Fatalf("candidate address = %v after caller mutation", got)
	}
}

func TestPeerCandidateRejectsIncompleteDurableEvidence(t *testing.T) {
	base := peerCandidateParamsFixture(t, snapshotFixture(t), "01890f00-0000-7000-8000-000000000702", 2)
	for _, test := range []struct {
		name   string
		mutate func(*PeerCandidateParams)
	}{
		{name: "numeric Node ID", mutate: func(value *PeerCandidateParams) { value.NumericNodeID = 0 }},
		{name: "unsafe numeric Node ID", mutate: func(value *PeerCandidateParams) { value.NumericNodeID = maximumSafeNumericID + 1 }},
		{name: "numeric owner ID", mutate: func(value *PeerCandidateParams) { value.NumericOwnerID = 0 }},
		{name: "unsafe numeric owner ID", mutate: func(value *PeerCandidateParams) { value.NumericOwnerID = maximumSafeNumericID + 1 }},
		{name: "scope", mutate: func(value *PeerCandidateParams) { value.Scope = network.Scope{} }},
		{name: "Node ID", mutate: func(value *PeerCandidateParams) { value.NodeID = node.ID{} }},
		{name: "owner", mutate: func(value *PeerCandidateParams) { value.OwnerID = identity.PrincipalID{} }},
		{name: "hostname", mutate: func(value *PeerCandidateParams) { value.Hostname = node.Hostname{} }},
		{name: "machine key", mutate: func(value *PeerCandidateParams) { value.MachineKey = node.MachineKey{} }},
		{name: "Node key", mutate: func(value *PeerCandidateParams) { value.NodeKey = node.Key{} }},
		{name: "generation", mutate: func(value *PeerCandidateParams) { value.SessionGeneration = 0 }},
		{name: "addresses", mutate: func(value *PeerCandidateParams) { value.Addresses = nil }},
		{name: "creation", mutate: func(value *PeerCandidateParams) { value.CreatedAt = time.Time{} }},
		{name: "expiry", mutate: func(value *PeerCandidateParams) { value.KeyExpiry = value.CreatedAt }},
	} {
		t.Run(test.name, func(t *testing.T) {
			params := base
			params.Addresses = append([]netip.Prefix(nil), base.Addresses...)
			test.mutate(&params)
			if _, err := NewPeerCandidate(params); !errors.Is(err, ErrInvalidPeerCandidate) {
				t.Fatalf("NewPeerCandidate() error = %v, want ErrInvalidPeerCandidate", err)
			}
		})
	}
}

func peerCandidateFixture(
	t *testing.T,
	snapshot Snapshot,
	nodeID string,
	marker byte,
) PeerCandidate {
	t.Helper()
	candidate, err := NewPeerCandidate(peerCandidateParamsFixture(t, snapshot, nodeID, marker))
	if err != nil {
		t.Fatalf("NewPeerCandidate() error = %v", err)
	}
	return candidate
}

func peerCandidateParamsFixture(
	t *testing.T,
	snapshot Snapshot,
	nodeIDValue string,
	marker byte,
) PeerCandidateParams {
	t.Helper()
	nodeID, err := node.ParseID(nodeIDValue)
	if err != nil {
		t.Fatalf("node.ParseID() error = %v", err)
	}
	ownerID, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatalf("identity.ParsePrincipalID() error = %v", err)
	}
	hostname, err := node.ParseHostname(fmt.Sprintf("node-%d.example", marker))
	if err != nil {
		t.Fatalf("node.ParseHostname() error = %v", err)
	}
	machineKey, err := node.NewMachineKey([32]byte{marker})
	if err != nil {
		t.Fatalf("node.NewMachineKey() error = %v", err)
	}
	nodeKey, err := node.NewKey([32]byte{marker + 100})
	if err != nil {
		t.Fatalf("node.NewKey() error = %v", err)
	}
	createdAt := snapshot.CreatedAt().Add(time.Duration(marker) * time.Minute)
	return PeerCandidateParams{
		NumericNodeID:     int64(700) + int64(marker),
		NumericOwnerID:    11,
		Scope:             snapshot.Scope(),
		NodeID:            nodeID,
		OwnerID:           ownerID,
		Hostname:          hostname,
		MachineKey:        machineKey,
		NodeKey:           nodeKey,
		SessionGeneration: int64(marker),
		Addresses:         []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("100.64.0.%d/32", marker))},
		CreatedAt:         createdAt,
		KeyExpiry:         createdAt.Add(24 * time.Hour),
	}
}
