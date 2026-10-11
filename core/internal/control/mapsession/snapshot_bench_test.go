package mapsession

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

// largeNetworkFixture returns a snapshot of a Network with candidates other
// Devices, of which self has rules to the first peers.
func largeNetworkFixture(tb testing.TB, candidates, peers int) (SnapshotParams, []PeerCandidate) {
	tb.Helper()
	base := snapshotFixture(tb)
	ownerID, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	if err != nil {
		tb.Fatal(err)
	}
	list := make([]PeerCandidate, 0, candidates)
	for index := range candidates {
		ordinal := index + 2 // self is 1
		nodeID, err := node.ParseID(fmt.Sprintf("01890f00-0000-7000-8000-%012x", 0x10000+ordinal))
		if err != nil {
			tb.Fatal(err)
		}
		hostname, err := node.ParseHostname(fmt.Sprintf("node-%d.example", ordinal))
		if err != nil {
			tb.Fatal(err)
		}
		machineKey, err := node.NewMachineKey(sha256.Sum256(binary.BigEndian.AppendUint64([]byte("m"), uint64(ordinal))))
		if err != nil {
			tb.Fatal(err)
		}
		nodeKey, err := node.NewKey(sha256.Sum256(binary.BigEndian.AppendUint64([]byte("n"), uint64(ordinal))))
		if err != nil {
			tb.Fatal(err)
		}
		address := netip.AddrFrom4([4]byte{100, 64 + byte(ordinal>>16), byte(ordinal >> 8), byte(ordinal)})
		created := base.CreatedAt().Add(time.Duration(ordinal) * time.Second)
		candidate, err := NewPeerCandidate(PeerCandidateParams{
			NumericNodeID: int64(1000 + ordinal), NumericOwnerID: 11, Scope: base.Scope(), NodeID: nodeID,
			OwnerID: ownerID, Hostname: hostname, MachineKey: machineKey, NodeKey: nodeKey, SessionGeneration: 1,
			Addresses: []netip.Prefix{netip.PrefixFrom(address, 32)}, CreatedAt: created, KeyExpiry: created.Add(24 * time.Hour),
		})
		if err != nil {
			tb.Fatal(err)
		}
		list = append(list, candidate)
	}
	rules := make([]policy.Rule, 0, peers)
	for index := range peers {
		ruleID, err := policy.ParseRuleID(fmt.Sprintf("01890f00-0000-7000-8000-%012x", 0x900000+index))
		if err != nil {
			tb.Fatal(err)
		}
		rule, err := policy.NewRule(policy.RuleParams{ID: ruleID, Scope: base.Scope(), SourceNodeID: base.NodeID(),
			DestinationNodeID: list[index].NodeID(), Protocol: policy.ProtocolICMP})
		if err != nil {
			tb.Fatal(err)
		}
		rules = append(rules, rule)
	}
	packetPolicy, err := policy.NewSnapshot(policy.SnapshotParams{Scope: base.Scope(), Revision: base.PacketPolicy().Revision(), Rules: rules})
	if err != nil {
		tb.Fatal(err)
	}
	params := base.params()
	params.PeerCandidates = list
	params.PacketPolicy = packetPolicy
	return params, list
}

// BenchmarkSnapshotRefresh measures what a stream refresh does with one
// snapshot: build it, check it and list the authorized peers.
func BenchmarkSnapshotRefresh(b *testing.B) {
	for _, size := range []struct{ candidates, peers int }{{1000, 50}, {10000, 50}, {10000, 500}} {
		b.Run(fmt.Sprintf("candidates=%d/peers=%d", size.candidates, size.peers), func(b *testing.B) {
			params, _ := largeNetworkFixture(b, size.candidates, size.peers)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				snapshot, err := NewSnapshot(params)
				if err != nil {
					b.Fatal(err)
				}
				if !snapshot.IsValid() || len(snapshot.AuthorizedPeers()) != size.peers {
					b.Fatal("unexpected snapshot")
				}
			}
		})
	}
}
