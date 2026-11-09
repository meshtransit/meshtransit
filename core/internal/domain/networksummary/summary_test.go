package networksummary

import (
	"net/netip"
	"testing"
	"time"
)

func validSummary() Summary {
	at := time.Date(2026, time.November, 9, 8, 0, 0, 0, time.UTC)
	return Summary{
		WorkspaceID: 103, NetworkID: 203, NetworkRevision: 7, DirtyGeneration: 3, EvaluatedAt: at,
		IPv4Prefix: netip.MustParsePrefix("100.80.0.0/24"), AddressesCapacity: 254, AddressesInUse: 10,
		AddressesHeld: 2, ActiveDevices: 9, RuleCount: 4, PolicyRevision: 2, SharesOutActive: 1,
		RecomputeAt: at.Add(time.Hour),
		Peers: []Peer{{Direction: "outgoing", PeerWorkspaceID: 103, PeerNetworkID: 204, Active: 1},
			{Direction: "incoming", PeerWorkspaceID: 104, Waiting: 1}},
	}
}

func TestSummaryValidateAcceptsATrueSnapshot(t *testing.T) {
	t.Parallel()
	if err := validSummary().Validate(); err != nil {
		t.Fatal(err)
	}
	noRange := validSummary()
	noRange.IPv4Prefix, noRange.AddressesCapacity, noRange.AddressesInUse, noRange.AddressesHeld = netip.Prefix{}, 0, 0, 0
	if err := noRange.Validate(); err != nil {
		t.Fatal("a Network without an IPv4 range was refused", err)
	}
}

func TestSummaryValidateRefusesImpossibleFigures(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*Summary){
		"negative count":          func(summary *Summary) { summary.ActiveDevices = -1 },
		"no marker":               func(summary *Summary) { summary.NetworkRevision = 0 },
		"no evaluation time":      func(summary *Summary) { summary.EvaluatedAt = time.Time{} },
		"wrong capacity":          func(summary *Summary) { summary.AddressesCapacity = 256 },
		"more taken than room":    func(summary *Summary) { summary.AddressesInUse = 300 },
		"IPv6 as the IPv4 range":  func(summary *Summary) { summary.IPv4Prefix = netip.MustParsePrefix("fd00::/64") },
		"addresses without range": func(summary *Summary) { summary.IPv4Prefix = netip.Prefix{} },
		"recompute in the past":   func(summary *Summary) { summary.RecomputeAt = summary.EvaluatedAt },
		"peer is itself":          func(summary *Summary) { summary.Peers[0].PeerNetworkID = 203 },
		"foreign Network named":   func(summary *Summary) { summary.Peers[1].PeerNetworkID = 999 },
		"empty peer":              func(summary *Summary) { summary.Peers[0].Active = 0 },
		"unknown direction":       func(summary *Summary) { summary.Peers[0].Direction = "both" },
	} {
		summary := validSummary()
		summary.Peers = append([]Peer(nil), summary.Peers...)
		change(&summary)
		if summary.Validate() == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
