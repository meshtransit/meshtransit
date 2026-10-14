package mtcp

import (
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/relay"
	"meshtransit.net/core/internal/domain/workspace"
)

// must panics on a fixture error; fixtures are fixed values.
func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func relayDirectoryFixture(t *testing.T) relay.Directory {
	t.Helper()
	relayNode := must(relay.NewNode(relay.NodeParams{Name: "1a", HostName: "relay-sin.example.com",
		CertName: "relay-cert-sin.example.com", IPv4: "192.0.2.10", IPv6: "2001:db8::10", STUNPort: 3478, RelayPort: 443}))
	region := must(relay.NewRegion(relay.RegionParams{ID: 1, Code: "sin", Name: "Singapore",
		Nodes: []relay.Node{relayNode}}))
	return must(relay.NewDirectory(relay.DirectoryParams{Revision: 1, Regions: []relay.Region{region}}))
}

func peerFixture(t *testing.T, scope network.Scope, id string, numeric int64, address string, keyByte byte) mapsession.PeerCandidate {
	t.Helper()
	createdAt := time.Date(2026, time.September, 14, 3, 0, 0, 0, time.UTC)
	return must(mapsession.NewPeerCandidate(mapsession.PeerCandidateParams{
		NumericNodeID: numeric, NumericOwnerID: 11, Scope: scope,
		NodeID:            must(node.ParseID(id)),
		OwnerID:           must(identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")),
		Hostname:          must(node.ParseHostname("peer-" + address[len(address)-1:] + ".example")),
		MachineKey:        must(node.NewMachineKey([32]byte{keyByte, 0xaa})),
		NodeKey:           must(node.NewKey([32]byte{keyByte, 0xbb})),
		SessionGeneration: 1, Addresses: []netip.Prefix{netip.MustParsePrefix(address + "/32")},
		CreatedAt: createdAt, KeyExpiry: createdAt.Add(24 * time.Hour),
	}))
}

// snapshotFixture is node-one (100.64.0.1) with peers whose rules open TCP
// 80-81 and 443, ICMP and UDP 53, 5353-5354 to it, plus an outbound rule
// that must not appear in its inbound filter.
func snapshotFixture(t *testing.T, revision int64, peers ...mapsession.PeerCandidate) mapsession.Snapshot {
	t.Helper()
	return snapshotGenerationFixture(t, revision, 3, peers...)
}

// snapshotGenerationFixture is snapshotFixture for a session generation.
func snapshotGenerationFixture(t *testing.T, revision, generation int64,
	peers ...mapsession.PeerCandidate) mapsession.Snapshot {
	t.Helper()
	scope := must(network.NewScope(must(workspace.ParseID("01890f00-0000-7000-8000-000000000101")),
		must(network.ParseID("01890f00-0000-7000-8000-000000000201"))))
	self := must(node.ParseID("01890f00-0000-7000-8000-000000000701"))
	if len(peers) == 0 {
		peers = []mapsession.PeerCandidate{peerFixture(t, scope, "01890f00-0000-7000-8000-000000000702", 702, "100.64.0.2", 2)}
	}
	ports := func(first, last uint16) policy.PortRange { return must(policy.NewPortRange(first, last)) }
	var rules []policy.Rule
	for index, peer := range peers {
		for kind, params := range []policy.RuleParams{
			{SourceNodeID: peer.NodeID(), DestinationNodeID: self, Protocol: policy.ProtocolTCP,
				DestinationPortRanges: []policy.PortRange{ports(80, 81), ports(443, 443)}},
			{SourceNodeID: peer.NodeID(), DestinationNodeID: self, Protocol: policy.ProtocolICMP},
			{SourceNodeID: peer.NodeID(), DestinationNodeID: self, Protocol: policy.ProtocolUDP,
				DestinationPortRanges: []policy.PortRange{ports(53, 53), ports(5353, 5354)}},
			{SourceNodeID: self, DestinationNodeID: peer.NodeID(), Protocol: policy.ProtocolUDP,
				DestinationPortRanges: []policy.PortRange{ports(53, 53)}},
		} {
			params.ID = must(policy.ParseRuleID("01890f00-0000-7000-8000-0000000008" + string(rune('0'+index)) + string(rune('0'+kind))))
			params.Scope = scope
			rules = append(rules, must(policy.NewRule(params)))
		}
	}
	createdAt := time.Date(2026, time.September, 14, 3, 0, 0, 0, time.UTC)
	return must(mapsession.NewSnapshot(mapsession.SnapshotParams{
		Scope: scope, NetworkName: must(network.ParseDisplayName("Development Mesh")),
		NetworkRevision: revision, RecoveryEpoch: 2, SessionGeneration: generation, NumericNodeID: 701, NumericOwnerID: 11,
		NodeID: self, Hostname: must(node.ParseHostname("node-one.example")),
		MachineKey: must(node.NewMachineKey([32]byte{1})), NodeKey: must(node.NewKey([32]byte{1, 2, 3})),
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}, CreatedAt: createdAt,
		KeyExpiry: createdAt.Add(24 * time.Hour), PeerCandidates: peers,
		PacketPolicy:   must(policy.NewSnapshot(policy.SnapshotParams{Scope: scope, Revision: 5, Rules: rules})),
		RelayDirectory: relayDirectoryFixture(t),
	}))
}

// streamFixture is snapshotFixture with complete connectivity, alternating
// between one and two peers so consecutive revisions form authority deltas.
func streamFixture(t *testing.T, revision int64) mapsession.Snapshot {
	t.Helper()
	scope := snapshotFixture(t, 1).Scope()
	peers := []mapsession.PeerCandidate{
		peerFixture(t, scope, "01890f00-0000-7000-8000-000000000702", 702, "100.64.0.2", 2),
		peerFixture(t, scope, "01890f00-0000-7000-8000-000000000703", 703, "100.64.0.3", 3),
	}
	snapshot := snapshotFixture(t, revision, peers[:1+revision%2]...)
	connectivity := []mapsession.Connectivity{must(mapsession.NewConnectivity(mapsession.ConnectivityParams{
		Key: must(mapsession.NewConnectivityKey(snapshot.NodeID(), snapshot.SessionGeneration())), Online: true,
	}))}
	for _, peer := range snapshot.AuthorizedPeers() {
		connectivity = append(connectivity, must(mapsession.NewConnectivity(mapsession.ConnectivityParams{
			Key: must(mapsession.NewConnectivityKey(peer.NodeID(), peer.SessionGeneration())), Online: true,
		})))
	}
	return must(snapshot.WithConnectivity(connectivity))
}
