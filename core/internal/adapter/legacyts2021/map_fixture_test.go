package legacyts2021

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

const mapRequestBody = `{
  "Version":142,
  "Compress":"zstd",
  "KeepAlive":true,
  "NodeKey":"nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  "Stream":false,
  "OmitPeers":false,
  "Hostinfo":{"Hostname":"node-one.example"}
}`

func mapSnapshotFixture(t *testing.T) mapsession.Snapshot {
	t.Helper()
	return mapSnapshotFixtureWithCandidates(t, nil)
}

func mapSnapshotWithCandidateFixture(t *testing.T) mapsession.Snapshot {
	t.Helper()
	base := mapSnapshotFixture(t)
	peerNodeID, err := node.ParseID("01890f00-0000-7000-8000-000000000702")
	if err != nil {
		t.Fatalf("node.ParseID(peer) error = %v", err)
	}
	ownerID, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatalf("identity.ParsePrincipalID() error = %v", err)
	}
	hostname, err := node.ParseHostname("node-two.example")
	if err != nil {
		t.Fatalf("node.ParseHostname(peer) error = %v", err)
	}
	machineKey, err := node.NewMachineKey([32]byte{2})
	if err != nil {
		t.Fatalf("node.NewMachineKey(peer) error = %v", err)
	}
	nodeKey, err := node.NewKey([32]byte{3})
	if err != nil {
		t.Fatalf("node.NewKey(peer) error = %v", err)
	}
	candidate, err := mapsession.NewPeerCandidate(mapsession.PeerCandidateParams{
		NumericNodeID:     702,
		NumericOwnerID:    11,
		Scope:             base.Scope(),
		NodeID:            peerNodeID,
		OwnerID:           ownerID,
		Hostname:          hostname,
		MachineKey:        machineKey,
		NodeKey:           nodeKey,
		SessionGeneration: 1,
		Addresses:         []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		CreatedAt:         base.CreatedAt(),
		KeyExpiry:         base.KeyExpiry(),
	})
	if err != nil {
		t.Fatalf("mapsession.NewPeerCandidate() error = %v", err)
	}
	return mapSnapshotFixtureWithCandidates(t, []mapsession.PeerCandidate{candidate})
}

func mapSnapshotWithAuthorizedCandidateFixture(t *testing.T) mapsession.Snapshot {
	t.Helper()
	base := mapSnapshotWithCandidateFixture(t)
	candidate := base.PeerCandidates()[0]
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000801")
	if err != nil {
		t.Fatalf("policy.ParseRuleID() error = %v", err)
	}
	rule, err := policy.NewRule(policy.RuleParams{
		ID:                ruleID,
		Scope:             base.Scope(),
		SourceNodeID:      base.NodeID(),
		DestinationNodeID: candidate.NodeID(),
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
	params := mapsession.SnapshotParams{
		Scope:             base.Scope(),
		NetworkName:       base.NetworkName(),
		NetworkRevision:   base.NetworkRevision(),
		RecoveryEpoch:     base.RecoveryEpoch(),
		SessionGeneration: base.SessionGeneration(),
		NumericNodeID:     base.NumericNodeID(),
		NumericOwnerID:    base.NumericOwnerID(),
		NodeID:            base.NodeID(),
		Hostname:          base.Hostname(),
		MachineKey:        base.MachineKey(),
		NodeKey:           base.NodeKey(),
		Addresses:         base.Addresses(),
		CreatedAt:         base.CreatedAt(),
		KeyExpiry:         base.KeyExpiry(),
		PeerCandidates:    base.PeerCandidates(),
		PacketPolicy:      packetPolicy,
		RelayDirectory:    base.RelayDirectory(),
	}
	snapshot, err := mapsession.NewSnapshot(params)
	if err != nil {
		t.Fatalf("mapsession.NewSnapshot() error = %v", err)
	}
	return snapshot
}

func mapSnapshotWithInboundPolicyFixture(t *testing.T) mapsession.Snapshot {
	t.Helper()
	base := mapSnapshotWithCandidateFixture(t)
	candidate := base.PeerCandidates()[0]
	rules := make([]policy.Rule, 0, 3)
	for _, params := range []policy.RuleParams{
		{
			ID:                    mapRuleIDFixture(t, "01890f00-0000-7000-8000-000000000801"),
			Scope:                 base.Scope(),
			SourceNodeID:          candidate.NodeID(),
			DestinationNodeID:     base.NodeID(),
			Protocol:              policy.ProtocolTCP,
			DestinationPortRanges: []policy.PortRange{mapPortRangeFixture(t, 80, 81), mapPortRangeFixture(t, 443, 443)},
		},
		{
			ID:                mapRuleIDFixture(t, "01890f00-0000-7000-8000-000000000802"),
			Scope:             base.Scope(),
			SourceNodeID:      candidate.NodeID(),
			DestinationNodeID: base.NodeID(),
			Protocol:          policy.ProtocolICMP,
		},
		{
			ID:                    mapRuleIDFixture(t, "01890f00-0000-7000-8000-000000000803"),
			Scope:                 base.Scope(),
			SourceNodeID:          base.NodeID(),
			DestinationNodeID:     candidate.NodeID(),
			Protocol:              policy.ProtocolUDP,
			DestinationPortRanges: []policy.PortRange{mapPortRangeFixture(t, 53, 53)},
		},
	} {
		rule, err := policy.NewRule(params)
		if err != nil {
			t.Fatalf("policy.NewRule() error = %v", err)
		}
		rules = append(rules, rule)
	}
	packetPolicy, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    base.Scope(),
		Revision: base.PacketPolicy().Revision(),
		Rules:    rules,
	})
	if err != nil {
		t.Fatalf("policy.NewSnapshot() error = %v", err)
	}
	params := mapSnapshotParams(base)
	params.PacketPolicy = packetPolicy
	snapshot, err := mapsession.NewSnapshot(params)
	if err != nil {
		t.Fatalf("mapsession.NewSnapshot() error = %v", err)
	}
	return snapshot
}

func mapSnapshotWithInboundTransportPolicyFixture(t *testing.T) mapsession.Snapshot {
	t.Helper()
	base := mapSnapshotWithInboundPolicyFixture(t)
	peers := base.PeerCandidates()
	if len(peers) != 1 {
		t.Fatalf("PeerCandidates() = %d, want 1", len(peers))
	}
	rules := base.PacketPolicy().Rules()
	udpRule, err := policy.NewRule(policy.RuleParams{
		ID:                mapRuleIDFixture(t, "01890f00-0000-7000-8000-000000000804"),
		Scope:             base.Scope(),
		SourceNodeID:      peers[0].NodeID(),
		DestinationNodeID: base.NodeID(),
		Protocol:          policy.ProtocolUDP,
		DestinationPortRanges: []policy.PortRange{
			mapPortRangeFixture(t, 53, 53),
			mapPortRangeFixture(t, 5353, 5354),
		},
	})
	if err != nil {
		t.Fatalf("policy.NewRule(UDP) error = %v", err)
	}
	rules = append(rules, udpRule)
	packetPolicy, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: base.Scope(), Revision: base.PacketPolicy().Revision(), Rules: rules,
	})
	if err != nil {
		t.Fatalf("policy.NewSnapshot() error = %v", err)
	}
	params := mapSnapshotParams(base)
	params.PacketPolicy = packetPolicy
	snapshot, err := mapsession.NewSnapshot(params)
	if err != nil {
		t.Fatalf("mapsession.NewSnapshot() error = %v", err)
	}
	return snapshot
}

func mapRuleIDFixture(t *testing.T, value string) policy.RuleID {
	t.Helper()
	id, err := policy.ParseRuleID(value)
	if err != nil {
		t.Fatalf("policy.ParseRuleID() error = %v", err)
	}
	return id
}

func mapPortRangeFixture(t *testing.T, first, last uint16) policy.PortRange {
	t.Helper()
	portRange, err := policy.NewPortRange(first, last)
	if err != nil {
		t.Fatalf("policy.NewPortRange() error = %v", err)
	}
	return portRange
}

func mapSnapshotParams(base mapsession.Snapshot) mapsession.SnapshotParams {
	return mapsession.SnapshotParams{
		Scope:             base.Scope(),
		NetworkName:       base.NetworkName(),
		NetworkRevision:   base.NetworkRevision(),
		RecoveryEpoch:     base.RecoveryEpoch(),
		SessionGeneration: base.SessionGeneration(),
		NumericNodeID:     base.NumericNodeID(),
		NumericOwnerID:    base.NumericOwnerID(),
		NodeID:            base.NodeID(),
		Hostname:          base.Hostname(),
		MachineKey:        base.MachineKey(),
		NodeKey:           base.NodeKey(),
		Addresses:         base.Addresses(),
		CreatedAt:         base.CreatedAt(),
		KeyExpiry:         base.KeyExpiry(),
		PeerCandidates:    base.PeerCandidates(),
		PacketPolicy:      base.PacketPolicy(),
		RelayDirectory:    base.RelayDirectory(),
	}
}

func mapSnapshotFixtureWithCandidates(
	t *testing.T,
	peerCandidates []mapsession.PeerCandidate,
) mapsession.Snapshot {
	t.Helper()
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	networkName, err := network.ParseDisplayName("Development Mesh")
	if err != nil {
		t.Fatalf("network.ParseDisplayName() error = %v", err)
	}
	nodeID, err := node.ParseID("01890f00-0000-7000-8000-000000000701")
	if err != nil {
		t.Fatalf("node.ParseID() error = %v", err)
	}
	hostname, err := node.ParseHostname("node-one.example")
	if err != nil {
		t.Fatalf("node.ParseHostname() error = %v", err)
	}
	machineKey, err := node.NewMachineKey([32]byte{1})
	if err != nil {
		t.Fatalf("node.NewMachineKey() error = %v", err)
	}
	var rawNodeKey [32]byte
	for index := range rawNodeKey {
		rawNodeKey[index] = byte(index + 1)
	}
	nodeKey, err := node.NewKey(rawNodeKey)
	if err != nil {
		t.Fatalf("node.NewKey() error = %v", err)
	}
	createdAt := time.Date(2026, time.September, 14, 3, 0, 0, 0, time.UTC)
	packetPolicy, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope:    scope,
		Revision: 5,
		Rules:    nil,
	})
	if err != nil {
		t.Fatalf("policy.NewSnapshot() error = %v", err)
	}
	snapshot, err := mapsession.NewSnapshot(mapsession.SnapshotParams{
		Scope:             scope,
		NetworkName:       networkName,
		NetworkRevision:   7,
		RecoveryEpoch:     2,
		SessionGeneration: 3,
		NumericNodeID:     701,
		NumericOwnerID:    11,
		NodeID:            nodeID,
		Hostname:          hostname,
		MachineKey:        machineKey,
		NodeKey:           nodeKey,
		Addresses:         []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		CreatedAt:         createdAt,
		KeyExpiry:         createdAt.Add(24 * time.Hour),
		PeerCandidates:    peerCandidates,
		PacketPolicy:      packetPolicy,
		RelayDirectory:    mapRelayDirectoryFixture(t),
	})
	if err != nil {
		t.Fatalf("mapsession.NewSnapshot() error = %v", err)
	}
	return snapshot
}

func mapRelayDirectoryFixture(t *testing.T) relay.Directory {
	t.Helper()
	relayNode, err := relay.NewNode(relay.NodeParams{
		Name:      "1a",
		HostName:  "relay-sin.example.com",
		CertName:  "relay-cert-sin.example.com",
		IPv4:      "192.0.2.10",
		IPv6:      "2001:db8::10",
		STUNPort:  3478,
		RelayPort: 443,
	})
	if err != nil {
		t.Fatalf("relay.NewNode() error = %v", err)
	}
	stunNode, err := relay.NewNode(relay.NodeParams{
		Name: "1b", HostName: "stun-sin.example.com", IPv4: "192.0.2.11",
		IPv6: "none", STUNPort: 3478, IsSTUNOnly: true,
	})
	if err != nil {
		t.Fatalf("relay.NewNode(STUN only) error = %v", err)
	}
	region, err := relay.NewRegion(relay.RegionParams{
		ID: 1, Code: "sin", Name: "Singapore", Nodes: []relay.Node{relayNode, stunNode},
	})
	if err != nil {
		t.Fatalf("relay.NewRegion() error = %v", err)
	}
	directory, err := relay.NewDirectory(relay.DirectoryParams{
		Revision: 1,
		Regions:  []relay.Region{region},
	})
	if err != nil {
		t.Fatalf("relay.NewDirectory() error = %v", err)
	}
	return directory
}
