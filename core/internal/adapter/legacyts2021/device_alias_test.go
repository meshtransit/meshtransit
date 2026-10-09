package legacyts2021

import (
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing/sharingtest"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

func TestDeviceAliasMapEncodesExactBothSidedGrant(t *testing.T) {
	t.Parallel()
	for _, protocol := range []policy.Protocol{policy.ProtocolTCP, policy.ProtocolUDP, policy.ProtocolICMP} {
		ports := []policy.PortRange{mapPortRangeFixture(t, 8443, 8443)}
		if protocol == policy.ProtocolICMP {
			ports = nil
		}
		provider, consumer, _ := aliasMapSnapshots(t, protocol, ports, 7)
		for _, self := range []mapsession.Snapshot{provider, consumer} {
			wire := decodeFullMapResponseFixture(t, self)
			if len(wire.Peers) != 1 || wire.Node.SelfNodeV4MasqAddrForThisPeer != nil {
				t.Fatal("invalid peer count or alias on self")
			}
			peer := wire.Peers[0]
			grant, ok := self.DeviceAliasFor(self.AuthorizedPeers()[0].NodeID())
			if !ok {
				t.Fatal("missing grant")
			}
			if !slices.Equal(peer.Addresses, grant.RemoteAddresses) || !slices.Equal(peer.AllowedIPs, grant.RemoteAddresses) ||
				peer.SelfNodeV4MasqAddrForThisPeer == nil || peer.SelfNodeV6MasqAddrForThisPeer == nil ||
				*peer.SelfNodeV4MasqAddrForThisPeer != grant.LocalAddresses[0].Addr() || *peer.SelfNodeV6MasqAddrForThisPeer != grant.LocalAddresses[1].Addr() {
				t.Fatal("wire exposed raw peer address or incomplete aliases")
			}
			documents := peer.CapMap[deviceAliasCapability]
			if len(documents) != 1 {
				t.Fatal("missing typed wire grant")
			}
			var doc deviceAliasDocument
			if err := json.Unmarshal([]byte(documents[0]), &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Version != 1 || doc.ContractID != grant.ContractID.String() || doc.EndpointID != grant.EndpointID.String() ||
				doc.GrantRevision != 14 || doc.Generation != 1 || doc.RecoveryEpoch != 2 ||
				doc.SelfKey != wire.Node.Key.String() || doc.PeerKey != peer.Key.String() || !doc.ExpiresAt.Equal(grant.ExpiresAt) ||
				len(doc.Services) == 0 || (doc.Role == "consumer") != grant.IsConsumer {
				t.Fatal("wire identity/direction/version/deadline mismatch")
			}
			if grant.IsConsumer {
				if len(wire.PacketFilter) != 0 {
					t.Fatal("reverse filter granted")
				}
				continue
			}
			if len(wire.PacketFilter) != 1 {
				t.Fatal("provider filter missing")
			}
			filter := wire.PacketFilter[0]
			for i, source := range filter.SrcIPs {
				if source != grant.RemoteAddresses[i].Addr().String() {
					t.Fatal("wrong source alias")
				}
			}
			for i, destination := range filter.DstPorts {
				if destination.IP != self.Addresses()[i].Addr().String() {
					t.Fatal("filter must use canonical destination after client alias normalization")
				}
			}
		}
	}
}

func TestDeviceAliasAuthorityDeltaReplacesGrantOnRevisionChange(t *testing.T) {
	t.Parallel()
	current, _, _ := aliasMapSnapshots(t, policy.ProtocolTCP, []policy.PortRange{mapPortRangeFixture(t, 8443, 8443)}, 7)
	next, _, _ := aliasMapSnapshots(t, policy.ProtocolTCP, []policy.PortRange{mapPortRangeFixture(t, 8443, 8443)}, 8)
	delta, err := mapsession.NewAuthorityDelta(current, next)
	if err != nil {
		t.Fatal(err)
	}
	if len(delta.ChangedPeers()) != 1 {
		t.Fatal("alias grant revision changed without peer replacement")
	}
	_, wire := decodeAuthorityDeltaFixture(t, delta)
	var doc deviceAliasDocument
	if err := json.Unmarshal([]byte(wire.PeersChanged[0].CapMap[deviceAliasCapability][0]), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.GrantRevision != 15 {
		t.Fatal("stale grant revision in delta")
	}
}

func aliasMapSnapshots(t *testing.T, protocol policy.Protocol, ports []policy.PortRange, providerRevision int64) (mapsession.Snapshot, mapsession.Snapshot, mapsession.Snapshot) {
	t.Helper()
	p := mapSnapshotParams(mapSnapshotFixture(t))
	p.PeerCandidates = nil
	p.NetworkRevision = providerRevision
	p.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd00:10::1/128")}
	provider, err := mapsession.NewSnapshot(p)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000102")
	if err != nil {
		t.Fatal(err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000202")
	if err != nil {
		t.Fatal(err)
	}
	p.Scope, err = network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	p.NodeID, err = node.ParseID("01890f00-0000-7000-8000-000000000702")
	if err != nil {
		t.Fatal(err)
	}
	p.NumericNodeID = 702
	p.NetworkRevision = 7
	p.NodeKey, err = node.NewKey([32]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	p.MachineKey, err = node.NewMachineKey([32]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	p.PacketPolicy, err = policy.NewSnapshot(policy.SnapshotParams{Scope: p.Scope, Revision: 5})
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := mapsession.NewSnapshot(p)
	if err != nil {
		t.Fatal(err)
	}
	evidence := sharingtest.New(t, sharingtest.Params{ProviderScope: provider.Scope(), ConsumerScope: consumer.Scope(),
		ProviderDeviceID: provider.NodeID(), ConsumerDeviceID: consumer.NodeID(), ProviderAddress: netip.MustParseAddr("100.96.0.1"),
		EvaluatedAt: provider.CreatedAt().Add(time.Hour), RecoveryEpoch: provider.RecoveryEpoch(), Protocol: protocol, Ports: ports})
	return aliasMapProjection(t, provider, consumer, evidence, providerRevision), aliasMapProjection(t, consumer, provider, evidence, providerRevision), provider
}

func aliasMapProjection(t *testing.T, self, peer mapsession.Snapshot, evidence sharingtest.Evidence, providerRevision int64) mapsession.Snapshot {
	t.Helper()
	owner, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	resource := []netip.Prefix{netip.MustParsePrefix("100.96.0.1/32"), netip.MustParsePrefix("fd00:feed::1/128")}
	source := []netip.Prefix{netip.MustParsePrefix("100.96.1.1/32"), netip.MustParsePrefix("fd00:feed:1::1/128")}
	local, remote := resource, source
	if self.Scope() == evidence.Authority.Contract.ConsumerScope() {
		local, remote = source, resource
	}
	candidate, err := mapsession.NewPeerCandidate(mapsession.PeerCandidateParams{NumericNodeID: peer.NumericNodeID(), NumericOwnerID: peer.NumericOwnerID(), Scope: peer.Scope(),
		NodeID: peer.NodeID(), OwnerID: owner, Hostname: peer.Hostname(), MachineKey: peer.MachineKey(), NodeKey: peer.NodeKey(), SessionGeneration: peer.SessionGeneration(), Addresses: remote, CreatedAt: peer.CreatedAt(), KeyExpiry: peer.KeyExpiry()})
	if err != nil {
		t.Fatal(err)
	}
	aliases, err := mapsession.NewDeviceAlias(mapsession.DeviceAliasParams{ContractID: evidence.Authority.Contract.ID(), EndpointID: evidence.Authority.Endpoint.ID(), Generation: 1, RecoveryEpoch: self.RecoveryEpoch(),
		SelfKey: self.NodeKey(), PeerKey: peer.NodeKey(), SelfSessionGeneration: self.SessionGeneration(), PeerSessionGeneration: peer.SessionGeneration(), LocalAddresses: local, RemoteAddresses: remote, ExpiresAt: evidence.Authority.Endpoint.ExpiresAt()})
	if err != nil {
		t.Fatal(err)
	}
	projection, err := mapsession.NewDirectDeviceProjection(mapsession.DirectDeviceProjectionParams{Self: self, Peer: candidate, ProviderTarget: evidence.Target, ProviderExport: evidence.Export,
		Authority: evidence.Authority, ConsumerRule: evidence.Rule, ProviderNetworkRevision: providerRevision, ConsumerNetworkRevision: 7, ConsumerPolicyRevision: 5, Aliases: aliases})
	if err != nil {
		t.Fatal(err)
	}
	result, err := self.WithDirectDeviceProjections([]mapsession.DirectDeviceProjection{projection})
	if err != nil {
		t.Fatal(err)
	}
	result, err = result.WithConnectivity([]mapsession.Connectivity{mapConnectivityWithoutEndpointsFixture(t, self.NodeID(), self.SessionGeneration(), true), mapConnectivityWithoutEndpointsFixture(t, peer.NodeID(), peer.SessionGeneration(), true)})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

var aliasSharingFixtureOutput = flag.String("alias-sharing-fixture-output", "", "explicit output directory for synthetic Core alias frames")

// TestExportDeviceAliasFrames produces synthetic owned conformance fixtures.
// It does not admit a runtime client or qualify live sharing.
func TestExportDeviceAliasFrames(t *testing.T) {
	if *aliasSharingFixtureOutput == "" {
		t.Skip("explicit fixture output directory required")
	}
	for _, test := range []struct {
		name     string
		protocol policy.Protocol
		ports    []policy.PortRange
	}{
		{"tcp", policy.ProtocolTCP, []policy.PortRange{mapPortRangeFixture(t, 8443, 8443)}},
		{"udp", policy.ProtocolUDP, []policy.PortRange{mapPortRangeFixture(t, 8443, 8443)}},
		{"icmp", policy.ProtocolICMP, nil},
	} {
		provider, consumer, _ := aliasMapSnapshots(t, test.protocol, test.ports, 7)
		for name, snapshot := range map[string]mapsession.Snapshot{"provider": provider, "consumer": consumer} {
			wire := decodeFullMapResponseFixture(t, snapshot)
			body, err := json.MarshalIndent(wire, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(*aliasSharingFixtureOutput, name+"-"+test.name+".json"), append(body, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
