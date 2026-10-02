package legacyts2021

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/sharing/sharingtest"
	"tailscale.com/util/zstdframe"
)

func TestDirectDeviceMapEncodesOnlyDirectionalHostAccess(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name          string
		protocol      policy.Protocol
		ports         []policy.PortRange
		wireProtocols []int
	}{
		{"ICMP both families", policy.ProtocolICMP, nil, []int{1, 58}},
		{"TCP one port", policy.ProtocolTCP, []policy.PortRange{mapPortRangeFixture(t, 443, 443)}, []int{6}},
		{"UDP one port", policy.ProtocolUDP, []policy.PortRange{mapPortRangeFixture(t, 53, 53)}, []int{17}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			provider, consumer, _ := directMapSnapshots(t, test.protocol, test.ports)
			providerWire := decodeFullMapResponseFixture(t, provider)
			consumerWire := decodeFullMapResponseFixture(t, consumer)
			if len(providerWire.Peers) != 1 || len(consumerWire.Peers) != 1 || len(consumerWire.PacketFilter) != 0 ||
				len(providerWire.PacketFilter) != 1 {
				t.Fatal("unexpected visibility or reverse grant")
			}
			if !slices.Equal(providerWire.Peers[0].AllowedIPs, consumer.Addresses()) ||
				!slices.Equal(consumerWire.Peers[0].AllowedIPs, provider.Addresses()) {
				t.Fatal("sharing installed broader routes than exact host prefixes")
			}
			if !providerWire.Peers[0].KeyExpiry.Equal(provider.ProjectionExpiry()) ||
				!consumerWire.Peers[0].KeyExpiry.Equal(consumer.ProjectionExpiry()) {
				t.Fatal("wire peer outlived sharing grant")
			}
			filter := providerWire.PacketFilter[0]
			if !slices.Equal(filter.IPProto, test.wireProtocols) ||
				!slices.Equal(filter.SrcIPs, []string{"100.64.0.2", "2001:db8::2"}) || len(filter.DstPorts) != 2 {
				t.Fatalf("unexpected inbound tuple: %+v", filter)
			}
			for index, destination := range filter.DstPorts {
				if destination.IP != provider.Addresses()[index].Addr().String() {
					t.Fatal("wrong exported Device")
				}
				if test.protocol != policy.ProtocolICMP && (destination.Ports.First != test.ports[0].First() ||
					destination.Ports.Last != test.ports[0].Last()) {
					t.Fatal("widened port range")
				}
			}
		})
	}
}

func TestDirectDeviceAuthorityDeltaWithdrawsPeerAndFilterTogether(t *testing.T) {
	t.Parallel()
	provider, _, base := directMapSnapshots(t, policy.ProtocolICMP, nil)
	params := mapSnapshotParams(base)
	params.NetworkRevision++
	next, err := mapsession.NewSnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	next, err = next.WithConnectivity([]mapsession.Connectivity{
		mapConnectivityWithoutEndpointsFixture(t, next.NodeID(), next.SessionGeneration(), true),
	})
	if err != nil {
		t.Fatal(err)
	}
	delta, err := mapsession.NewAuthorityDelta(provider, next)
	if err != nil {
		t.Fatal(err)
	}
	fields, wire := decodeAuthorityDeltaFixture(t, delta)
	if string(fields["PacketFilter"]) != "[]" || len(wire.PeersChanged) != 0 ||
		len(wire.PeersRemoved) != 1 || int64(wire.PeersRemoved[0]) != provider.AuthorizedPeers()[0].NumericNodeID() {
		t.Fatal("withdrawal frame retained peer or inbound allow")
	}
	full := decodeFullMapResponseFixture(t, next)
	if len(full.Peers) != 0 || len(full.PacketFilter) != 0 {
		t.Fatal("full resync retained withdrawn sharing")
	}
}

func directMapSnapshots(t *testing.T, protocol policy.Protocol, ports []policy.PortRange) (mapsession.Snapshot, mapsession.Snapshot, mapsession.Snapshot) {
	t.Helper()
	params := mapSnapshotParams(mapSnapshotFixture(t))
	params.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("2001:db8::1/128")}
	provider, err := mapsession.NewSnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000202")
	if err != nil {
		t.Fatal(err)
	}
	params.Scope, err = network.NewScope(provider.Scope().WorkspaceID(), networkID)
	if err != nil {
		t.Fatal(err)
	}
	params.NodeID, err = node.ParseID("01890f00-0000-7000-8000-000000000702")
	if err != nil {
		t.Fatal(err)
	}
	params.NumericNodeID = 702
	params.NodeKey, err = node.NewKey([32]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	params.MachineKey, err = node.NewMachineKey([32]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	params.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32"), netip.MustParsePrefix("2001:db8::2/128")}
	params.PacketPolicy, err = policy.NewSnapshot(policy.SnapshotParams{Scope: params.Scope, Revision: 5})
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := mapsession.NewSnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	evidence := sharingtest.New(t, sharingtest.Params{
		ProviderScope: provider.Scope(), ConsumerScope: consumer.Scope(), ProviderDeviceID: provider.NodeID(),
		ConsumerDeviceID: consumer.NodeID(), ProviderAddress: provider.Addresses()[0].Addr(),
		EvaluatedAt: provider.CreatedAt().Add(time.Hour), RecoveryEpoch: provider.RecoveryEpoch(), Protocol: protocol, Ports: ports,
	})
	providerMap := directMapProjection(t, provider, consumer, evidence)
	consumerMap := directMapProjection(t, consumer, provider, evidence)
	return providerMap, consumerMap, provider
}

func directMapProjection(t *testing.T, self, peer mapsession.Snapshot, evidence sharingtest.Evidence) mapsession.Snapshot {
	t.Helper()
	owner, err := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := mapsession.NewPeerCandidate(mapsession.PeerCandidateParams{
		NumericNodeID: peer.NumericNodeID(), NumericOwnerID: peer.NumericOwnerID(), Scope: peer.Scope(),
		NodeID: peer.NodeID(), OwnerID: owner, Hostname: peer.Hostname(), MachineKey: peer.MachineKey(),
		NodeKey: peer.NodeKey(), SessionGeneration: peer.SessionGeneration(), Addresses: peer.Addresses(),
		CreatedAt: peer.CreatedAt(), KeyExpiry: peer.KeyExpiry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	projection, err := mapsession.NewDirectDeviceProjection(mapsession.DirectDeviceProjectionParams{
		Self: self, Peer: candidate, ProviderTarget: evidence.Target, ProviderExport: evidence.Export,
		Authority: evidence.Authority, ConsumerRule: evidence.Rule, ProviderNetworkRevision: 7,
		ConsumerNetworkRevision: 7, ConsumerPolicyRevision: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := self.WithDirectDeviceProjections([]mapsession.DirectDeviceProjection{projection})
	if err != nil {
		t.Fatal(err)
	}
	result, err = result.WithConnectivity([]mapsession.Connectivity{
		mapConnectivityWithoutEndpointsFixture(t, self.NodeID(), self.SessionGeneration(), true),
		mapConnectivityWithoutEndpointsFixture(t, peer.NodeID(), peer.SessionGeneration(), true),
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

var directSharingFixtureOutput = flag.String("direct-sharing-fixture-output", "", "explicit output directory for synthetic Core sharing frames")

// TestExportDirectSharingFrames is an opt-in fixture producer, not a live qualification gate.
func TestExportDirectSharingFrames(t *testing.T) {
	if *directSharingFixtureOutput == "" {
		t.Skip("fixture generation requires explicit output directory")
	}
	provider, consumer, base := directMapSnapshots(t, policy.ProtocolICMP, nil)
	params := mapSnapshotParams(base)
	params.NetworkRevision++
	withdrawn, err := mapsession.NewSnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	withdrawn, err = withdrawn.WithConnectivity([]mapsession.Connectivity{
		mapConnectivityWithoutEndpointsFixture(t, withdrawn.NodeID(), withdrawn.SessionGeneration(), true),
	})
	if err != nil {
		t.Fatal(err)
	}
	delta, err := mapsession.NewAuthorityDelta(provider, withdrawn)
	if err != nil {
		t.Fatal(err)
	}
	for name, snapshot := range map[string]mapsession.Snapshot{
		"provider-full": provider, "consumer-full": consumer, "provider-removed-full": withdrawn,
	} {
		encoded, err := EncodeFullMapResponse(snapshot, 142)
		if err != nil {
			t.Fatal(err)
		}
		writeDirectSharingFixture(t, name, encoded)
	}
	encoded, err := EncodeAuthorityDeltaMapResponse(delta, 142)
	if err != nil {
		t.Fatal(err)
	}
	writeDirectSharingFixture(t, "provider-removed-delta", encoded)
	encoded, err = encodeAuthorityWithdrawalMapResponse(provider, 142, mapResponseCompressionZstd)
	if err != nil {
		t.Fatal(err)
	}
	writeDirectSharingFixture(t, "provider-terminal-withdrawal", encoded)
}

func writeDirectSharingFixture(t *testing.T, name string, encoded []byte) {
	t.Helper()
	document, err := zstdframe.AppendDecode(nil, encoded[4:], zstdframe.MaxDecodedSize(maxMapResponseBytes))
	if err != nil {
		t.Fatal(err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, document, "", "  "); err != nil {
		t.Fatal(err)
	}
	formatted := append(pretty.Bytes(), '\n')
	if err := os.WriteFile(filepath.Join(*directSharingFixtureOutput, name+".json"), formatted, 0600); err != nil {
		t.Fatal(err)
	}
}
