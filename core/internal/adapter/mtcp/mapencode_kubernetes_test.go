package mtcp

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

const kubernetesTestZone = "000000000101.000000000201.mesh.internal"

// replicaFixture is replica ordinal of cluster kinda-k1 at 100.64.0.<marker>.
func replicaFixture(t *testing.T, scope network.Scope, marker byte, ordinal int) mapsession.PeerCandidate {
	t.Helper()
	createdAt := time.Date(2026, time.September, 14, 3, 0, 0, 0, time.UTC)
	return must(mapsession.NewPeerCandidate(mapsession.PeerCandidateParams{
		NumericNodeID: 700 + int64(marker), NumericOwnerID: 11, Scope: scope,
		NodeID:            must(node.ParseID(fmt.Sprintf("01890f00-0000-7000-8000-000000000%03d", 700+int(marker)))),
		OwnerID:           must(identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")),
		Hostname:          must(node.ParseHostname(fmt.Sprintf("kinda-k1-%d", ordinal))),
		DNSLabel:          must(node.ParseDNSLabel(fmt.Sprintf("kinda-k1-%d", ordinal))),
		KubernetesCluster: must(kubecluster.ParseName("kinda-k1")),
		MachineKey:        must(node.NewMachineKey([32]byte{marker, 0xaa})),
		NodeKey:           must(node.NewKey([32]byte{marker, 0xbb})),
		SessionGeneration: 1, Addresses: []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("100.64.0.%d/32", marker))},
		CreatedAt: createdAt, KeyExpiry: createdAt.Add(24 * time.Hour),
	}))
}

// dnsAddresses lists each record name's addresses.
func dnsAddresses(config *mtcpv1.DnsConfig) map[string][]string {
	records := map[string][]string{}
	for _, record := range config.GetRecords() {
		address, _ := netip.AddrFromSlice(record.GetValue())
		records[record.GetName()] = append(records[record.GetName()], address.String())
	}
	return records
}

// TestEncodeSnapshotNamesKubernetesClusterNotReplicas: a gateway replica of
// the Network is a placeholder with no display name and no record, and its
// cluster resolves to its addresses (mtcp-v1 §7.3, K1a2b).
func TestEncodeSnapshotNamesKubernetesClusterNotReplicas(t *testing.T) {
	t.Parallel()
	scope := snapshotFixture(t, 7).Scope()
	replica := replicaFixture(t, scope, 3, 0)
	standard := peerFixture(t, scope, "01890f00-0000-7000-8000-000000000702", 702, "100.64.0.2", 2)
	message, err := encodeSnapshot(snapshotFixture(t, 7, standard, replica), &mtcpv1.View{Epoch: 9, Seq: 1},
		false, nil, dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	const zone = kubernetesTestZone
	peers := message.GetPeers()
	if len(peers) != 2 || peers[0].GetDisplayName() != "peer-2.example" ||
		peers[1].GetName() != "device-01890f00000070008000000000000703.invalid." || peers[1].GetDisplayName() != "" {
		t.Fatalf("peers = %v", peers)
	}
	records := dnsAddresses(message.GetDns())
	if got := records["kinda-k1.kube."+zone]; len(got) != 1 || got[0] != "100.64.0.3" {
		t.Fatalf("cluster record = %v in %v", got, records)
	}
	if _, found := records["kinda-k1-0."+zone]; found {
		t.Fatalf("the replica has its own record: %v", records)
	}
}

// TestSinkSendsAJoiningReplicaUnderItsCluster: a replica that joins reaches
// a source as one placeholder peer, and the cluster's record, with both
// replicas, in the same delta (K1a2b §8).
func TestSinkSendsAJoiningReplicaUnderItsCluster(t *testing.T) {
	session, node, control := testSession(t)
	sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}}, time.Now)
	scope := snapshotFixture(t, 7).Scope()
	first, second := replicaFixture(t, scope, 3, 0), replicaFixture(t, scope, 4, 1)
	connected := func(revision int64, peers ...mapsession.PeerCandidate) mapsession.Snapshot {
		snapshot := snapshotFixture(t, revision, peers...)
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
	initial := connected(7, first)
	if err := sink.SendSnapshot(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	node.messages()
	if err := sink.SendAuthorityDelta(t.Context(), must(mapsession.NewAuthorityDelta(initial,
		connected(8, first, second)))); err != nil {
		t.Fatal(err)
	}
	_, message, _ := node.read()
	delta, ok := message.(*mtcpv1.MapDelta)
	if !ok {
		t.Fatalf("sent %T", message)
	}
	upserts := delta.GetPeersUpsert()
	if len(upserts) != 1 || upserts[0].GetDeviceId() != second.NodeID().String() ||
		upserts[0].GetName() != "device-01890f00000070008000000000000704.invalid." || upserts[0].GetDisplayName() != "" {
		t.Fatalf("upserts = %v", upserts)
	}
	got := dnsAddresses(delta.GetDns())["kinda-k1.kube."+kubernetesTestZone]
	if !slices.Equal(got, []string{"100.64.0.3", "100.64.0.4"}) {
		t.Fatalf("cluster record = %v in %v", got, delta.GetDns())
	}
}
