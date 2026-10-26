package mapsession

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

const kubernetesTestZone = "000000000101.000000000201.mesh.internal"

// replicaParams (marker 5 or more: self holds the keys of 1 and 2) is a
// gateway replica of cluster (no cluster: a standard
// Device) with an IPv4 address and, when dual, an IPv6 one.
func replicaParams(t *testing.T, base Snapshot, marker byte, label, cluster string, dual bool) PeerCandidateParams {
	t.Helper()
	params := peerCandidateParamsFixture(t, base, fmt.Sprintf("01890f00-0000-7000-8000-000000000%03d", 800+int(marker)), marker)
	if label != "" {
		params.DNSLabel = mustLabel(t, label)
	}
	if cluster != "" {
		params.KubernetesCluster = must(kubecluster.ParseName(cluster))
	}
	params.Addresses = []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("100.64.1.%d/32", marker))}
	if dual {
		params.Addresses = append(params.Addresses, netip.MustParsePrefix(fmt.Sprintf("fd00::1:%d/128", marker)))
	}
	return params
}

// clusterSnapshot is snapshotFixture named node-1 in kubernetesTestZone
// (unless anonymous) with one rule from self to each peer.
func clusterSnapshot(t *testing.T, anonymous bool, peers ...PeerCandidateParams) Snapshot {
	t.Helper()
	base := snapshotFixture(t)
	params := base.params()
	if !anonymous {
		params.DNSLabel = mustLabel(t, "node-1")
		params.WorkspaceCode, params.NetworkCode = identity.DisplayCode("000000000101"), identity.DisplayCode("000000000201")
	}
	rules := make([]policy.Rule, 0, len(peers))
	params.PeerCandidates = make([]PeerCandidate, 0, len(peers))
	for index, peer := range peers {
		params.PeerCandidates = append(params.PeerCandidates, must(NewPeerCandidate(peer)))
		rules = append(rules, must(policy.NewRule(policy.RuleParams{ID: policyRuleID(t, index+1),
			Scope: base.Scope(), SourceNodeID: base.NodeID(), DestinationNodeID: peer.NodeID,
			Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{must(policy.NewPortRange(443, 443))}})))
	}
	params.PacketPolicy = must(policy.NewSnapshot(policy.SnapshotParams{Scope: base.Scope(), Revision: 5, Rules: rules}))
	snapshot, err := NewSnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func placeholderOf(id node.ID) string {
	return "device-" + strings.ReplaceAll(id.String(), "-", "") + ".invalid"
}

func addressesOf(params ...PeerCandidateParams) []netip.Addr {
	var addresses []netip.Addr
	for _, peer := range params {
		for _, prefix := range peer.Addresses {
			addresses = append(addresses, prefix.Addr())
		}
	}
	return addresses
}

func equalRecords(left, right []DNSRecord) bool {
	return slices.EqualFunc(left, right, func(first, second DNSRecord) bool {
		return first.Name == second.Name && slices.Equal(first.Addresses, second.Addresses)
	})
}

// TestDNSViewNamesKubernetesClustersNotReplicas: a replica of the Network is
// a placeholder with no record of its own, and each cluster is one record
// of its replicas' addresses in Device order (K1a2b §4.2, §8).
func TestDNSViewNamesKubernetesClustersNotReplicas(t *testing.T) {
	t.Parallel()
	base := snapshotFixture(t)
	standard := replicaParams(t, base, 5, "peer-1", "", false)
	first := replicaParams(t, base, 6, "kinda-k1-0", "kinda-k1", true)
	second := replicaParams(t, base, 7, "kinda-k1-1", "kinda-k1", true)
	other := replicaParams(t, base, 8, "other-0", "other", false)
	snapshot := clusterSnapshot(t, false, standard, first, second, other)
	for _, compute := range []func(dnsname.Suffix) (DNSView, error){snapshot.DNSView, snapshot.DNSPeerNames} {
		view, err := compute(dnsname.Default())
		if err != nil {
			t.Fatal(err)
		}
		if view.SelfName() != "node-1."+kubernetesTestZone || view.Unnamed() != 0 || view.Dropped() != 0 {
			t.Fatalf("self %q, unnamed %d, dropped %d", view.SelfName(), view.Unnamed(), view.Dropped())
		}
		for _, replica := range []PeerCandidateParams{first, second, other} {
			if name, _ := view.PeerName(replica.NodeID); name != placeholderOf(replica.NodeID) {
				t.Errorf("replica %s is named %q", replica.NodeID, name)
			}
		}
		if name, _ := view.PeerName(standard.NodeID); name != "peer-1."+kubernetesTestZone {
			t.Errorf("standard peer is named %q", name)
		}
		want := []DNSRecord{
			{Name: "kinda-k1.kube." + kubernetesTestZone, Addresses: addressesOf(first, second)},
			{Name: "node-1." + kubernetesTestZone, Addresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")}},
			{Name: "other.kube." + kubernetesTestZone, Addresses: addressesOf(other)},
			{Name: "peer-1." + kubernetesTestZone, Addresses: addressesOf(standard)},
		}
		if records := view.Records(); !equalRecords(records, want) {
			t.Fatalf("records = %+v, want %+v", records, want)
		}
	}
}

// TestDNSViewNamesReplicasBeforeLabelsAndCodes: a replica without a label,
// or in a map without display codes, is still a placeholder, never its
// hostname, and is never counted unnamed.
func TestDNSViewNamesReplicasBeforeLabelsAndCodes(t *testing.T) {
	t.Parallel()
	base := snapshotFixture(t)
	unlabeled := replicaParams(t, base, 6, "", "kinda-k1", false)
	snapshot := clusterSnapshot(t, false, unlabeled)
	for _, compute := range []func(dnsname.Suffix) (DNSView, error){snapshot.DNSView, snapshot.DNSPeerNames} {
		view, err := compute(dnsname.Default())
		if err != nil {
			t.Fatal(err)
		}
		if name, _ := view.PeerName(unlabeled.NodeID); name != placeholderOf(unlabeled.NodeID) || view.Unnamed() != 0 {
			t.Fatalf("unlabeled replica is named %q, unnamed %d", name, view.Unnamed())
		}
	}
	named, err := snapshot.DNSView(dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	want := []DNSRecord{
		{Name: "kinda-k1.kube." + kubernetesTestZone, Addresses: addressesOf(unlabeled)},
		{Name: "node-1." + kubernetesTestZone, Addresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")}},
	}
	if !equalRecords(named.Records(), want) {
		t.Fatalf("records = %+v", named.Records())
	}
	labeled := replicaParams(t, base, 7, "kinda-k1-1", "kinda-k1", false)
	anonymous, err := clusterSnapshot(t, true, labeled).DNSView(dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	if name, _ := anonymous.PeerName(labeled.NodeID); name != placeholderOf(labeled.NodeID) ||
		len(anonymous.Records()) != 0 || anonymous.Unnamed() != 0 {
		t.Fatalf("replica without codes is named %q, records %+v", name, anonymous.Records())
	}
}

// TestDNSViewBoundsClusterRecordAddresses: a node takes at most 32
// addresses for one name, so a cluster record keeps the first 32 in Device
// order, IPv4 then IPv6 of each replica, and counts the rest dropped.
func TestDNSViewBoundsClusterRecordAddresses(t *testing.T) {
	t.Parallel()
	base := snapshotFixture(t)
	replicas := make([]PeerCandidateParams, 0, 17)
	for index := range 17 {
		replicas = append(replicas, replicaParams(t, base, byte(10+index), fmt.Sprintf("big-%d", index), "big", true))
	}
	view, err := clusterSnapshot(t, false, replicas...).DNSView(dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(view.Records(), func(record DNSRecord) bool {
		return record.Name == "big.kube."+kubernetesTestZone
	})
	if index < 0 {
		t.Fatalf("records = %+v", view.Records())
	}
	record := view.Records()[index]
	if len(record.Addresses) != MaximumClusterRecordAddresses || view.Dropped() != 2 ||
		!slices.Equal(record.Addresses, addressesOf(replicas[:16]...)) {
		t.Fatalf("cluster record has %d addresses, dropped %d", len(record.Addresses), view.Dropped())
	}
}
