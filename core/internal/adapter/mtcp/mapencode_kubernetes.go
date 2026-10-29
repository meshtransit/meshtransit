package mtcp

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/dnsname"
)

// CapabilityKubeCA is kube.ca1: a node takes the Kubernetes clusters it may
// reach and their roots in its map (mtcp-v1 §7.11, K1a4d).
const CapabilityKubeCA = "kube.ca1"

// maximumKubernetesRootPool bounds the roots' DER one map message carries
// (K1a4d design §2.4); the rest follow in later messages that carry the
// field.
const maximumKubernetesRootPool = 2 << 20

// kubeClusterState is what a node holds of its clusters, as this session
// sent them (§7.11): the last availability sent, whether the epoch had an
// authoritative list, that list, and the sent set (the roots that list
// names whose DER the node holds, by the node's own drop rule).
type kubeClusterState struct {
	availability mtcpv1.KubernetesClusters_Availability
	available    bool
	// listDigest identifies the list sent (a session keeps 32 bytes, not
	// up to 1,000 clusters, review d2 M3).
	listDigest [32]byte
	sent       map[[32]byte]struct{}
}

// kubeClusterCounts are what one encoding left out or saw: clusters past
// the map's bound, roots past the message's DER budget, and clusters whose
// zone name is not the name their gateways' certificates carry.
type kubeClusterCounts struct {
	dropped, deferred, mismatched int
}

// encodeKubernetesClusters returns the field a message to the node carries,
// nil when a delta carries none, and the state after it. A snapshot (full)
// always carries it and starts the epoch. While the clusters are not
// available, neither the list nor the sent set changes (design §2.4): a
// snapshot or an epoch that has not had an authoritative list says why; a
// delta after one sends nothing for UNREAD and says RESTORE once.
func (state kubeClusterState) encodeKubernetesClusters(snapshot mapsession.Snapshot, suffix dnsname.Suffix,
	full bool,
) (*mtcpv1.KubernetesClusters, kubeClusterState, kubeClusterCounts) {
	if full {
		state.available = false
	}
	trust := snapshot.Kubernetes().Trust()
	switch trust.Availability() {
	case mapsession.KubernetesTrustAvailable:
		return state.encodeAvailable(snapshot, trust, suffix, full)
	case mapsession.KubernetesTrustRestore:
		return state.encodeUnavailable(mtcpv1.KubernetesClusters_RESTORE, full)
	default:
		return state.encodeUnavailable(mtcpv1.KubernetesClusters_UNREAD, full)
	}
}

// encodeUnavailable says why the clusters are not available: always in a
// snapshot, else once; UNREAD never after the epoch had an authoritative
// list (a transient failure leaves the node's list as it is).
func (state kubeClusterState) encodeUnavailable(availability mtcpv1.KubernetesClusters_Availability,
	full bool,
) (*mtcpv1.KubernetesClusters, kubeClusterState, kubeClusterCounts) {
	send := full || state.availability != availability
	if availability == mtcpv1.KubernetesClusters_UNREAD && !full && state.available {
		send = false
	}
	if !send {
		return nil, state, kubeClusterCounts{}
	}
	state.availability = availability
	return &mtcpv1.KubernetesClusters{Availability: availability}, state, kubeClusterCounts{}
}

func (state kubeClusterState) encodeAvailable(snapshot mapsession.Snapshot, trust mapsession.KubernetesTrust,
	suffix dnsname.Suffix, full bool,
) (*mtcpv1.KubernetesClusters, kubeClusterState, kubeClusterCounts) {
	clusters, dropped := snapshot.KubernetesClusters(suffix)
	counts := kubeClusterCounts{dropped: dropped}
	list := make([]*mtcpv1.KubernetesCluster, 0, len(clusters))
	referenced := map[[32]byte]struct{}{}
	for _, cluster := range clusters {
		encoded := &mtcpv1.KubernetesCluster{
			ClusterId: cluster.ID.String(), Name: cluster.Name.String(), DnsName: cluster.DNSName,
			TlsServerName: cluster.TLSName, RootFingerprints: make([][]byte, 0, len(cluster.Roots)),
		}
		for _, root := range cluster.Roots {
			encoded.RootFingerprints = append(encoded.RootFingerprints, slices.Clone(root[:]))
			referenced[root] = struct{}{}
		}
		if cluster.DNSName != "" && cluster.TLSName != "" && cluster.DNSName != cluster.TLSName {
			counts.mismatched++
		}
		list = append(list, encoded)
	}
	// The node drops DER no listed cluster names; so does the sent set.
	sent := make(map[[32]byte]struct{}, len(referenced))
	if !full {
		for fingerprint := range state.sent {
			if _, named := referenced[fingerprint]; named {
				sent[fingerprint] = struct{}{}
			}
		}
	}
	var pool [][]byte
	budget := maximumKubernetesRootPool
	for _, cluster := range clusters {
		for _, root := range cluster.Roots {
			if _, held := sent[root]; held {
				continue
			}
			der, ok := trust.Root(root)
			if !ok {
				continue // the inventory has none: the cluster shows incomplete
			}
			// The trust checked each DER against its fingerprint.
			if len(der) > budget {
				counts.deferred++
				continue
			}
			budget -= len(der)
			pool = append(pool, der)
			sent[root] = struct{}{}
		}
	}
	digest, hashed := kubeClusterListDigest(list)
	unchanged := !full && hashed && state.availability == mtcpv1.KubernetesClusters_AVAILABLE &&
		digest == state.listDigest
	state.availability, state.available, state.listDigest, state.sent =
		mtcpv1.KubernetesClusters_AVAILABLE, true, digest, sent
	if unchanged && len(pool) == 0 {
		return nil, state, counts
	}
	return &mtcpv1.KubernetesClusters{
		Clusters: list, Roots: pool, Availability: mtcpv1.KubernetesClusters_AVAILABLE,
	}, state, counts
}

// kubeClusterListDigest hashes a list's deterministic encoding; false when
// it cannot (never for these fields), and the list is then sent.
func kubeClusterListDigest(list []*mtcpv1.KubernetesCluster) ([32]byte, bool) {
	hash := sha256.New()
	options := proto.MarshalOptions{Deterministic: true}
	for _, cluster := range list {
		encoded, err := options.Marshal(cluster)
		if err != nil {
			return [32]byte{}, false
		}
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(encoded)))
		hash.Write(size[:])
		hash.Write(encoded)
	}
	return [32]byte(hash.Sum(nil)), true
}
