package daemon

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/kubeprofile"
)

// keyedDataPlane is a data plane that tells which key an address is under.
type keyedDataPlane struct {
	keys map[netip.Addr][32]byte
}

func (keyedDataPlane) Apply(context.Context, networkmap.Snapshot, dataplane.NodePrivateKey) (dataplane.State, error) {
	return "", nil
}

func (keyedDataPlane) Close() error { return nil }

func (plane keyedDataPlane) PeerKeyAt(address netip.Addr) ([32]byte, bool) {
	key, found := plane.keys[address]
	return key, found
}

// A gateway's peer is named only while the data plane holds the map's key
// for its address: a map half applied names no one (K1b design §4).
func TestKubernetesPeerAtNeedsTheDataPlanesKey(t *testing.T) {
	t.Parallel()
	address := netip.MustParseAddr("100.64.0.10")
	snapshot := directorySnapshot()
	snapshot.Peers[0].PublicKey = "nodekey:" + strings.Repeat("ab", 32)
	snapshot.Peers[0].Kubernetes = &networkmap.KubernetesAccess{OwnerRef: "person-1"}
	key, err := dataplane.ParseNodeKey(snapshot.Peers[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{dataPlane: keyedDataPlane{keys: map[netip.Addr][32]byte{address: key}}}
	if _, found := service.KubernetesPeerAt(address); found {
		t.Fatal("named without a map")
	}
	service.peerSession.setDirectory(newPeerDirectory(snapshot))
	peer, found := service.KubernetesPeerAt(netip.AddrFrom16(address.As16()))
	if !found || peer.DeviceID != "dev-direct" || peer.Key != key || peer.Kubernetes.OwnerRef != "person-1" {
		t.Fatalf("peer %+v, %t", peer, found)
	}
	service.dataPlane = keyedDataPlane{keys: map[netip.Addr][32]byte{address: {9}}}
	if _, found := service.KubernetesPeerAt(address); found {
		t.Fatal("named while the data plane holds another key")
	}
	service.dataPlane = keyedDataPlane{}
	if _, found := service.KubernetesPeerAt(address); found {
		t.Fatal("named while the data plane holds no key")
	}
	if _, found := (&Service{}).KubernetesPeerAt(address); found {
		t.Fatal("named without a data plane")
	}
	// A peer with access over a whole prefix is no one's (review b5a L7).
	snapshot.Peers[0].Addresses = append(snapshot.Peers[0].Addresses, netip.MustParsePrefix("100.64.1.0/24"))
	service.dataPlane = keyedDataPlane{keys: map[netip.Addr][32]byte{address: key}}
	directory := newPeerDirectory(snapshot)
	if len(directory.kubernetesRefused) != 1 || directory.kubernetesRefused[0] != snapshot.Peers[0].StableID {
		t.Fatalf("refused %v", directory.kubernetesRefused)
	}
	service.peerSession.setDirectory(directory)
	if _, found := service.KubernetesPeerAt(address); found {
		t.Fatal("named with a prefix address")
	}
}

// A peer comes with the scopes its scoped grants name, the contact and
// whether the map withheld access, all from the one map.
func TestKubernetesPeerAtCarriesItsScopes(t *testing.T) {
	t.Parallel()
	address := netip.MustParseAddr("100.64.0.10")
	snapshot := directorySnapshot()
	snapshot.Peers[0].PublicKey = "nodekey:" + strings.Repeat("ab", 32)
	named, other := [32]byte{1}, [32]byte{2}
	snapshot.Peers[0].Kubernetes = &networkmap.KubernetesAccess{Scoped: []networkmap.KubernetesScopedGrant{
		{Group: "edit", Scope: named, ValidUntil: time.Now().Add(time.Hour)},
	}}
	snapshot.KubernetesScopes = map[[32]byte]networkmap.KubernetesScope{
		named: {ProfileName: "developer"}, other: {ProfileName: "other"},
	}
	snapshot.KubernetesAccessContact = "#platform"
	key, err := dataplane.ParseNodeKey(snapshot.Peers[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{dataPlane: keyedDataPlane{keys: map[netip.Addr][32]byte{address: key}}}
	service.peerSession.setDirectory(newPeerDirectory(snapshot))
	peer, found := service.KubernetesPeerAt(address)
	if !found || len(peer.Scopes) != 1 || peer.Scopes[named].ProfileName != "developer" ||
		peer.AccessContact != "#platform" || peer.Withheld {
		t.Fatalf("peer %+v, %t", peer, found)
	}
	snapshot.Peers[0].Kubernetes = nil
	snapshot.KubernetesWithheld = true
	service.peerSession.setDirectory(newPeerDirectory(snapshot))
	if peer, found = service.KubernetesPeerAt(address); !found || !peer.Withheld || peer.Scopes != nil {
		t.Fatalf("withheld peer %+v, %t", peer, found)
	}
}

// The namespaces the peers' scoped grants name, by group, are where a
// gateway measures its ceilings: sorted, once each, "*" left out.
func TestKubernetesRuleNamespaces(t *testing.T) {
	t.Parallel()
	scope := func(namespaces ...string) kubeprofile.Scope {
		made, err := kubeprofile.NewScope(kubeprofile.Profile{Name: "developer", Namespaced: []kubeprofile.Rule{{
			APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"},
		}}}, namespaces, false)
		if err != nil {
			t.Fatal(err)
		}
		return made
	}
	snapshot := directorySnapshot()
	teams, everywhere, unnamed, expired := [32]byte{1}, [32]byte{2}, [32]byte{3}, [32]byte{4}
	until := time.Now().Add(time.Hour)
	snapshot.Peers[0].Kubernetes = &networkmap.KubernetesAccess{Scoped: []networkmap.KubernetesScopedGrant{
		{Group: "edit", Scope: teams, ValidUntil: until},
		{Group: "edit", Scope: everywhere, ValidUntil: until},
		{Group: "view", Scope: unnamed, ValidUntil: until},
		{Group: "ops", Scope: expired, ValidUntil: time.Now().Add(-time.Minute)},
	}}
	snapshot.KubernetesScopes = map[[32]byte]networkmap.KubernetesScope{
		teams: {Scope: scope("team-b", "team-a")}, everywhere: {Scope: scope("*")},
		expired: {Scope: scope("old")},
	}
	service := &Service{}
	if namespaces := service.KubernetesRuleNamespaces(); namespaces != nil {
		t.Fatalf("without a map: %v", namespaces)
	}
	service.peerSession.setDirectory(newPeerDirectory(snapshot))
	namespaces := service.KubernetesRuleNamespaces()
	if len(namespaces) != 1 || strings.Join(namespaces["edit"], ",") != "team-a,team-b" {
		t.Fatalf("namespaces %v", namespaces)
	}
}
