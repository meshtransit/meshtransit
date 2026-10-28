package daemon

import (
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
)

// A gateway's peer lookup by address carries the peer's Kubernetes access,
// as a copy the caller cannot change the map through.
func TestPeerAtCarriesKubernetesAccess(t *testing.T) {
	t.Parallel()
	until := time.Now().Add(time.Hour)
	address := netip.MustParsePrefix("100.64.0.2/32")
	service := &Service{}
	service.peerSession.setDirectory(newPeerDirectory(networkmap.Snapshot{Peers: []networkmap.Node{{
		ID: 2, StableID: "dev-2", Name: "laptop.mesh.", Addresses: []netip.Prefix{address},
		Kubernetes: &networkmap.KubernetesAccess{Grants: []networkmap.KubernetesGrant{{Group: "view", ValidUntil: until}}},
	}}}))
	first, found := service.PeerAt(address.Addr())
	if !found || first.Kubernetes == nil || first.Kubernetes.Grants[0].Group != "view" {
		t.Fatalf("PeerAt() = %+v, %v", first, found)
	}
	first.Kubernetes.Grants[0].Group = "admin"
	if again, _ := service.PeerAt(address.Addr()); again.Kubernetes.Grants[0].Group != "view" {
		t.Fatal("PeerAt() shares the map's access")
	}
}
