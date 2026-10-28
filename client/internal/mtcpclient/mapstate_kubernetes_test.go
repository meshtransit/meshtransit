package mtcpclient

import (
	"fmt"
	"slices"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
)

// Only a Kubernetes gateway's map stream declares gateway.kube.v1: no other
// node takes its peers' Kubernetes access (mtcp-v1 §7.8).
func TestOnlyAGatewayStreamDeclaresGatewayKube(t *testing.T) {
	t.Parallel()
	if slices.Contains(streamCapabilities(controlplane.NetmapOptions{}, false), "gateway.kube.v1") {
		t.Fatal("meshd declared gateway.kube.v1")
	}
	if !slices.Contains(streamCapabilities(controlplane.NetmapOptions{}, true), "gateway.kube.v1") {
		t.Fatal("a gateway did not declare gateway.kube.v1")
	}
	all := controlplane.NetmapOptions{
		EnableDeviceAliases: true, EnableSubnetRoutes: true, EnableSubnetRouter: true,
		EnableExits: true, EnableDNSForward: true, EnableExitNode: true,
	}
	if slices.Contains(streamCapabilities(all, false), "gateway.kube.v1") ||
		!slices.Contains(streamCapabilities(all, true), "gateway.kube.v1") {
		t.Fatal("gateway.kube.v1 depends on other options")
	}
}

// A peer's Kubernetes access and owner reach the product model; self never
// carries any, whatever Core sends.
func TestConvertDeviceCarriesKubernetesAccess(t *testing.T) {
	t.Parallel()
	until := time.Now().Add(time.Hour).Truncate(time.Millisecond).UTC()
	changed := until.Add(-48 * time.Hour)
	peer := device("01890f00-0000-7000-8000-000000000702", 2, "100.64.0.2")
	peer.Owner = &mtcpv1.Owner{Ref: "tags:01890f00-0000-7000-8000-000000000c01"}
	peer.Kubernetes = &mtcpv1.KubernetesAccess{OwnerChangedMs: changed.UnixMilli(), Grants: []*mtcpv1.KubernetesGrant{
		{Group: "edit", ValidUntilMs: until.UnixMilli()}, {Group: "view", ValidUntilMs: until.UnixMilli()},
	}}
	node, err := convertDevice(peer, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	access := node.Kubernetes
	if access == nil || access.OwnerRef != "tags:01890f00-0000-7000-8000-000000000c01" ||
		!access.OwnerChangedAt.Equal(changed) || len(access.Grants) != 2 || access.Grants[1].Group != "view" ||
		!access.Grants[1].ValidUntil.Equal(until) {
		t.Fatalf("access = %+v", access)
	}
	if plain, err := convertDevice(device("01890f00-0000-7000-8000-000000000703", 3, "100.64.0.3"), false,
		time.Now()); err != nil || plain.Kubernetes != nil {
		t.Fatalf("a peer without access = %+v, %v", plain.Kubernetes, err)
	}
	if self, err := convertDevice(peer, true, time.Now()); err != nil || self.Kubernetes != nil {
		t.Fatalf("self with access = %+v, %v", self.Kubernetes, err)
	}
}

// withAccess grants peer group view for an hour, owned by owner.
func withAccess(peer *mtcpv1.Device, owner string) *mtcpv1.Device {
	peer.Owner = &mtcpv1.Owner{Ref: owner}
	peer.Kubernetes = &mtcpv1.KubernetesAccess{Grants: []*mtcpv1.KubernetesGrant{
		{Group: "view", ValidUntilMs: time.Now().Add(time.Hour).UnixMilli()},
	}}
	return peer
}

// A gateway's map keeps a peer's access through patches, drops it with an
// upsert that carries none, and loses only that peer's access when it is
// malformed; any other node ignores access (mtcp-v1 §7.8).
func TestGatewayMapStateKeepsPeersAccess(t *testing.T) {
	t.Parallel()
	const member = "01890f00-0000-7000-8000-000000000011"
	gateway := newMapState(false)
	gateway.takesKubernetes = true
	message := snapshotMessage(7)
	message.Peers[0] = withAccess(message.Peers[0], member)
	if err := gateway.applySnapshot(message); err != nil {
		t.Fatal(err)
	}
	access := func(state *mapState, peer string) *networkmap.KubernetesAccess {
		t.Helper()
		for _, node := range build(t, state).Peers {
			if node.StableID == peer {
				return node.Kubernetes
			}
		}
		t.Fatalf("no peer %s", peer)
		return nil
	}
	if got := access(gateway, "peer-a"); got == nil || got.OwnerRef != member {
		t.Fatalf("snapshot access = %+v", got)
	}
	offline := false
	if err := gateway.applyDelta(&mtcpv1.MapDelta{
		View:        &mtcpv1.View{Epoch: 7, Seq: 2},
		PeerPatches: []*mtcpv1.PeerPatch{{DeviceId: "peer-a", Online: &offline}},
	}); err != nil {
		t.Fatal(err)
	}
	if access(gateway, "peer-a") == nil {
		t.Fatal("a patch dropped the access")
	}
	// Seven tags: a long owner reference is still one.
	tags := "tags:"
	for index := range 7 {
		if index > 0 {
			tags += ","
		}
		tags += fmt.Sprintf("01890f00-0000-7000-8000-%012d", 100+index)
	}
	if err := gateway.applyDelta(&mtcpv1.MapDelta{
		View:        &mtcpv1.View{Epoch: 7, Seq: 3},
		PeersUpsert: []*mtcpv1.Device{withAccess(device("peer-b", 3, "100.64.0.3"), tags)},
	}); err != nil {
		t.Fatal(err)
	}
	if got := access(gateway, "peer-b"); got == nil || got.OwnerRef != tags {
		t.Fatalf("seven tags = %+v", got)
	}
	// A malformed owner costs that peer its access, not the map.
	if err := gateway.applyDelta(&mtcpv1.MapDelta{
		View:        &mtcpv1.View{Epoch: 7, Seq: 4},
		PeersUpsert: []*mtcpv1.Device{withAccess(device("peer-b", 3, "100.64.0.3"), "tags:not-a-tag")},
	}); err != nil {
		t.Fatal(err)
	}
	if access(gateway, "peer-b") != nil || access(gateway, "peer-a") == nil {
		t.Fatal("a malformed access was kept, or cost another peer its own")
	}
	// An upsert without access replaces the peer, access and all.
	if err := gateway.applyDelta(&mtcpv1.MapDelta{
		View:        &mtcpv1.View{Epoch: 7, Seq: 5},
		PeersUpsert: []*mtcpv1.Device{device("peer-a", 2, "100.64.0.2")},
	}); err != nil {
		t.Fatal(err)
	}
	if access(gateway, "peer-a") != nil {
		t.Fatal("an upsert without access kept it")
	}
	// meshd ignores access it never asked for.
	plain := newMapState(false)
	message = snapshotMessage(7)
	message.Peers[0] = withAccess(message.Peers[0], member)
	if err := plain.applySnapshot(message); err != nil {
		t.Fatal(err)
	}
	if access(plain, "peer-a") != nil {
		t.Fatal("meshd kept a peer's access")
	}
}
