package mapsession

import (
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/node"
)

// An operation needs the peer in the map and each of its groups granted
// and unexpired on the database clock (K1b0 §3.3).
func TestKubernetesOperationChecksPeerAndGroups(t *testing.T) {
	t.Parallel()
	read := time.Now()
	authorized, candidate := snapshotWithAuthorizedPeerFixture(t)
	peer, other := candidate.NodeID(), node.ID{0x01, 0x8a}
	view, err := NewKubernetesView(map[node.ID]KubernetesAccess{peer: {
		Grants: []KubernetesGrant{
			{Group: "admins", ValidUntil: read.Add(-time.Second).UTC()},
			{Group: "dev", ValidUntil: read.Add(time.Hour).UTC()},
			{Group: "ops", ValidUntil: read.Add(time.Hour).UTC()},
		},
		OwnerKind: KubernetesOwnerTags, OwnerRef: "tags:a",
	}}, KubernetesScopeTable{})
	if err != nil {
		t.Fatal(err)
	}
	params := authorized.params()
	params.Kubernetes, params.ReadAtLocal, params.DatabaseReadAt = view, read, read.UTC()
	snapshot, err := NewSnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		peer   node.ID
		groups []string
		want   KubernetesOperationCheck
	}{
		{"granted", peer, []string{"dev", "ops"}, KubernetesOperationAllowed},
		{"no groups", peer, nil, KubernetesOperationAllowed},
		{"expired group", peer, []string{"admins"}, KubernetesOperationNotGranted},
		{"unknown group", peer, []string{"dev", "root"}, KubernetesOperationNotGranted},
		{"not a peer", other, []string{"dev"}, KubernetesOperationNoPeer},
	} {
		access, got := snapshot.KubernetesOperation(test.peer, test.groups)
		if got != test.want {
			t.Fatalf("%s: check = %d, want %d", test.name, got, test.want)
		}
		if got == KubernetesOperationAllowed && (access.OwnerKind.String() != "tags" || access.OwnerRef != "tags:a") {
			t.Fatalf("%s: access = %+v", test.name, access)
		}
	}
}

// A peer whose every grant expired holds no access at all.
func TestKubernetesOperationRefusesAPeerWhoseGrantsExpired(t *testing.T) {
	t.Parallel()
	read := time.Now()
	authorized, candidate := snapshotWithAuthorizedPeerFixture(t)
	peer := candidate.NodeID()
	params := authorized.params()
	params.Kubernetes = gatewayViewFixture(t, peer, "dev", read.Add(-time.Minute).UTC())
	params.ReadAtLocal, params.DatabaseReadAt = read, read.UTC()
	snapshot, err := NewSnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	if _, got := snapshot.KubernetesOperation(peer, nil); got != KubernetesOperationNoPeer {
		t.Fatalf("check = %d, want no peer", got)
	}
}
