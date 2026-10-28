package mapsession

import (
	"bytes"
	"testing"
	"time"
)

func testKubernetesCA(root, signing byte) KubernetesCA {
	ca := KubernetesCA{}
	if root != 0 {
		ca.Root = bytes.Repeat([]byte{root}, 32)
	}
	if signing != 0 {
		ca.Signing = bytes.Repeat([]byte{signing}, 32)
	}
	return ca
}

// A view names its cluster's CAs only when they are valid: 32-byte
// fingerprints, and no intermediate without a root (mtcp-v1 §7.10).
func TestKubernetesViewCA(t *testing.T) {
	t.Parallel()
	view := KubernetesView{}
	if _, known := view.CA(); known {
		t.Fatal("a zero view names CAs")
	}
	for name, ca := range map[string]KubernetesCA{
		"both":            testKubernetesCA(1, 2),
		"root only":       testKubernetesCA(1, 0),
		"none yet":        testKubernetesCA(0, 0),
		"short root":      {Root: []byte{1}},
		"signing no root": testKubernetesCA(0, 2),
	} {
		got, known := view.WithCA(ca).CA()
		if known != ca.Valid() || known && !got.Equal(ca) {
			t.Errorf("%s: CA() = %+v, %v", name, got, known)
		}
	}
	if view.WithCA(testKubernetesCA(1, 2)).Equal(view.WithCA(testKubernetesCA(1, 3))) ||
		!view.WithCA(testKubernetesCA(1, 2)).Equal(view.WithCA(testKubernetesCA(1, 2))) ||
		view.Equal(view.WithCA(testKubernetesCA(0, 0))) {
		t.Fatal("Equal ignores the CAs")
	}
}

// At a new revision a CA change alone is a delta of the gateway's own
// entry (§7.10).
func TestAuthorityDeltaCarriesSelfWhenTheCAChanges(t *testing.T) {
	t.Parallel()
	_, base, peer := authorityDeltaSnapshotsFixture(t)
	access := gatewayViewFixture(t, peer.NodeID(), "view", time.Time{})
	current := withView(t, base, access.WithCA(testKubernetesCA(1, 2)), base.NetworkRevision())
	next := withView(t, base, access.WithCA(testKubernetesCA(1, 3)), base.NetworkRevision()+1)
	delta, err := NewAuthorityDelta(current, next)
	if err != nil {
		t.Fatal(err)
	}
	if !delta.SelfChanged() || len(delta.ChangedPeers()) != 0 || !delta.IsValid() {
		t.Fatalf("delta self %v, peers %d", delta.SelfChanged(), len(delta.ChangedPeers()))
	}
}

// Only a gateway.cert1 session keeps the CAs, with or without
// gateway.kube.v1; the access needs gateway.kube.v1.
func TestKubernetesCANeedsTheCapability(t *testing.T) {
	t.Parallel()
	authorized, peer := snapshotWithAuthorizedPeerFixture(t)
	view := gatewayViewFixture(t, peer.NodeID(), "view", time.Time{}).WithCA(testKubernetesCA(1, 2))
	snapshot := withView(t, authorized, view, authorized.NetworkRevision())
	request, err := NewRequest(snapshot.NodeKey())
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		request         Request
		access, caKnown bool
	}{
		"neither":   {request: request},
		"kube only": {request: request.WithKubernetes(), access: true},
		"cert only": {request: request.WithKubernetesCA(), caKnown: true},
		"both":      {request: request.WithKubernetes().WithKubernetesCA(), access: true, caKnown: true},
	} {
		kept := snapshot.withKubernetesCapability(test.request).Kubernetes()
		_, known := kept.CA()
		if kept.Computed() != test.access || known != test.caKnown {
			t.Errorf("%s: access %v, CA %v", name, kept.Computed(), known)
		}
	}
}
