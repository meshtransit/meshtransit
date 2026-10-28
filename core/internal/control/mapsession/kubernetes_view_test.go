package mapsession

import (
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/node"
)

// gatewayViewFixture grants peer one group until until (zero: a day after
// the fixture's creation), owned by a member.
func gatewayViewFixture(t *testing.T, peer node.ID, group string, until time.Time) KubernetesView {
	t.Helper()
	if until.IsZero() {
		until = time.Date(2026, time.September, 15, 3, 0, 0, 0, time.UTC)
	}
	view, err := NewKubernetesView(map[node.ID]KubernetesAccess{peer: {
		Grants:    []KubernetesGrant{{Group: group, ValidUntil: until}},
		OwnerKind: KubernetesOwnerMember, OwnerRef: "01890f00-0000-7000-8000-000000000011",
	}})
	if err != nil {
		t.Fatal(err)
	}
	return view
}

// withView rebuilds snapshot with view at revision.
func withView(t *testing.T, snapshot Snapshot, view KubernetesView, revision int64) Snapshot {
	t.Helper()
	params := snapshot.params()
	params.Kubernetes, params.NetworkRevision = view, revision
	next, err := NewSnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

// A view never carries a grant without a group, a deadline or an owner kind.
func TestKubernetesViewRefusesIncompleteAccess(t *testing.T) {
	t.Parallel()
	peer := snapshotFixture(t).NodeID()
	until := time.Date(2026, time.September, 15, 3, 0, 0, 0, time.UTC)
	member := func(grants ...KubernetesGrant) KubernetesAccess {
		return KubernetesAccess{Grants: grants, OwnerKind: KubernetesOwnerMember, OwnerRef: "x"}
	}
	for name, access := range map[string]map[node.ID]KubernetesAccess{
		"no grant":      {peer: member()},
		"no deadline":   {peer: member(KubernetesGrant{Group: "view"})},
		"unsorted":      {peer: member(KubernetesGrant{"view", until}, KubernetesGrant{"edit", until})},
		"invalid group": {peer: member(KubernetesGrant{"View", until})},
		"no owner kind": {peer: {Grants: []KubernetesGrant{{"view", until}}}},
		"invalid peer":  {{}: member(KubernetesGrant{"view", until})},
	} {
		if _, err := NewKubernetesView(access); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A gateway's peers' access changing without a revision (a membership
// lapsing) is a new map: the stream sends a snapshot instead of failing on
// a connectivity delta with nothing in it (K1a3 §13.1).
func TestKubernetesAccessAloneChangesTheMap(t *testing.T) {
	t.Parallel()
	authorized, peer := snapshotWithAuthorizedPeerFixture(t)
	revision := authorized.NetworkRevision()
	current := withView(t, authorized, gatewayViewFixture(t, peer.NodeID(), "view", time.Time{}), revision)
	next := withView(t, authorized, gatewayViewFixture(t, peer.NodeID(), "edit", time.Time{}), revision)
	if streamSnapshotChanged(current, current) || !streamSnapshotChanged(current, next) {
		t.Fatal("streamSnapshotChanged ignores the Kubernetes access")
	}
	// Another deadline is another map.
	later := withView(t, authorized, gatewayViewFixture(t, peer.NodeID(), "view", time.Now()), revision)
	if !streamSnapshotChanged(current, later) {
		t.Fatal("a new grant deadline left the map unchanged")
	}
	sink := &recordingStreamSink{}
	if _, err := (&StreamService{}).deliver(t.Context(), sink, current, next); err != nil {
		t.Fatal(err)
	}
	if snapshots, _ := sink.state(); len(snapshots) != 1 || len(sink.authorityWithdrawals()) != 0 {
		t.Fatalf("sent %d snapshots, %d withdrawals", len(snapshots), len(sink.authorityWithdrawals()))
	}
}

// At a new revision a peer whose access alone changed is upserted, so the
// gateway replaces it (§4.5); an otherwise empty change is no delta.
func TestAuthorityDeltaUpsertsAPeerWhoseAccessChanged(t *testing.T) {
	t.Parallel()
	_, base, peer := authorityDeltaSnapshotsFixture(t)
	current := withView(t, base, gatewayViewFixture(t, peer.NodeID(), "view", time.Time{}), base.NetworkRevision())
	next := withView(t, base, gatewayViewFixture(t, peer.NodeID(), "edit", time.Time{}), base.NetworkRevision()+1)
	delta, err := NewAuthorityDelta(current, next)
	if err != nil {
		t.Fatal(err)
	}
	if changed := delta.ChangedPeers(); len(changed) != 1 || changed[0].NodeID() != peer.NodeID() {
		t.Fatalf("changed peers = %v", changed)
	}
	same := withView(t, base, gatewayViewFixture(t, peer.NodeID(), "view", time.Time{}), base.NetworkRevision()+1)
	if _, err := NewAuthorityDelta(current, same); err == nil {
		t.Fatal("a delta without changes was built")
	}
}

// Only a session that negotiated gateway.kube.v1 keeps the access.
func TestKubernetesAccessNeedsTheCapability(t *testing.T) {
	t.Parallel()
	authorized, peer := snapshotWithAuthorizedPeerFixture(t)
	snapshot := withView(t, authorized, gatewayViewFixture(t, peer.NodeID(), "view", time.Time{}),
		authorized.NetworkRevision())
	request, err := NewRequest(snapshot.NodeKey())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.withKubernetesCapability(request).Kubernetes().Computed() {
		t.Fatal("a session without gateway.kube.v1 kept the access")
	}
	if kept := snapshot.withKubernetesCapability(request.WithKubernetes()).Kubernetes(); !kept.Equal(snapshot.Kubernetes()) {
		t.Fatal("a gateway.kube.v1 session lost the access")
	}
}

// A gateway's map rebuilds just after its peers' access next changes, and
// otherwise at its projection or key deadline.
func TestGatewayMapRefreshesWhenAccessChanges(t *testing.T) {
	t.Parallel()
	authorized, peer := snapshotWithAuthorizedPeerFixture(t)
	if !refreshDeadline(authorized).Equal(authorized.ProjectionExpiry()) {
		t.Fatal("a map without access refreshes early")
	}
	at := authorized.CreatedAt().Add(time.Hour)
	gateway := withView(t, authorized, gatewayViewFixture(t, peer.NodeID(), "view", at), authorized.NetworkRevision())
	if got := refreshDeadline(gateway); !got.Equal(at.Add(kubernetesRefreshMargin)) {
		t.Fatalf("refreshDeadline() = %v, want %v", got, at.Add(kubernetesRefreshMargin))
	}
}

// The Service opens a map with its peers' Kubernetes access only for a
// session that asked for it, whatever the store computed (§12.4).
func TestServiceOpensAccessOnlyForGatewayKube(t *testing.T) {
	t.Parallel()
	authorized, peer := snapshotWithAuthorizedPeerFixture(t)
	snapshot := withView(t, authorized, gatewayViewFixture(t, peer.NodeID(), "view", time.Time{}),
		authorized.NetworkRevision())
	for _, capable := range []bool{false, true} {
		service := newServiceFixture(t, &recordingSnapshotStore{snapshot: snapshot}, &recordingEndpointObserver{})
		machine, request := authenticatedRequestFixture(t, snapshot)
		if capable {
			request = request.WithKubernetes()
		}
		opened, err := service.Open(t.Context(), machine, request)
		if err != nil {
			t.Fatal(err)
		}
		if opened.Kubernetes().Computed() != capable {
			t.Fatalf("gateway.kube.v1 %v: access %+v", capable, opened.Kubernetes())
		}
	}
}

// A view refreshes at its earliest grant's deadline: every other end bounds
// the grants it comes with.
func TestKubernetesViewRefreshesAtItsEarliestGrant(t *testing.T) {
	t.Parallel()
	first, second := snapshotFixture(t).NodeID(), must(node.ParseID("01890f00-0000-7000-8000-000000000702"))
	early := time.Date(2026, time.September, 14, 5, 0, 0, 0, time.UTC)
	view, err := NewKubernetesView(map[node.ID]KubernetesAccess{
		first: {Grants: []KubernetesGrant{{"edit", early.Add(time.Hour)}, {"view", early}},
			OwnerKind: KubernetesOwnerWorkspace},
		second: {Grants: []KubernetesGrant{{"view", early.Add(2 * time.Hour)}}, OwnerKind: KubernetesOwnerWorkspace},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !view.RefreshAt().Equal(early) {
		t.Fatalf("RefreshAt() = %v, want %v", view.RefreshAt(), early)
	}
	if empty, _ := NewKubernetesView(nil); !empty.RefreshAt().IsZero() || !empty.Computed() {
		t.Fatalf("an empty view = %+v", empty)
	}
}

// A rebuild describes the same read: how current the map is, and its
// deadlines, still count from it (K1a3c, MapFresh as_of).
func TestRebuildsKeepTheReadTime(t *testing.T) {
	t.Parallel()
	params := snapshotFixture(t).params()
	read := time.Now().Add(-time.Minute)
	params.ReadAtLocal, params.DatabaseReadAt = read, read.UTC()
	snapshot, err := NewSnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := NewSnapshot(snapshot.params())
	if err != nil {
		t.Fatal(err)
	}
	if !rebuilt.ReadAtLocal().Equal(read) || !rebuilt.databaseReadAt.Equal(read.UTC()) {
		t.Fatalf("rebuilt read at %v / %v, want %v", rebuilt.ReadAtLocal(), rebuilt.databaseReadAt, read)
	}
}
