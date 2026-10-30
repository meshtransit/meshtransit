package mtcp

import (
	"bytes"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/kubeprofile"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// scopedViewFixture: granted holds view whole and edit through the
// developer profile in team-a, reporting until an hour from now.
func scopedViewFixture(t *testing.T, granted mapsession.PeerCandidate) (mapsession.KubernetesView, [32]byte) {
	t.Helper()
	profile := kubeprofile.Profile{Name: "developer", Namespaced: []kubeprofile.Rule{
		{APIGroups: []string{"", "apps"}, Resources: []string{"pods", "deployments"}, Verbs: []string{"get", "list"}}},
		Cluster: []kubeprofile.Rule{{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}}}}
	profileHash, err := kubeprofile.ContentHash(profile)
	if err != nil {
		t.Fatal(err)
	}
	scopeHash, err := kubeprofile.ScopeHash(profileHash, []string{"team-a"}, true)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(24 * time.Hour).Truncate(time.Millisecond)
	report := time.Now().Add(time.Hour).Truncate(time.Millisecond)
	table := mapsession.KubernetesScopeTable{
		Profiles: []mapsession.KubernetesProfile{{Hash: profileHash, ID: "01890f00-0000-7000-8000-00000000cc01",
			Profile: kubeprofile.Normalize(profile)}},
		Scopes: []mapsession.KubernetesScope{{Hash: scopeHash, Profile: profileHash, Namespaces: []string{"team-a"},
			ClusterPart: true}},
	}
	view, err := mapsession.NewKubernetesView(map[node.ID]mapsession.KubernetesAccess{granted.NodeID(): {
		Grants: []mapsession.KubernetesGrant{{Group: "view", ValidUntil: until}},
		ScopedGrants: []mapsession.KubernetesScopedGrant{{Group: "edit", Scope: scopeHash, Report: true,
			ReportUntil: report, ValidUntil: until}},
		OwnerKind: mapsession.KubernetesOwnerWorkspace,
	}}, table)
	if err != nil {
		t.Fatal(err)
	}
	return view, scopeHash
}

// A gateway's snapshot carries its peers' scoped grants and its cluster's
// scope table, which a gateway checks as valid: each profile under its own
// hash, each scope under its own (mtcp-v1 §7.12).
func TestEncodeSnapshotCarriesTheScopeTable(t *testing.T) {
	t.Parallel()
	scope := snapshotFixture(t, 7).Scope()
	granted := peerFixture(t, scope, "01890f00-0000-7000-8000-000000000702", 702, "100.64.0.2", 2)
	view, scopeHash := scopedViewFixture(t, granted)
	message, err := encodeSnapshot(snapshotFixture(t, 7, granted).WithKubernetes(view),
		&mtcpv1.View{Epoch: 9, Seq: 1}, false, nil, dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	scoped := message.GetPeers()[0].GetKubernetes().GetScopedGrants()
	if len(scoped) != 1 || scoped[0].GetGroup() != "edit" || !bytes.Equal(scoped[0].GetScope(), scopeHash[:]) ||
		scoped[0].GetMode() != mtcpv1.KubernetesScopedGrant_REPORT || scoped[0].GetReportUntilMs() == 0 ||
		scoped[0].GetReportUntilMs() > scoped[0].GetValidUntilMs() {
		t.Fatalf("scoped grants = %v", scoped)
	}
	table := message.GetKubernetesScopes()
	if err := sharedmtcp.ValidateKubernetesScopeTable(table); err != nil || len(table.GetProfiles()) != 1 ||
		len(table.GetScopes()) != 1 {
		t.Fatalf("table = %v, %v", table, err)
	}
	encoded := table.GetProfiles()[0]
	rules := func(entries []*mtcpv1.KubernetesProfileRule) []kubeprofile.Rule {
		out := make([]kubeprofile.Rule, len(entries))
		for index, rule := range entries {
			out[index] = kubeprofile.Rule{APIGroups: rule.GetApiGroups(), Resources: rule.GetResources(),
				Verbs: rule.GetVerbs(), ResourceNames: rule.GetResourceNames(), NonResourceURLs: rule.GetNonResourceUrls()}
		}
		return out
	}
	hash, err := kubeprofile.ContentHash(kubeprofile.Profile{Name: encoded.GetName(),
		Namespaced: rules(encoded.GetNamespaced()), Cluster: rules(encoded.GetCluster())})
	if err != nil || !bytes.Equal(hash[:], encoded.GetHash()) {
		t.Fatalf("the gateway would not recognize the profile: %x, %v", hash, err)
	}
	wire := table.GetScopes()[0]
	again, err := kubeprofile.ScopeHash([32]byte(wire.GetProfile()), wire.GetNamespaces(), wire.GetClusterPart())
	if err != nil || !bytes.Equal(again[:], wire.GetHash()) {
		t.Fatalf("the gateway would not recognize the scope: %v", err)
	}
	if kubernetesScopeTableOversize(table) {
		t.Fatal("a small table counts as oversize")
	}
}

// An audit intent names a profile only from a gateway.kube.v2 session, in
// form (invalid otherwise); and what let it through for its first group
// must be in the map: a whole grant without a profile, the scope named with
// one, a reporting grant with report_allowed (§7.12, review d3 M2).
func TestKubeAuditIntentProfile(t *testing.T) {
	t.Parallel()
	scope := snapshotFixture(t, 7).Scope()
	granted := peerFixture(t, scope, auditPeer, 702, "100.64.0.2", 2)
	view, scopeHash := scopedViewFixture(t, granted)
	snapshot := snapshotFixture(t, 7, granted).WithKubernetes(view)
	with := func(groups []string, profile []byte, reported bool) *mtcpv1.KubeAuditIntent {
		intent := auditIntent(1, auditPeer, groups...)
		intent.Profile, intent.ReportAllowed = profile, reported
		return intent
	}
	other := bytes.Repeat([]byte{7}, 32)
	for name, test := range map[string]struct {
		intent       *mtcpv1.KubeAuditIntent
		profiles     bool
		valid, holds bool
	}{
		"whole group, no profile":   {with([]string{"view"}, nil, false), true, true, true},
		"scoped group, no profile":  {with([]string{"edit"}, nil, false), true, true, false},
		"report without profile":    {with([]string{"edit"}, nil, true), true, false, false},
		"profile from a v1 session": {with([]string{"edit"}, scopeHash[:], false), false, false, false},
		"short profile":             {with([]string{"edit"}, scopeHash[:8], false), true, false, false},
		"granted scope, reported":   {with([]string{"edit"}, scopeHash[:], true), true, true, true},
		"granted scope, enforced":   {with([]string{"edit"}, scopeHash[:], false), true, true, true},
		"scope of another group":    {with([]string{"view"}, scopeHash[:], false), true, true, false},
		"scope not granted":         {with([]string{"edit"}, other, false), true, true, false},
	} {
		valid := kubeAuditProfileValid(test.intent, test.profiles)
		holds := valid && kubeAuditProfileHeld(test.intent, snapshot, granted.NodeID())
		if valid != test.valid || holds != test.holds {
			t.Errorf("%s: valid = %t, holds = %t", name, valid, holds)
		}
	}
	// report_allowed needs a reporting grant: an enforcing one is not it.
	enforcing := snapshotFixture(t, 7, granted).WithKubernetes(enforcingViewFixture(t, granted, scopeHash, view))
	if kubeAuditProfileHeld(with([]string{"edit"}, scopeHash[:], true), enforcing, granted.NodeID()) {
		t.Fatal("report_allowed held by an enforcing grant")
	}
	if !kubeAuditProfileHeld(with([]string{"edit"}, scopeHash[:], false), enforcing, granted.NodeID()) {
		t.Fatal("an enforcing grant not held")
	}
}

// enforcingViewFixture is view with granted's scoped grant enforcing.
func enforcingViewFixture(t *testing.T, granted mapsession.PeerCandidate, scope [32]byte,
	view mapsession.KubernetesView) mapsession.KubernetesView {
	t.Helper()
	access, _ := view.For(granted.NodeID())
	access.ScopedGrants = []mapsession.KubernetesScopedGrant{{Group: "edit", Scope: scope,
		ValidUntil: access.ScopedGrants[0].ValidUntil}}
	return must(mapsession.NewKubernetesView(map[node.ID]mapsession.KubernetesAccess{granted.NodeID(): access},
		view.Scopes()))
}

// A delta carries the scope table only when it changed, and a present,
// empty table when it is gone (§7.12).
func TestSinkSendsTheScopeTableWhenItChanges(t *testing.T) {
	session, node, control := testSession(t)
	sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}}, time.Now)
	scope := snapshotFixture(t, 7).Scope()
	granted := peerFixture(t, scope, "01890f00-0000-7000-8000-000000000702", 702, "100.64.0.2", 2)
	connected := func(revision int64, view mapsession.KubernetesView) mapsession.Snapshot {
		snapshot := snapshotFixture(t, revision, granted)
		connectivity := []mapsession.Connectivity{must(mapsession.NewConnectivity(mapsession.ConnectivityParams{
			Key: must(mapsession.NewConnectivityKey(snapshot.NodeID(), snapshot.SessionGeneration())), Online: true,
		})), must(mapsession.NewConnectivity(mapsession.ConnectivityParams{
			Key: must(mapsession.NewConnectivityKey(granted.NodeID(), granted.SessionGeneration())), Online: true,
		}))}
		return must(snapshot.WithConnectivity(connectivity)).WithKubernetes(view)
	}
	whole := gatewayView(t, granted, time.Time{})
	scoped, _ := scopedViewFixture(t, granted)
	initial := connected(7, whole)
	if err := sink.SendSnapshot(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	node.messages()
	next := connected(8, scoped)
	if err := sink.SendAuthorityDelta(t.Context(), must(mapsession.NewAuthorityDelta(initial, next))); err != nil {
		t.Fatal(err)
	}
	_, message, _ := node.read()
	if delta := message.(*mtcpv1.MapDelta); len(delta.GetKubernetesScopes().GetScopes()) != 1 {
		t.Fatalf("the new table = %v", delta.GetKubernetesScopes())
	}
	gone := connected(9, whole)
	if err := sink.SendAuthorityDelta(t.Context(), must(mapsession.NewAuthorityDelta(next, gone))); err != nil {
		t.Fatal(err)
	}
	_, message, _ = node.read()
	if delta := message.(*mtcpv1.MapDelta); delta.GetKubernetesScopes() == nil ||
		len(delta.GetKubernetesScopes().GetScopes()) != 0 {
		t.Fatalf("the cleared table = %v", delta.GetKubernetesScopes())
	}
}
