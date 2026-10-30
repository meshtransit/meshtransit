package mtcpclient

import (
	"bytes"
	"encoding/hex"
	"slices"
	"sort"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/kubeprofile"
)

const scopeMember = "01890f00-0000-7000-8000-000000000011"

// scopeProfile is a small profile: read pods in the rule's namespaces.
func scopeProfile(name string) kubeprofile.Profile {
	return kubeprofile.Profile{Name: name, Namespaced: []kubeprofile.Rule{{APIGroups: []string{""},
		Resources: []string{"pods"}, Verbs: []string{"get", "list"}}}}
}

func profileEntry(t testing.TB, profile kubeprofile.Profile) *mtcpv1.KubernetesProfile {
	t.Helper()
	hash, err := kubeprofile.ContentHash(profile)
	if err != nil {
		t.Fatal(err)
	}
	normalized := kubeprofile.Normalize(profile)
	rules := func(rules []kubeprofile.Rule) []*mtcpv1.KubernetesProfileRule {
		out := make([]*mtcpv1.KubernetesProfileRule, len(rules))
		for index, rule := range rules {
			out[index] = &mtcpv1.KubernetesProfileRule{ApiGroups: rule.APIGroups, Resources: rule.Resources,
				Verbs: rule.Verbs, ResourceNames: rule.ResourceNames, NonResourceUrls: rule.NonResourceURLs}
		}
		return out
	}
	return &mtcpv1.KubernetesProfile{Hash: hash[:], ProfileId: "01890f00-0000-7000-8000-0000000000f1",
		Name: profile.Name, Namespaced: rules(normalized.Namespaced), Cluster: rules(normalized.Cluster)}
}

func scopeEntry(t testing.TB, profile *mtcpv1.KubernetesProfile, namespaces []string, clusterPart bool) *mtcpv1.KubernetesScope {
	t.Helper()
	var profileHash [32]byte
	copy(profileHash[:], profile.GetHash())
	hash, err := kubeprofile.ScopeHash(profileHash, namespaces, clusterPart)
	if err != nil {
		t.Fatal(err)
	}
	return &mtcpv1.KubernetesScope{Hash: hash[:], Profile: profile.GetHash(), Namespaces: namespaces,
		ClusterPart: clusterPart}
}

// table sorts its entries by hash, as Core sends them.
func table(profiles []*mtcpv1.KubernetesProfile, scopes []*mtcpv1.KubernetesScope) *mtcpv1.KubernetesScopeTable {
	sort.Slice(profiles, func(i, j int) bool { return bytes.Compare(profiles[i].GetHash(), profiles[j].GetHash()) < 0 })
	sort.Slice(scopes, func(i, j int) bool { return bytes.Compare(scopes[i].GetHash(), scopes[j].GetHash()) < 0 })
	return &mtcpv1.KubernetesScopeTable{Profiles: profiles, Scopes: scopes}
}

func scopedGrant(group string, scope *mtcpv1.KubernetesScope) *mtcpv1.KubernetesScopedGrant {
	return &mtcpv1.KubernetesScopedGrant{Group: group, Scope: scope.GetHash(),
		ValidUntilMs: time.Now().Add(time.Hour).UnixMilli()}
}

func gatewayState(profiles bool) *mapState {
	state := newMapState(false)
	state.takesKubernetes, state.takesProfiles = true, profiles
	return state
}

func peerAccess(t *testing.T, snapshot networkmap.Snapshot, id string) *networkmap.KubernetesAccess {
	t.Helper()
	for _, node := range snapshot.Peers {
		if node.StableID == id {
			return node.Kubernetes
		}
	}
	t.Fatalf("no peer %s", id)
	return nil
}

// fixture is a map whose peer-a holds view narrowed to team-a and peer-b
// holds edit whole and view narrowed.
func fixture(t testing.TB) (*mtcpv1.MapSnapshot, *mtcpv1.KubernetesScope) {
	profile := profileEntry(t, scopeProfile("reader"))
	scope := scopeEntry(t, profile, []string{"team-a"}, false)
	message := snapshotMessage(7)
	message.KubernetesScopes = table([]*mtcpv1.KubernetesProfile{profile}, []*mtcpv1.KubernetesScope{scope})
	message.Peers[0].Owner = &mtcpv1.Owner{Ref: scopeMember}
	message.Peers[0].Kubernetes = &mtcpv1.KubernetesAccess{ScopedGrants: []*mtcpv1.KubernetesScopedGrant{
		scopedGrant("view", scope)}}
	message.Peers[1].Owner = &mtcpv1.Owner{Ref: scopeMember}
	message.Peers[1].Kubernetes = &mtcpv1.KubernetesAccess{
		Grants:       []*mtcpv1.KubernetesGrant{{Group: "edit", ValidUntilMs: time.Now().Add(time.Hour).UnixMilli()}},
		ScopedGrants: []*mtcpv1.KubernetesScopedGrant{scopedGrant("view", scope)}}
	return message, scope
}

// A gateway declares gateway.kube.v2 only when it applies profiles, and
// only beside gateway.kube.v1 (mtcp-v1 §13).
func TestGatewayDeclaresKubeV2OnlyWithProfiles(t *testing.T) {
	t.Parallel()
	with := controlplane.NetmapOptions{KubeProfiles: true}
	if slices.Contains(streamCapabilities(controlplane.NetmapOptions{}, true), "gateway.kube.v2") ||
		slices.Contains(streamCapabilities(with, false), "gateway.kube.v2") ||
		!slices.Contains(streamCapabilities(with, true), "gateway.kube.v2") ||
		!slices.Contains(streamCapabilities(with, true), "gateway.kube.v1") {
		t.Fatal("gateway.kube.v2 declared where it should not be, or missing")
	}
}

// Scoped grants resolve against the table, and are never whole groups.
func TestGatewayResolvesScopedGrants(t *testing.T) {
	t.Parallel()
	message, scope := fixture(t)
	state := gatewayState(true)
	if err := state.applySnapshot(message); err != nil {
		t.Fatal(err)
	}
	snapshot := build(t, state)
	var hash [32]byte
	copy(hash[:], scope.GetHash())
	resolved, found := snapshot.KubernetesScopes[hash]
	if snapshot.KubernetesWithheld || !found || resolved.ProfileName != "reader" ||
		!slices.Equal(resolved.Scope.Namespaces(), []string{"team-a"}) {
		t.Fatalf("scopes %+v, withheld %v", snapshot.KubernetesScopes, snapshot.KubernetesWithheld)
	}
	a := peerAccess(t, snapshot, "peer-a")
	if a == nil || len(a.Grants) != 0 || len(a.Scoped) != 1 || a.Scoped[0].Scope != hash || a.Scoped[0].Report ||
		len(a.GroupsAt(time.Now())) != 0 {
		t.Fatalf("peer-a = %+v", a)
	}
	b := peerAccess(t, snapshot, "peer-b")
	if b == nil || !slices.Equal(b.GroupsAt(time.Now()), []string{"edit"}) || len(b.Scoped) != 1 {
		t.Fatalf("peer-b = %+v", b)
	}
}

// A v1 gateway ignores the table and scoped grants: it sees fewer grants,
// never wider ones (mtcp-v1 §7.12, K2-I5).
func TestV1GatewayIgnoresScopedGrants(t *testing.T) {
	t.Parallel()
	message, _ := fixture(t)
	state := gatewayState(false)
	if err := state.applySnapshot(message); err != nil {
		t.Fatal(err)
	}
	snapshot := build(t, state)
	if snapshot.KubernetesScopes != nil || peerAccess(t, snapshot, "peer-a") != nil {
		t.Fatalf("v1 took scopes: %+v, peer-a %+v", snapshot.KubernetesScopes, peerAccess(t, snapshot, "peer-a"))
	}
	if b := peerAccess(t, snapshot, "peer-b"); b == nil || len(b.Scoped) != 0 ||
		!slices.Equal(b.GroupsAt(time.Now()), []string{"edit"}) {
		t.Fatalf("peer-b = %+v", b)
	}
}

// Errors only narrow: a table unusable as a whole withholds every peer's
// access; a wrong profile, scope or grant costs only what depends on it; a
// peer's grants out of order cost that peer (mtcp-v1 §7.12).
func TestScopeErrorsOnlyNarrow(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		change    func(*mtcpv1.MapSnapshot, *mtcpv1.KubernetesScope)
		withheld  bool
		aScoped   int  // -1: peer-a loses its access
		bWhole    bool // peer-b keeps edit
		bScoped   int
		scopesNow int
	}{
		"valid": {func(*mtcpv1.MapSnapshot, *mtcpv1.KubernetesScope) {}, false, 1, true, 1, 1},
		"table out of order": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			message.KubernetesScopes.Scopes = append(message.KubernetesScopes.Scopes, message.KubernetesScopes.Scopes[0])
		}, true, -1, false, 0, 0},
		"profile hash wrong": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			message.KubernetesScopes.Profiles[0].Name = "other"
		}, false, -1, true, 0, 0},
		"scope namespaces unsorted": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			message.KubernetesScopes.Scopes[0].Namespaces = []string{"team-b", "team-a"}
		}, false, -1, true, 0, 0},
		"scope hash wrong": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			message.KubernetesScopes.Scopes[0].ClusterPart = true
		}, false, -1, true, 0, 0},
		"no table": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			message.KubernetesScopes = nil
		}, false, -1, true, 0, 0},
		"unknown mode": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			message.Peers[0].Kubernetes.ScopedGrants[0].Mode = 7
		}, false, -1, true, 1, 1},
		"enforce with a report deadline": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			message.Peers[0].Kubernetes.ScopedGrants[0].ReportUntilMs = time.Now().UnixMilli()
		}, false, -1, true, 1, 1},
		"report without a deadline": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			message.Peers[0].Kubernetes.ScopedGrants[0].Mode = mtcpv1.KubernetesScopedGrant_REPORT
		}, false, -1, true, 1, 1},
		"report past the grant": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			grant := message.Peers[0].Kubernetes.ScopedGrants[0]
			grant.Mode, grant.ReportUntilMs = mtcpv1.KubernetesScopedGrant_REPORT, grant.ValidUntilMs+1
		}, false, -1, true, 1, 1},
		"report within the grant": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			grant := message.Peers[0].Kubernetes.ScopedGrants[0]
			grant.Mode, grant.ReportUntilMs = mtcpv1.KubernetesScopedGrant_REPORT, grant.ValidUntilMs-1
		}, false, 1, true, 1, 1},
		"scope names no profile": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			message.KubernetesScopes.Profiles = nil
		}, false, -1, true, 0, 0},
		"short scope": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			grant := message.Peers[0].Kubernetes.ScopedGrants[0]
			grant.Scope = grant.Scope[:31]
		}, false, -1, true, 1, 1},
		"negative mode": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			message.Peers[0].Kubernetes.ScopedGrants[0].Mode = -1
		}, false, -1, true, 1, 1},
		"scoped group not a label": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			message.Peers[1].Kubernetes.ScopedGrants[0].Group = "View"
		}, false, 1, true, 0, 1},
		"grant names no scope": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			message.Peers[0].Kubernetes.ScopedGrants[0].Scope = bytes.Repeat([]byte{9}, 32)
		}, false, -1, true, 1, 1},
		"grants twice": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			grants := message.Peers[1].Kubernetes.ScopedGrants
			message.Peers[1].Kubernetes.ScopedGrants = append(grants, grants[0])
		}, false, 1, false, 0, 1},
		"65 grants": {func(message *mtcpv1.MapSnapshot, scope *mtcpv1.KubernetesScope) {
			access := message.Peers[1].Kubernetes
			for index := range 64 {
				access.Grants = append(access.Grants, &mtcpv1.KubernetesGrant{
					Group: "g" + string(rune('a'+index/26)) + string(rune('a'+index%26)), ValidUntilMs: access.Grants[0].ValidUntilMs})
			}
		}, false, 1, false, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			message, scope := fixture(t)
			test.change(message, scope)
			state := gatewayState(true)
			if err := state.applySnapshot(message); err != nil {
				t.Fatal(err)
			}
			snapshot := build(t, state)
			a, b := peerAccess(t, snapshot, "peer-a"), peerAccess(t, snapshot, "peer-b")
			switch {
			case snapshot.KubernetesWithheld != test.withheld, len(snapshot.KubernetesScopes) != test.scopesNow:
				t.Errorf("withheld %v, scopes %d", snapshot.KubernetesWithheld, len(snapshot.KubernetesScopes))
			case test.aScoped < 0 && a != nil, test.aScoped >= 0 && (a == nil || len(a.Scoped) != test.aScoped):
				t.Errorf("peer-a = %+v", a)
			case !test.bWhole && b != nil && (len(b.Grants) != 0 || len(b.Scoped) != 0):
				t.Errorf("peer-b kept %+v", b)
			case test.bWhole && (b == nil || !slices.Contains(b.GroupsAt(time.Now()), "edit") || len(b.Scoped) != test.bScoped):
				t.Errorf("peer-b = %+v", b)
			}
		})
	}
}

// A delta replaces the table only when it carries one; a withheld table
// holds until a valid one arrives.
func TestScopeTableAcrossDeltas(t *testing.T) {
	t.Parallel()
	message, scope := fixture(t)
	valid := proto.Clone(message.KubernetesScopes).(*mtcpv1.KubernetesScopeTable)
	broken := proto.Clone(valid).(*mtcpv1.KubernetesScopeTable)
	broken.Scopes = append(broken.Scopes, broken.Scopes[0])
	state := gatewayState(true)
	if err := state.applySnapshot(message); err != nil {
		t.Fatal(err)
	}
	step := func(seq uint64, scopes *mtcpv1.KubernetesScopeTable, wantWithheld bool, wantScopes int) {
		t.Helper()
		if err := state.applyDelta(&mtcpv1.MapDelta{View: &mtcpv1.View{Epoch: 7, Seq: seq}, KubernetesScopes: scopes}); err != nil {
			t.Fatal(err)
		}
		snapshot := build(t, state)
		if snapshot.KubernetesWithheld != wantWithheld || len(snapshot.KubernetesScopes) != wantScopes {
			t.Fatalf("seq %d: withheld %v, scopes %d", seq, snapshot.KubernetesWithheld, len(snapshot.KubernetesScopes))
		}
	}
	step(2, nil, false, 1)
	step(3, broken, true, 0)
	step(4, nil, true, 0) // a delta without a table keeps the bad one
	step(5, valid, false, 1)
	step(6, &mtcpv1.KubernetesScopeTable{}, false, 0) // present and empty: no scopes
	snapshot := build(t, state)
	if access := peerAccess(t, snapshot, "peer-a"); access != nil {
		t.Fatalf("peer-a kept access to a scope gone: %+v", access)
	}
	if b := peerAccess(t, snapshot, "peer-b"); b == nil || !slices.Equal(b.GroupsAt(time.Now()), []string{"edit"}) ||
		len(b.Scoped) != 0 {
		t.Fatalf("peer-b = %+v", b)
	}
	step(7, broken, true, 0)
	// A snapshot without a table holds none: nothing is withheld.
	next, _ := fixture(t)
	next.View.Epoch, next.KubernetesScopes = 8, nil
	if err := state.applySnapshot(next); err != nil {
		t.Fatal(err)
	}
	if snapshot := build(t, state); snapshot.KubernetesWithheld || len(snapshot.KubernetesScopes) != 0 {
		t.Fatalf("a snapshot without a table: withheld %v, scopes %d", snapshot.KubernetesWithheld,
			len(snapshot.KubernetesScopes))
	}
	if scope == nil {
		t.Fatal("no scope")
	}
}

// Scoped grants keep their key order (mtcp-v1 §7.12): enforcing before
// reporting, report deadlines increasing; a grant twice or out of order
// costs the peer its access.
func TestScopedGrantOrder(t *testing.T) {
	t.Parallel()
	message, scope := fixture(t)
	until := message.Peers[0].Kubernetes.ScopedGrants[0].ValidUntilMs
	report := func(reportUntil int64) *mtcpv1.KubernetesScopedGrant {
		grant := scopedGrant("view", scope)
		grant.Mode, grant.ReportUntilMs, grant.ValidUntilMs = mtcpv1.KubernetesScopedGrant_REPORT, reportUntil, until
		return grant
	}
	enforce := scopedGrant("view", scope)
	enforce.ValidUntilMs = until
	for name, test := range map[string]struct {
		grants []*mtcpv1.KubernetesScopedGrant
		kept   int // -1: the peer loses its access
	}{
		"enforce then report":         {[]*mtcpv1.KubernetesScopedGrant{enforce, report(until - 10)}, 2},
		"report then enforce":         {[]*mtcpv1.KubernetesScopedGrant{report(until - 10), enforce}, -1},
		"two reports by deadline":     {[]*mtcpv1.KubernetesScopedGrant{report(until - 20), report(until - 10)}, 2},
		"two reports out of order":    {[]*mtcpv1.KubernetesScopedGrant{report(until - 10), report(until - 20)}, -1},
		"the same report twice":       {[]*mtcpv1.KubernetesScopedGrant{report(until - 10), report(until - 10)}, -1},
		"a dropped grant keeps order": {[]*mtcpv1.KubernetesScopedGrant{enforce, report(until + 10)}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			message, _ := fixture(t)
			message.Peers[0].Kubernetes.ScopedGrants = test.grants
			state := gatewayState(true)
			if err := state.applySnapshot(message); err != nil {
				t.Fatal(err)
			}
			access := peerAccess(t, build(t, state), "peer-a")
			if test.kept < 0 && access != nil || test.kept >= 0 && (access == nil || len(access.Scoped) != test.kept) {
				t.Fatalf("peer-a = %+v", access)
			}
		})
	}
}

// The wire layout of the new fields never changes silently (mtcp-v1 §7.12,
// §6.10): field numbers 3, 14, 16, 14 and 15.
func TestScopedFieldsWireGolden(t *testing.T) {
	t.Parallel()
	encode := proto.MarshalOptions{Deterministic: true}
	for name, test := range map[string]struct {
		message proto.Message
		want    string
	}{
		"access": {&mtcpv1.KubernetesAccess{Grants: []*mtcpv1.KubernetesGrant{{Group: "view", ValidUntilMs: 1000}},
			ScopedGrants: []*mtcpv1.KubernetesScopedGrant{{Group: "edit", Scope: bytes.Repeat([]byte{1}, 32),
				Mode: mtcpv1.KubernetesScopedGrant_REPORT, ReportUntilMs: 500, ValidUntilMs: 1000}}},
			"0a090a047669657710e8071a300a046564697412200101010101010101010101010101010101010101010101010101010101010101180120f40328e807"},
		"snapshot table": {&mtcpv1.MapSnapshot{KubernetesScopes: &mtcpv1.KubernetesScopeTable{}}, "7200"},
		"delta table": {&mtcpv1.MapDelta{KubernetesScopes: &mtcpv1.KubernetesScopeTable{Scopes: []*mtcpv1.KubernetesScope{{
			Hash: bytes.Repeat([]byte{2}, 32), Profile: bytes.Repeat([]byte{3}, 32), Namespaces: []string{"team-a"},
			ClusterPart: true}}}},
			"820150124e0a200202020202020202020202020202020202020202020202020202020202020202122003030303030303030303030303030303030303030303030303030303030303031a067465616d2d612001"},
		"audit intent": {&mtcpv1.KubeAuditIntent{Profile: bytes.Repeat([]byte{4}, 32), ReportAllowed: true},
			"722004040404040404040404040404040404040404040404040404040404040404047801"},
	} {
		encoded, err := encode.Marshal(test.message)
		if err != nil || hex.EncodeToString(encoded) != test.want {
			t.Errorf("%s: %x (%v)", name, encoded, err)
		}
	}
}

// Whatever the table and grants, the map applies, scoped grants never join
// the whole ones, every kept scoped grant names a usable scope, and a
// withheld table leaves no peer any access.
func FuzzScopedMap(f *testing.F) {
	message, _ := fixture(f)
	tableBytes, _ := proto.Marshal(message.KubernetesScopes)
	accessBytes, _ := proto.Marshal(message.Peers[1].Kubernetes)
	f.Add(tableBytes, accessBytes)
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, tableBytes, accessBytes []byte) {
		var scopes mtcpv1.KubernetesScopeTable
		var access mtcpv1.KubernetesAccess
		if proto.Unmarshal(tableBytes, &scopes) != nil || proto.Unmarshal(accessBytes, &access) != nil {
			return
		}
		message := snapshotMessage(7)
		message.KubernetesScopes = &scopes
		message.Peers[0].Owner = &mtcpv1.Owner{Ref: scopeMember}
		message.Peers[0].Kubernetes = &access
		state := gatewayState(true)
		if state.applySnapshot(message) != nil {
			return
		}
		snapshot, err := state.build(snapshotInput{revision: 1, controlTime: time.Now(), now: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.KubernetesWithheld {
			for _, peer := range snapshot.Peers {
				if peer.Kubernetes != nil {
					t.Fatal("a withheld table left access")
				}
			}
		}
		got := peerAccess(t, snapshot, "peer-a")
		if got == nil {
			return
		}
		if len(got.Grants) != len(access.GetGrants()) {
			t.Fatal("scoped grants joined the whole ones")
		}
		sent := map[string]bool{}
		for _, grant := range access.GetScopedGrants() {
			sent[grant.GetGroup()] = true
		}
		for _, grant := range got.Scoped {
			if _, found := snapshot.KubernetesScopes[grant.Scope]; !found || !sent[grant.Group] {
				t.Fatal("a kept grant names no usable scope, or a group never sent scoped")
			}
		}
	})
}
