package mapsession

import (
	"slices"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

// kubernetesAccessFixture: gateway 9 is the only member of cluster group 90.
// Device group 10 = {1, 2}; identity group 30 = {4 until policyNow+1h};
// Devices 1..5 and 9 live. Rules to the cluster: group 10 [view], identity
// group 30 [edit], Device 2 [debug] (granted twice to 2 with group 10), and
// Device 3 [admin] with no source data. A plain rule 1 -> 9 on TCP 22 grants
// nothing. Device 5 is a router; Device 1's owner expires in 2h.
func kubernetesAccessFixture(t *testing.T, sources []KubernetesSource) (NetworkPolicy, map[int64]node.ID) {
	t.Helper()
	scope := snapshotFixture(t).Scope()
	ids := map[int64]node.ID{}
	devices := make([]PolicyDevice, 0, 6)
	for _, device := range []int64{1, 2, 3, 4, 5, 9} {
		ids[device] = policyNodeID(t, device)
		devices = append(devices, PolicyDevice{Device: device, NodeID: ids[device], ExpiresAt: policyNow.Add(24 * time.Hour)})
	}
	https, _ := policy.NewPortRange(443, 443)
	ssh, _ := policy.NewPortRange(22, 22)
	toCluster := func(ordinal int, kind SelectorKind, ref int64, groups ...string) NetworkPolicyRule {
		return NetworkPolicyRule{ID: policyRuleID(t, ordinal), SourceKind: kind, SourceRef: ref,
			DestinationKind: SelectorDeviceGroup, DestinationRef: 90, Protocol: policy.ProtocolTCP,
			Ports: []policy.PortRange{https}, KubernetesGroups: groups}
	}
	networkPolicy, err := NewNetworkPolicy(NetworkPolicyParams{
		Scope: scope, Revision: 4, ReleaseActive: true,
		Rules: []NetworkPolicyRule{
			toCluster(1, SelectorDeviceGroup, 10, "view"),
			toCluster(2, SelectorIdentityGroup, 30, "edit"),
			toCluster(3, SelectorDevice, 2, "debug", "view"),
			toCluster(4, SelectorDevice, 3, "admin"),
			toCluster(5, SelectorDevice, 5, "view"),
			toCluster(6, SelectorDevice, 4),
			{ID: policyRuleID(t, 7), SourceKind: SelectorDevice, SourceRef: 1, DestinationKind: SelectorDevice,
				DestinationRef: 9, Protocol: policy.ProtocolTCP, Ports: []policy.PortRange{ssh}},
		},
		Members: []SelectorMember{
			{Kind: SelectorDeviceGroup, Selector: 90, Device: 9},
			{Kind: SelectorDeviceGroup, Selector: 10, Device: 1}, {Kind: SelectorDeviceGroup, Selector: 10, Device: 2},
			{Kind: SelectorIdentityGroup, Selector: 30, Device: 4, ValidUntil: policyNow.Add(time.Hour)},
		},
		Devices:           devices,
		KubernetesSources: sources,
	})
	if err != nil {
		t.Fatal(err)
	}
	return networkPolicy, ids
}

// replicaOf reports gateway 9 as the only replica of its cluster.
func replicaOf(ids map[int64]node.ID) func(node.ID) bool {
	return func(id node.ID) bool { return id == ids[9] }
}

func kubernetesSourcesFixture() []KubernetesSource {
	return []KubernetesSource{
		{Device: 1, OwnerKind: KubernetesOwnerMember, OwnerRef: "01890f00-0000-7000-8000-000000000011",
			MemberOwned: true, OwnerActive: true, OwnerValidUntil: policyNow.Add(2 * time.Hour)},
		{Device: 2, OwnerKind: KubernetesOwnerTags, OwnerRef: "tags:01890f00-0000-7000-8000-000000000c01",
			OwnerChangedAt: policyNow.Add(-time.Hour)},
		{Device: 4, OwnerKind: KubernetesOwnerMember, OwnerRef: "01890f00-0000-7000-8000-000000000014",
			MemberOwned: true, OwnerActive: true},
		{Device: 5, OwnerKind: KubernetesOwnerWorkspace, Forwards: true},
		// Device 6 is in no rule's source: its owner's end changes nothing.
		{Device: 6, OwnerKind: KubernetesOwnerMember, OwnerRef: "01890f00-0000-7000-8000-000000000016",
			MemberOwned: true, OwnerActive: true, OwnerValidUntil: policyNow.Add(30 * time.Minute)},
		{Device: 9, OwnerKind: KubernetesOwnerWorkspace},
	}
}

// The gateway's peers get exactly the groups of the rules whose edges reach
// it, each until the earliest deadline on the path it came by, and only with
// the evidence behind them (K1a3 §4.3, §12.2, §12.3, §13.5).
func TestKubernetesAccessComesFromTheEdgesToTheGateway(t *testing.T) {
	t.Parallel()
	networkPolicy, ids := kubernetesAccessFixture(t, kubernetesSourcesFixture())
	access := networkPolicy.KubernetesAccessFor(ids[9], replicaOf(ids), policyNow)
	grants := func(device int64) map[string]time.Time {
		result := map[string]time.Time{}
		for _, grant := range access[ids[device]].Grants {
			result[grant.Group] = grant.ValidUntil
		}
		return result
	}
	day := policyNow.Add(24 * time.Hour)
	// Device 1: group 10 [view], until its owner's membership ends.
	if got := grants(1); len(got) != 1 || !got["view"].Equal(policyNow.Add(2*time.Hour)) {
		t.Fatalf("Device 1 = %v", got)
	}
	// Device 2: group 10 [view] and itself [debug, view]; the later deadline wins.
	if got := grants(2); len(got) != 2 || !got["view"].Equal(day) || !got["debug"].Equal(day) {
		t.Fatalf("Device 2 = %v", got)
	}
	if !slices.IsSortedFunc(access[ids[2]].Grants, func(a, b KubernetesGrant) int {
		if a.Group < b.Group {
			return -1
		}
		return 1
	}) || access[ids[2]].OwnerRef != "tags:01890f00-0000-7000-8000-000000000c01" ||
		!access[ids[2]].OwnerChangedAt.Equal(policyNow.Add(-time.Hour)) {
		t.Fatalf("Device 2 access = %+v", access[ids[2]])
	}
	// Device 4: identity group 30 [edit] until its membership; the rule
	// without groups grants none.
	if got := grants(4); len(got) != 1 || !got["edit"].Equal(policyNow.Add(time.Hour)) {
		t.Fatalf("Device 4 = %v", got)
	}
	// Device 3 has no source data, Device 5 forwards for others, the
	// gateway itself and the plain rule grant nothing.
	for _, device := range []int64{3, 5, 9} {
		if _, granted := access[ids[device]]; granted {
			t.Errorf("Device %d was granted %+v", device, access[ids[device]])
		}
	}
	// Past a deadline the grant is gone: after an hour Device 4 has none.
	if later := networkPolicy.KubernetesAccessFor(ids[9], replicaOf(ids), policyNow.Add(90*time.Minute)); len(later[ids[4]].Grants) != 0 {
		t.Fatalf("Device 4 after its membership: %+v", later[ids[4]])
	}
	// Selections still rebuild every map; an owner's end does not, the
	// grants it bounds carry it instead (§13.6).
	if !networkPolicy.ChangesAt().Equal(policyNow.Add(time.Hour)) {
		t.Fatalf("ChangesAt() = %v", networkPolicy.ChangesAt())
	}
	// A Device that is not a gateway, or a policy read without sources,
	// gets nothing.
	if access := networkPolicy.KubernetesAccessFor(ids[1], replicaOf(ids), policyNow); len(access) != 0 {
		t.Fatalf("a client got %+v", access)
	}
	bare, ids := kubernetesAccessFixture(t, nil)
	if access := bare.KubernetesAccessFor(ids[9], replicaOf(ids), policyNow); len(access) != 0 {
		t.Fatalf("no sources: %+v", access)
	}
}

// A member whose membership is not active gets no access, whatever the
// selector; the policy refuses inconsistent evidence.
func TestKubernetesAccessNeedsAnActiveOwner(t *testing.T) {
	t.Parallel()
	sources := kubernetesSourcesFixture()
	sources[1] = KubernetesSource{Device: 2, OwnerKind: KubernetesOwnerMember,
		OwnerRef: "01890f00-0000-7000-8000-000000000012", MemberOwned: true, OwnerActive: false}
	networkPolicy, ids := kubernetesAccessFixture(t, sources)
	if access := networkPolicy.KubernetesAccessFor(ids[9], replicaOf(ids), policyNow); len(access[ids[2]].Grants) != 0 {
		t.Fatalf("an inactive owner's Device: %+v", access[ids[2]])
	}
	scope := snapshotFixture(t).Scope()
	for name, params := range map[string]NetworkPolicyParams{
		"twice": {Scope: scope, Revision: 4, ReleaseActive: true,
			KubernetesSources: []KubernetesSource{{Device: 1, OwnerKind: KubernetesOwnerWorkspace},
				{Device: 1, OwnerKind: KubernetesOwnerWorkspace}}},
		"member without owner": {Scope: scope, Revision: 4, ReleaseActive: true,
			KubernetesSources: []KubernetesSource{{Device: 1, OwnerKind: KubernetesOwnerMember}}},
		"unknown owner kind": {Scope: scope, Revision: 4, ReleaseActive: true,
			KubernetesSources: []KubernetesSource{{Device: 1}}},
		"unsorted groups": {Scope: scope, Revision: 4, ReleaseActive: true, Rules: []NetworkPolicyRule{{
			ID: policyRuleID(t, 1), SourceKind: SelectorDevice, SourceRef: 1, DestinationKind: SelectorDeviceGroup,
			DestinationRef: 90, Protocol: policy.ProtocolTCP, KubernetesGroups: []string{"view", "edit"}}}},
		"groups to a Device": {Scope: scope, Revision: 4, ReleaseActive: true, Rules: []NetworkPolicyRule{{
			ID: policyRuleID(t, 1), SourceKind: SelectorDevice, SourceRef: 1, DestinationKind: SelectorDevice,
			DestinationRef: 2, Protocol: policy.ProtocolTCP, KubernetesGroups: []string{"view"}}}},
	} {
		if _, err := NewNetworkPolicy(params); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A member's Device speaks through its tags only while the member does: a
// tagged Device of an expired member gets nothing, and an active member's
// end bounds it (§4.4, b1 review H1).
func TestKubernetesAccessOfATaggedMemberDeviceNeedsItsOwner(t *testing.T) {
	t.Parallel()
	tagged := KubernetesSource{Device: 2, OwnerKind: KubernetesOwnerTags,
		OwnerRef: "tags:01890f00-0000-7000-8000-000000000c01", MemberOwned: true}
	sources := kubernetesSourcesFixture()
	sources[1] = tagged
	networkPolicy, ids := kubernetesAccessFixture(t, sources)
	if access := networkPolicy.KubernetesAccessFor(ids[9], replicaOf(ids), policyNow); len(access[ids[2]].Grants) != 0 {
		t.Fatalf("an expired member's tagged Device: %+v", access[ids[2]])
	}
	tagged.OwnerActive, tagged.OwnerValidUntil = true, policyNow.Add(3*time.Hour)
	sources[1] = tagged
	networkPolicy, ids = kubernetesAccessFixture(t, sources)
	access := networkPolicy.KubernetesAccessFor(ids[9], replicaOf(ids), policyNow)[ids[2]]
	if len(access.Grants) != 2 || !access.Grants[0].ValidUntil.Equal(policyNow.Add(3*time.Hour)) ||
		access.OwnerKind != KubernetesOwnerTags {
		t.Fatalf("an active member's tagged Device: %+v", access)
	}
	// A Device of the Workspace has no member to end.
	scope := snapshotFixture(t).Scope()
	if _, err := NewNetworkPolicy(NetworkPolicyParams{Scope: scope, Revision: 4, ReleaseActive: true,
		KubernetesSources: []KubernetesSource{{Device: 1, OwnerKind: KubernetesOwnerTags, OwnerRef: "tags:x",
			OwnerActive: true}}}); err == nil {
		t.Fatal("an active owner on a Device of the Workspace was accepted")
	}
}

// A reread of the same sources is the same policy; a change in a source
// alone is another, so the gateway's map follows it.
func TestKubernetesSourcesAreInPolicyEquality(t *testing.T) {
	t.Parallel()
	first, _ := kubernetesAccessFixture(t, kubernetesSourcesFixture())
	again, _ := kubernetesAccessFixture(t, kubernetesSourcesFixture())
	if !first.Equal(again) {
		t.Fatal("a reread of the same sources differs")
	}
	changed := kubernetesSourcesFixture()
	changed[2].OwnerActive = false
	other, _ := kubernetesAccessFixture(t, changed)
	if first.Equal(other) {
		t.Fatal("a changed owner left the policy equal")
	}
}

// A rule counts only when its destination group holds nothing but the
// gateway's cluster's replicas: were another Device in it, the group is not
// the cluster's and grants nothing (TD-CORE-100).
func TestKubernetesAccessNeedsTheClustersOwnGroup(t *testing.T) {
	t.Parallel()
	networkPolicy, ids := kubernetesAccessFixture(t, kubernetesSourcesFixture())
	if access := networkPolicy.KubernetesAccessFor(ids[9], func(node.ID) bool { return false }, policyNow); len(access) != 0 {
		t.Fatalf("a group of other Devices granted %+v", access)
	}
	if access := networkPolicy.KubernetesAccessFor(ids[9], nil, policyNow); len(access) != 0 {
		t.Fatalf("no replica check granted %+v", access)
	}
}
