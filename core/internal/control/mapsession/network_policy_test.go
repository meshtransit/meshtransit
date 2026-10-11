package mapsession

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
)

var policyNow = time.Date(2026, time.October, 11, 12, 0, 0, 0, time.UTC)

func policyNodeID(t *testing.T, device int64) node.ID {
	t.Helper()
	id, err := node.ParseID(fmt.Sprintf("01890f00-0000-7000-8000-%012x", 0x700+device))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func policyRuleID(t *testing.T, ordinal int) policy.RuleID {
	t.Helper()
	id, err := policy.ParseRuleID(fmt.Sprintf("01890f00-0000-7000-8000-%012x", 0x800+ordinal))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type policyPair struct{ source, destination int64 }

// networkPolicyFixture: Devices 1..6 live; 6 expires an hour after
// policyNow. Device group 10 = {1, 2}; tag 20 = {3}; identity group 30 =
// {4 until policyNow+1h, 5}. Rules: 1 -> 3 (Device), group 10 -> tag 20,
// identity group 30 -> Device 1, Device 6 -> group 10.
func networkPolicyFixture(t *testing.T) (NetworkPolicy, map[int64]node.ID) {
	t.Helper()
	scope := snapshotFixture(t).Scope()
	ids := map[int64]node.ID{}
	devices := make([]PolicyDevice, 0, 6)
	for device := int64(1); device <= 6; device++ {
		ids[device] = policyNodeID(t, device)
		expires := policyNow.Add(24 * time.Hour)
		if device == 6 {
			expires = policyNow.Add(time.Hour)
		}
		devices = append(devices, PolicyDevice{Device: device, NodeID: ids[device], ExpiresAt: expires})
	}
	tcp22, _ := policy.NewPortRange(22, 22)
	rule := func(ordinal int, sourceKind SelectorKind, sourceRef int64, destinationKind SelectorKind, destinationRef int64) NetworkPolicyRule {
		return NetworkPolicyRule{ID: policyRuleID(t, ordinal), SourceKind: sourceKind, SourceRef: sourceRef,
			DestinationKind: destinationKind, DestinationRef: destinationRef, Protocol: policy.ProtocolTCP,
			Ports: []policy.PortRange{tcp22}}
	}
	networkPolicy, err := NewNetworkPolicy(NetworkPolicyParams{
		Scope: scope, Revision: 4, ReleaseActive: true,
		Rules: []NetworkPolicyRule{
			rule(1, SelectorDevice, 1, SelectorDevice, 3),
			rule(2, SelectorDeviceGroup, 10, SelectorDeviceTag, 20),
			rule(3, SelectorIdentityGroup, 30, SelectorDevice, 1),
			rule(4, SelectorDevice, 6, SelectorDeviceGroup, 10),
		},
		Members: []SelectorMember{
			{Kind: SelectorDeviceGroup, Selector: 10, Device: 1}, {Kind: SelectorDeviceGroup, Selector: 10, Device: 2},
			{Kind: SelectorDeviceTag, Selector: 20, Device: 3},
			{Kind: SelectorIdentityGroup, Selector: 30, Device: 4, ValidUntil: policyNow.Add(time.Hour)},
			{Kind: SelectorIdentityGroup, Selector: 30, Device: 5},
		},
		Devices: devices,
	})
	if err != nil {
		t.Fatal(err)
	}
	return networkPolicy, ids
}

func pairsOf(t *testing.T, snapshot policy.Snapshot, ids map[int64]node.ID) map[policyPair]int {
	t.Helper()
	byNode := map[node.ID]int64{}
	for device, id := range ids {
		byNode[id] = device
	}
	pairs := map[policyPair]int{}
	for _, rule := range snapshot.Rules() {
		pairs[policyPair{byNode[rule.SourceNodeID()], byNode[rule.DestinationNodeID()]}]++
	}
	return pairs
}

func TestNetworkPolicyExpandsAroundOneDevice(t *testing.T) {
	t.Parallel()
	networkPolicy, ids := networkPolicyFixture(t)
	for device, want := range map[int64]map[policyPair]int{
		1: {{1, 3}: 2, {4, 1}: 1, {5, 1}: 1, {6, 1}: 1}, // rule 1 and rule 2 both pair 1 -> 3
		2: {{2, 3}: 1, {6, 2}: 1},
		3: {{1, 3}: 2, {2, 3}: 1},
		4: {{4, 1}: 1},
		6: {{6, 1}: 1, {6, 2}: 1},
	} {
		snapshot, err := networkPolicy.For(ids[device], policyNow, 100)
		if err != nil {
			t.Fatalf("For(%d) error = %v", device, err)
		}
		got := pairsOf(t, snapshot, ids)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("For(%d) pairs = %v, want %v", device, got, want)
		}
	}
}

func TestNetworkPolicyAppliesExpiry(t *testing.T) {
	t.Parallel()
	networkPolicy, ids := networkPolicyFixture(t)
	later := policyNow.Add(2 * time.Hour) // Device 6 expired, Device 4's membership lapsed
	snapshot, err := networkPolicy.For(ids[1], later, 100)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := pairsOf(t, snapshot, ids), map[policyPair]int{{1, 3}: 2, {5, 1}: 1}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("pairs after expiry = %v, want %v", got, want)
	}
	expired, err := networkPolicy.For(ids[6], later, 100)
	if err != nil || len(expired.Rules()) != 0 {
		t.Fatalf("an expired Device got rules: %d, %v", len(expired.Rules()), err)
	}
	if !networkPolicy.ChangesAt().Equal(policyNow.Add(time.Hour)) {
		t.Fatalf("ChangesAt() = %v", networkPolicy.ChangesAt())
	}
}

func TestNetworkPolicyBoundsAndRelease(t *testing.T) {
	t.Parallel()
	networkPolicy, ids := networkPolicyFixture(t)
	if _, err := networkPolicy.For(ids[1], policyNow, 2); !errors.Is(err, ErrPacketPolicyLimit) {
		t.Fatalf("For() over the limit = %v, want ErrPacketPolicyLimit", err)
	}
	scope := snapshotFixture(t).Scope()
	first, err := NewNetworkPolicy(NetworkPolicyParams{Scope: scope, Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot, err := first.For(ids[1], policyNow, 10); err != nil || len(snapshot.Rules()) != 0 {
		t.Fatalf("revision 1 without a release = %v", err)
	}
	missing, err := NewNetworkPolicy(NetworkPolicyParams{Scope: scope, Revision: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missing.For(ids[1], policyNow, 10); !errors.Is(err, ErrInvalidNetworkPolicy) {
		t.Fatalf("a later revision without its release = %v, want invalid", err)
	}
	if _, err := NewNetworkPolicy(NetworkPolicyParams{Scope: scope, Revision: 3, ReleaseActive: true,
		Rules: []NetworkPolicyRule{{ID: policyRuleID(t, 9), SourceKind: SelectorDevice, SourceRef: 1,
			DestinationKind: SelectorIdentityGroup, DestinationRef: 30, Protocol: policy.ProtocolICMP}}}); err == nil {
		t.Fatal("an Identity Group destination was accepted")
	}
}

func TestNetworkPolicyAndInventoryEqualCompareEvidence(t *testing.T) {
	t.Parallel()
	scope := snapshotFixture(t).Scope()
	build := func(revision int64) NetworkPolicy {
		policy, err := NewNetworkPolicy(NetworkPolicyParams{Scope: scope, Revision: revision})
		if err != nil {
			t.Fatal(err)
		}
		return policy
	}
	if !build(1).Equal(build(1)) || build(1).Equal(build(2)) || build(1).Equal(NetworkPolicy{}) {
		t.Fatal("NetworkPolicy.Equal() disagrees with the evidence")
	}
	params, list := largeNetworkFixture(t, 3, 1)
	first, err := NewNetworkInventory(params.Scope, list)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := NewNetworkInventory(params.Scope, list)
	fewer, _ := NewNetworkInventory(params.Scope, list[:2])
	if !first.Equal(second) || first.Same(second) || !first.Same(first) || first.Equal(fewer) {
		t.Fatal("NetworkInventory Equal/Same disagree with the evidence")
	}
}
