package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/catalog"
	"meshtransit.net/core/internal/domain/policy/compilation"
	policypublication "meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/workspace"
)

// A rule to a Kubernetes cluster is decoded as such, shown as such, and the
// refusals of a rule naming a replica name the rule.
func TestPolicyRulesToKubernetesClusters(t *testing.T) {
	t.Parallel()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	scope, _ := network.NewScope(workspaceID, networkID)
	const cluster = "01890f00-0000-7000-8000-000000000f01"
	input := publishPolicyRuleRequest{
		ID: "01890f00-0000-7000-8000-000000000801", SourceDeviceGroupID: "01890f00-0000-7000-8000-000000000a01",
		DestinationKubernetesCluster: cluster, Protocol: "tcp",
		DestinationPortRanges: []publishPolicyPortRangeRequest{{First: 443, Last: 443}},
	}
	intent, err := decodePolicyRuleIntent(scope, input)
	if err != nil || intent.DestinationKubernetesClusterID().String() != cluster {
		t.Fatalf("decodePolicyRuleIntent() = %+v, %v", intent, err)
	}
	other := input
	other.DestinationPortRanges = []publishPolicyPortRangeRequest{{First: 6443, Last: 6443}}
	if _, err := decodePolicyRuleIntent(scope, other); err == nil {
		t.Fatal("a rule to a cluster on port 6443 was decoded")
	}
	malformed := input
	malformed.DestinationKubernetesCluster = "kinda-k1"
	if _, err := decodePolicyRuleIntent(scope, malformed); err == nil {
		t.Fatal("a cluster named by name was decoded")
	}

	group, _ := devicegroup.ParseID("01890f00-0000-7000-8000-000000000a09")
	clusterID, _ := kubecluster.ParseID(cluster)
	https, _ := policy.NewPortRange(443, 443)
	byGroup, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: intent.ID(), Scope: scope, SourceGroupID: intent.SourceGroupID(), DestinationDeviceGroupID: group,
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{https},
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := policypublication.NewSemanticHash([32]byte{7})
	snapshot, err := catalog.NewSnapshot(catalog.SnapshotParams{Scope: scope, Revision: 4, SemanticHash: hash,
		RuleCount: 1, DeviceRulesOnly: true, Rows: []catalog.Row{{Intent: byGroup}}})
	if err != nil {
		t.Fatal(err)
	}
	named, err := snapshot.WithKubernetesClusters([]kubecluster.PolicyGroup{
		{ClusterID: clusterID, Name: "kinda-k1", GroupID: group}})
	if err != nil {
		t.Fatal(err)
	}
	rule := activePolicyProjection(named).Rules[0]
	if rule.SelectorKind != "kubernetes_cluster" || rule.DestinationSelectorID != cluster ||
		rule.DestinationDeviceID != "" || !activePolicyProjection(named).DeviceRulesOnly {
		t.Fatalf("projection = %+v", rule)
	}

	ruleID, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000802")
	refused := classifyPolicyPublicationError(errors.Join(&policypublication.KubernetesRuleError{RuleID: ruleID},
		errors.New("database")))
	if refused.Status != http.StatusConflict || refused.Code != "kubernetes_replica_rule" ||
		!strings.Contains(refused.Message, ruleID.String()) {
		t.Fatalf("classify = %+v", refused)
	}
	if unknown := classifyPolicyCompilationError(compilation.ErrKubernetesClusterUnavailable); unknown.Code !=
		"kubernetes_cluster_unavailable" || unknown.Status != http.StatusConflict {
		t.Fatalf("classify unknown cluster = %+v", unknown)
	}
	if unknown := classifyPolicySimulationError(compilation.ErrKubernetesClusterUnavailable); unknown.Code !=
		"kubernetes_cluster_unavailable" {
		t.Fatalf("classify simulation unknown cluster = %+v", unknown)
	}
}

// A rule to a cluster names its Kubernetes groups: given ones are decoded,
// none keeps those it has, an empty list is refused, and a read shows them;
// the refusals answer with their own codes (K1a3).
func TestPolicyRulesNameKubernetesGroups(t *testing.T) {
	t.Parallel()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	scope, _ := network.NewScope(workspaceID, networkID)
	groups := []string{"view", "edit"}
	input := publishPolicyRuleRequest{
		ID: "01890f00-0000-7000-8000-000000000801", SourceDeviceGroupID: "01890f00-0000-7000-8000-000000000a01",
		DestinationKubernetesCluster: "01890f00-0000-7000-8000-000000000f01", Protocol: "tcp",
		DestinationPortRanges: []publishPolicyPortRangeRequest{{First: 443, Last: 443}},
		KubernetesGroups:      &groups,
	}
	intent, err := decodePolicyRuleIntent(scope, input)
	if err != nil || strings.Join(intent.KubernetesGroups(), ",") != "edit,view" {
		t.Fatalf("decodePolicyRuleIntent() = %v, %v", intent.KubernetesGroups(), err)
	}
	kept := input
	kept.KubernetesGroups = nil
	if intent, err := decodePolicyRuleIntent(scope, kept); err != nil || intent.KubernetesGroups() != nil {
		t.Fatalf("no groups: %v, %v", intent.KubernetesGroups(), err)
	}
	empty := input
	empty.KubernetesGroups = &[]string{}
	if _, err := decodePolicyRuleIntent(scope, empty); err == nil {
		t.Fatal("an empty group list was decoded")
	}
	required := classifyPolicyCompilationError(compilation.ErrKubernetesGroupsRequired)
	if required.Status != http.StatusUnprocessableEntity || required.Code != "kubernetes_groups_required" {
		t.Fatalf("required = %+v", required)
	}
	lost := classifyPolicyPublicationError(policypublication.ErrKubernetesGroups)
	if lost.Status != http.StatusConflict || lost.Code != "kubernetes_groups_conflict" {
		t.Fatalf("lost = %+v", lost)
	}
}
