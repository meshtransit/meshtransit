package httpapi

import (
	"encoding/json"
	"testing"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
)

// A reviewer's view of Kubernetes changes (K2h f5): the before side is null
// for an added rule, the after side for a removed one; full rights read as
// {"full": true}; a set is named as in the release it is in.
func TestEncodeKubernetesChanges(t *testing.T) {
	t.Parallel()
	access := releasedKubernetesAccess(t)
	profile := access.Profiles[0]
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: managementPolicySimulationScope(t), Revision: 1, Rules: []policy.Rule{},
	})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := publication.NewCandidate(snapshot, 1)
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := empty.WithKubernetesProfiles(access.Profiles)
	if err != nil {
		t.Fatal(err)
	}
	var profiled publication.KubernetesAccess
	var groups []string
	for _, rule := range access.Rules {
		if !rule.Access.IsZero() {
			profiled, groups = rule.Access, rule.Groups
		}
	}
	cluster := access.Rules[mustRuleIDForTest(t, "01890f00-0000-7000-8000-000000000d01")].Cluster
	changes := publication.KubernetesChanges{
		Sets:     []publication.KubernetesSetChange{{Change: publication.KubernetesChangeRemoved, Before: profile}},
		SetCount: 1,
		Rules: []publication.KubernetesRuleChange{
			{RuleID: mustRuleIDForTest(t, "01890f00-0000-7000-8000-000000000d01"),
				Change: publication.KubernetesChangeAdded, Cluster: cluster, GroupsAfter: []string{"view"}},
			{RuleID: mustRuleIDForTest(t, "01890f00-0000-7000-8000-000000000d02"),
				Change: publication.KubernetesChangeRemoved, Cluster: cluster, ClusterBefore: cluster,
				GroupsBefore: groups, AccessBefore: profiled},
		},
		RuleCount: 4,
	}
	// A rule moved to another cluster, to full rights: both sides named.
	other, err := kubecluster.ParseID("01890f00-0000-7000-8000-000000000a02")
	if err != nil {
		t.Fatal(err)
	}
	changes.Rules = append(changes.Rules, publication.KubernetesRuleChange{
		RuleID: mustRuleIDForTest(t, "01890f00-0000-7000-8000-000000000d03"),
		Change: publication.KubernetesChangeChanged, Cluster: other, ClusterBefore: cluster,
		GroupsBefore: groups, GroupsAfter: groups, AccessBefore: profiled,
	})
	encoded, err := json.Marshal(encodeKubernetesChanges(changes, baseline, empty))
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		SetCount int `json:"set_count"`
		Sets     []struct {
			Change string          `json:"change"`
			Before json.RawMessage `json:"before"`
			After  json.RawMessage `json:"after"`
		} `json:"sets"`
		RuleCount int                          `json:"rule_count"`
		Rules     []map[string]json.RawMessage `json:"rules"`
		Truncated bool                         `json:"truncated"`
	}
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	if body.SetCount != 1 || len(body.Sets) != 1 || string(body.Sets[0].After) != "null" ||
		len(body.Sets[0].Before) < 10 || body.RuleCount != 4 || !body.Truncated || len(body.Rules) != 3 {
		t.Fatalf("%s", encoded)
	}
	added, removed, moved := body.Rules[0], body.Rules[1], body.Rules[2]
	if string(moved["cluster_before_id"]) != `"`+cluster.String()+`"` ||
		string(moved["cluster_id"]) != `"`+other.String()+`"` || string(moved["access_after"]) != `{"full":true}` ||
		string(moved["change"]) != `"changed"` {
		t.Errorf("moved: %s", encoded)
	}
	for key, want := range map[string]string{
		"access_before": "null", "access_after": `{"full":true}`, "groups_before": "[]",
		"groups_after": `["view"]`, "cluster_before_id": "null", "source_before": "null",
	} {
		if string(added[key]) != want {
			t.Errorf("added %s = %s, want %s", key, added[key], want)
		}
	}
	var before simulatedKubernetesAccess
	if err := json.Unmarshal(removed["access_before"], &before); err != nil || before.SetName != "developer" ||
		before.Mode != "report" || before.ReportUntil == nil || len(before.ContentHash) != 64 ||
		string(removed["access_after"]) != "null" || string(removed["cluster_before_id"]) != "null" {
		t.Fatalf("removed: %s", encoded)
	}
}

func mustRuleIDForTest(t *testing.T, value string) policy.RuleID {
	t.Helper()
	id, err := policy.ParseRuleID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
