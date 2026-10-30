package postgres

import (
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/shared/kubeprofile"
)

// An access read decodes only as the release it names: each rule once, from
// a known source to a cluster, with groups a cluster rule may hold, and
// hashed only when some rule names groups.
func TestDecodePolicyKubernetesGroups(t *testing.T) {
	t.Parallel()
	const rule = `{"id":"01890f00-0000-7000-8000-000000000801","cluster_id":"01890f00-0000-7000-8000-000000000f01",` +
		`"source_kind":"device_group","source_id":"01890f00-0000-7000-8000-000000000a01","groups":%s}`
	with := func(groups string) string { return strings.Replace(rule, "%s", groups, 1) }
	document := func(hashed bool, rules ...string) string {
		encoded, _ := json.Marshal(hashed)
		return `{"policy_revision":4,"groups_hashed":` + string(encoded) + `,"profiles_hashed":false,"rules":[` +
			strings.Join(rules, ",") + `],"profiles":[]}`
	}
	read, valid := decodePolicyKubernetesGroups([]byte(document(true, with(`["edit","view"]`))), 4)
	id, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000801")
	if !valid || !read.hashed || !slices.Equal(read.groups[id], []string{"edit", "view"}) ||
		read.sources[id].Kind() != publication.SideDeviceGroup || !read.clusters[id].IsValid() ||
		!read.access[id].IsZero() {
		t.Fatalf("decode = %+v, %t", read, valid)
	}
	legacy, valid := decodePolicyKubernetesGroups([]byte(document(false, with(`null`))), 4)
	if !valid || legacy.groups[id] != nil {
		t.Fatalf("legacy = %+v, %t", legacy, valid)
	}
	for name, encoded := range map[string]string{
		"another revision":  strings.Replace(document(false), `"policy_revision":4`, `"policy_revision":3`, 1),
		"no rules":          `{"policy_revision":4,"groups_hashed":false,"profiles":[]}`,
		"no profiles":       `{"policy_revision":4,"groups_hashed":false,"rules":[]}`,
		"hashed, no groups": document(true, with(`null`)),
		"twice":             document(false, with(`null`), with(`null`)),
		"unsorted":          document(true, with(`["view","edit"]`)),
		"empty groups":      document(false, with(`[]`)),
		"unknown source":    document(false, strings.Replace(with(`null`), "device_group", "site", 1)),
		"no cluster": document(false, strings.Replace(with(`null`),
			"01890f00-0000-7000-8000-000000000f01", "", 1)),
	} {
		if _, valid := decodePolicyKubernetesGroups([]byte(encoded), 4); valid {
			t.Errorf("%s decoded", name)
		}
	}
}

// A rule's profile decodes only as a profile of the release, with groups,
// and a stored profile only under its own content hash (K2).
func TestDecodePolicyKubernetesProfiles(t *testing.T) {
	t.Parallel()
	profile := kubeprofile.Profile{Name: "developer", Namespaced: []kubeprofile.Rule{
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}}
	hash, err := kubeprofile.ContentHash(profile)
	if err != nil {
		t.Fatal(err)
	}
	hashText := hex.EncodeToString(hash[:])
	const profileID = "01890f00-0000-7000-8000-000000000c01"
	stored := `{"id":"` + profileID + `","hash":"` + hashText + `","name":"developer",` +
		`"rules":{"namespaced":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]},"description":"pods"}`
	ruleWith := func(groups, access string) string {
		return `{"id":"01890f00-0000-7000-8000-000000000801","cluster_id":"01890f00-0000-7000-8000-000000000f01",` +
			`"source_kind":"device_group","source_id":"01890f00-0000-7000-8000-000000000a01","groups":` + groups +
			`,"profile":` + access + `}`
	}
	enforce := `{"id":"` + profileID + `","hash":"` + hashText + `","namespaces":["team-a"],"cluster_part":false,` +
		`"mode":"enforce","report_until_ms":null}`
	report := strings.Replace(strings.Replace(enforce, `"enforce"`, `"report"`, 1), `null`, `1800000000000`, 1)
	document := func(profilesHashed bool, rule, profiles string) string {
		hashed := "false"
		if profilesHashed {
			hashed = "true"
		}
		return `{"policy_revision":4,"groups_hashed":true,"profiles_hashed":` + hashed + `,"rules":[` + rule +
			`],"profiles":[` + profiles + `]}`
	}
	id, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000801")
	read, valid := decodePolicyKubernetesGroups([]byte(document(true, ruleWith(`["view"]`, enforce), stored)), 4)
	if !valid || !read.profilesHashed || read.access[id].ProfileHash() != hash || len(read.profiles) != 1 ||
		read.profiles[0].Description() != "pods" {
		t.Fatalf("decode = %+v, %t", read, valid)
	}
	carried, valid := decodePolicyKubernetesGroups([]byte(document(false, ruleWith(`["view"]`, report), stored)), 4)
	if !valid || carried.profilesHashed || !carried.access[id].Report() ||
		carried.access[id].ReportUntil().UnixMilli() != 1_800_000_000_000 {
		t.Fatalf("carried = %+v, %t", carried, valid)
	}
	unused, valid := decodePolicyKubernetesGroups([]byte(document(false, ruleWith(`["view"]`, `null`), stored)), 4)
	if !valid || !unused.access[id].IsZero() || len(unused.profiles) != 1 {
		t.Fatalf("unused = %+v, %t", unused, valid)
	}
	otherContent := strings.Replace(stored, `"verbs":["get"]`, `"verbs":["get","list"]`, 1)
	for name, encoded := range map[string]string{
		"profiles hashed, none applied": document(true, ruleWith(`["view"]`, `null`), stored),
		"a profile without groups":      document(false, ruleWith(`null`, enforce), stored),
		"a profile the release lacks":   document(false, ruleWith(`["view"]`, enforce), ""),
		"content under another hash":    document(false, ruleWith(`["view"]`, `null`), otherContent),
		"a profile twice":               document(false, ruleWith(`["view"]`, `null`), stored+","+stored),
		"report without deadline": document(false, ruleWith(`["view"]`,
			strings.Replace(enforce, `"enforce"`, `"report"`, 1)), stored),
		"enforce with deadline": document(false, ruleWith(`["view"]`,
			strings.Replace(enforce, `null`, `1800000000000`, 1)), stored),
		"unknown mode": document(false, ruleWith(`["view"]`,
			strings.Replace(enforce, `"enforce"`, `"audit"`, 1)), stored),
	} {
		if _, valid := decodePolicyKubernetesGroups([]byte(encoded), 4); valid {
			t.Errorf("%s decoded", name)
		}
	}
}

// A profile stored by the publish payload reads back under its own hash
// (review d2 M3): the rules column round-trips through JSON as the database
// keeps it.
func TestKubernetesProfilePayloadReadsBack(t *testing.T) {
	t.Parallel()
	id, err := publication.ParseKubernetesProfileID("01890f00-0000-7000-8000-000000000c01")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := publication.NewKubernetesProfile(publication.KubernetesProfileParams{ID: id,
		Description: "deploy, logs", Profile: kubeprofile.Profile{Name: "developer",
			Namespaced: []kubeprofile.Rule{{APIGroups: []string{"", "apps"}, Resources: []string{"pods/log", "deployments"},
				Verbs: []string{"get", "patch"}, ResourceNames: []string{"web"}}},
			Cluster: []kubeprofile.Rule{{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}},
				{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"list"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := json.Marshal(newPolicyKubernetesProfilePayload(profile))
	if err != nil {
		t.Fatal(err)
	}
	// The read names the columns differently; the rules object is the same.
	var columns map[string]json.RawMessage
	if err := json.Unmarshal(stored, &columns); err != nil {
		t.Fatal(err)
	}
	read, err := json.Marshal(map[string]json.RawMessage{"id": columns["profile_public_id"],
		"hash": columns["content_hash"], "name": columns["name"], "rules": columns["rules"],
		"description": columns["description"]})
	if err != nil {
		t.Fatal(err)
	}
	var wire policyKubernetesProfileWire
	if err := json.Unmarshal(read, &wire); err != nil {
		t.Fatal(err)
	}
	decoded, valid := decodePolicyKubernetesProfile(wire)
	if !valid || decoded.ContentHash() != profile.ContentHash() || decoded.Description() != "deploy, logs" {
		t.Fatalf("read back = %+v, %t", decoded, valid)
	}
}
