package postgres

import (
	"slices"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
)

// A groups read decodes only as the release it names: each rule once, from
// a known source to a cluster, with groups a cluster rule may hold, and
// hashed only when some rule names groups.
func TestDecodePolicyKubernetesGroups(t *testing.T) {
	t.Parallel()
	const rule = `{"id":"01890f00-0000-7000-8000-000000000801","cluster_id":"01890f00-0000-7000-8000-000000000f01",` +
		`"source_kind":"device_group","source_id":"01890f00-0000-7000-8000-000000000a01","groups":%s}`
	with := func(groups string) string { return strings.Replace(rule, "%s", groups, 1) }
	read, valid := decodePolicyKubernetesGroups([]byte(`{"policy_revision":4,"hashed":true,"rules":[`+
		with(`["edit","view"]`)+`]}`), 4)
	id, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000801")
	if !valid || !read.hashed || !slices.Equal(read.groups[id], []string{"edit", "view"}) ||
		read.sources[id].Kind() != publication.SideDeviceGroup || !read.clusters[id].IsValid() {
		t.Fatalf("decode = %+v, %t", read, valid)
	}
	legacy, valid := decodePolicyKubernetesGroups([]byte(`{"policy_revision":4,"hashed":false,"rules":[`+
		with(`null`)+`]}`), 4)
	if !valid || legacy.groups[id] != nil {
		t.Fatalf("legacy = %+v, %t", legacy, valid)
	}
	for name, document := range map[string]string{
		"another revision":  `{"policy_revision":3,"hashed":false,"rules":[]}`,
		"no rules":          `{"policy_revision":4,"hashed":false}`,
		"hashed, no groups": `{"policy_revision":4,"hashed":true,"rules":[` + with(`null`) + `]}`,
		"twice":             `{"policy_revision":4,"hashed":false,"rules":[` + with(`null`) + `,` + with(`null`) + `]}`,
		"unsorted":          `{"policy_revision":4,"hashed":true,"rules":[` + with(`["view","edit"]`) + `]}`,
		"empty groups":      `{"policy_revision":4,"hashed":false,"rules":[` + with(`[]`) + `]}`,
		"unknown source": `{"policy_revision":4,"hashed":false,"rules":[` +
			strings.Replace(with(`null`), "device_group", "site", 1) + `]}`,
		"no cluster": `{"policy_revision":4,"hashed":false,"rules":[` +
			strings.Replace(with(`null`), "01890f00-0000-7000-8000-000000000f01", "", 1) + `]}`,
	} {
		if _, valid := decodePolicyKubernetesGroups([]byte(document), 4); valid {
			t.Errorf("%s decoded", name)
		}
	}
}
