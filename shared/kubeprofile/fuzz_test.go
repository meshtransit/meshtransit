package kubeprofile

import (
	"encoding/json"
	"testing"
)

// A profile from anywhere either fails Validate or normalizes to a fixed
// point with one hash, and never panics.
func FuzzProfile(f *testing.F) {
	seed, _ := json.Marshal(developer())
	f.Add(seed)
	f.Add([]byte(`{"name":"x","namespaced":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]}`))
	f.Add([]byte(`{"name":"x","cluster":[{"nonResourceURLs":["/a*"],"verbs":["get"]}]}`))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		var profile Profile
		if json.Unmarshal(encoded, &profile) != nil {
			return
		}
		if Validate(profile) != nil {
			if _, err := ContentHash(profile); err == nil {
				t.Fatal("an invalid profile hashed")
			}
			return
		}
		normalized := Normalize(profile)
		if !equalProfiles(Normalize(normalized), normalized) {
			t.Fatal("Normalize is not idempotent")
		}
		first, err := ContentHash(profile)
		if err != nil {
			t.Fatal(err)
		}
		second, err := ContentHash(normalized)
		if err != nil || first != second {
			t.Fatal("normalizing changed the hash")
		}
	})
}

// More namespaces never take a right away, nor does turning the cluster
// part on.
func FuzzScopeMonotone(f *testing.F) {
	f.Add("get", "", "pods", "", "team-a", "x", "/metrics", true, false, false, uint8(2))
	f.Add("create", "", "pods", "exec", "team-a", "", "", true, true, false, uint8(2))
	f.Add("patch", "", "namespaces", "", "team-a", "team-a", "", true, false, true, uint8(1))
	f.Fuzz(func(t *testing.T, verb, group, resource, subresource, namespace, name, path string,
		resourceRequest, upgrade, mayCreate bool, scope uint8) {
		attributes := Attributes{ResourceRequest: resourceRequest, Verb: verb, APIGroup: group,
			Resource: resource, Subresource: subresource, Namespace: namespace, Name: name, Path: path,
			Upgrade: upgrade, MayCreate: mayCreate, Scope: ResourceScope(scope % 3)}
		wide := Profile{Name: "wide",
			Namespaced: []Rule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
			Cluster: []Rule{
				{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
				{NonResourceURLs: []string{"*"}, Verbs: []string{"*"}},
			}}
		for _, profile := range []Profile{developer(), wide} {
			narrow := mustScope(t, profile, []string{"team-a"}, false)
			wider := mustScope(t, profile, []string{"team-a", "team-b"}, false)
			every := mustScope(t, profile, []string{"*"}, false)
			withCluster := mustScope(t, profile, []string{"team-a"}, true)
			if narrow.Allows(attributes) && (!wider.Allows(attributes) || !every.Allows(attributes) ||
				!withCluster.Allows(attributes)) {
				t.Fatalf("%s: a wider scope refused %+v", profile.Name, attributes)
			}
			if narrow.Allows(attributes) != AllowsAny([]Grant{{Scope: narrow}}, attributes) {
				t.Fatal("AllowsAny of one grant differs from the grant")
			}
		}
	})
}

func mustScope(t *testing.T, profile Profile, namespaces []string, clusterPart bool) Scope {
	t.Helper()
	scope, err := NewScope(profile, namespaces, clusterPart)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

// A scope is never wider than RBAC: whatever it allows, the rule allows as
// the RBAC authorizer reads it, and create too where S1 and S3 ask for it
// (review K2a M5). The rule itself is fuzzed.
func FuzzStricterThanRBAC(f *testing.F) {
	f.Add("", "pods/exec", "*", "", "", "get", "", "pods", "exec", "team-a", "", "", true, false, uint8(2), true, false)
	f.Add("*", "*", "*", "", "", "delete", "", "namespaces", "", "team-a", "team-a", "", false, false, uint8(1), true, true)
	f.Add("", "", "get", "", "/metrics", "get", "", "", "", "", "", "/metrics", false, false, uint8(0), true, false)
	f.Fuzz(func(t *testing.T, ruleGroup, ruleResource, ruleVerb, ruleName, ruleURL, verb, group, resource,
		subresource, namespace, name, path string, upgrade, mayCreate bool, scope uint8, clusterPart, everywhere bool) {
		rule := Rule{Verbs: []string{ruleVerb}}
		if ruleURL != "" {
			rule.NonResourceURLs = []string{ruleURL}
		} else {
			rule.APIGroups, rule.Resources = []string{ruleGroup}, []string{ruleResource}
			if ruleName != "" {
				rule.ResourceNames = []string{ruleName}
			}
		}
		profile := Profile{Name: "fuzz", Cluster: []Rule{rule}}
		if ruleURL == "" {
			profile.Namespaced = []Rule{rule}
		}
		namespaces := []string{"team-a"}
		if everywhere {
			namespaces = []string{"*"}
		}
		granted, err := NewScope(profile, namespaces, clusterPart)
		if err != nil {
			return
		}
		attributes := Attributes{ResourceRequest: path == "", Verb: verb, APIGroup: group, Resource: resource,
			Subresource: subresource, Namespace: namespace, Name: name, Path: path, Upgrade: upgrade,
			MayCreate: mayCreate, Scope: ResourceScope(scope % 4)}
		if !granted.Allows(attributes) {
			return
		}
		if !ruleAllows(&rule, attributes) {
			t.Fatalf("allowed %+v that RBAC refuses under %+v", attributes, rule)
		}
		created := attributes
		created.Verb = "create"
		if attributes.ResourceRequest && (interactive[attributes.Subresource] ||
			attributes.MayCreate && attributes.Subresource == "") && !ruleAllows(&rule, created) {
			t.Fatalf("allowed %+v without create under %+v", attributes, rule)
		}
		if attributes.ResourceRequest && attributes.Namespace != "" && !everywhere &&
			attributes.Namespace != "team-a" && attributes.Scope == ScopeNamespaced {
			t.Fatalf("allowed namespace %q", attributes.Namespace)
		}
	})
}
