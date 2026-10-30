package kubeprofile

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Normalizing sorts and drops duplicates without touching its input, and
// the same rights in another order hash alike (K2 §7.1).
func TestNormalizeAndHash(t *testing.T) {
	t.Parallel()
	shuffled := Profile{Name: "developer",
		Namespaced: []Rule{
			{APIGroups: []string{"batch", "", "apps", "apps"}, Resources: []string{"jobs", "pods", "deployments"},
				Verbs: []string{"list", "get", "get"}},
			{APIGroups: []string{""}, Resources: []string{"pods/log"}, Verbs: []string{"get"}},
			{APIGroups: []string{""}, Resources: []string{"pods/log"}, Verbs: []string{"get"}},
		},
		Cluster: []Rule{{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}}},
	}
	original := cloneProfile(shuffled)
	normalized := Normalize(shuffled)
	if !equalProfiles(shuffled, original) {
		t.Fatal("Normalize changed its input")
	}
	if len(normalized.Namespaced) != 2 ||
		!slices.Equal(normalized.Namespaced[0].APIGroups, []string{"", "apps", "batch"}) ||
		!slices.Equal(normalized.Namespaced[0].Verbs, []string{"get", "list"}) {
		t.Fatalf("normalized %+v", normalized.Namespaced)
	}
	if !equalProfiles(Normalize(normalized), normalized) {
		t.Fatal("Normalize is not idempotent")
	}
	reordered := Profile{Name: "developer",
		Namespaced: []Rule{
			{APIGroups: []string{""}, Resources: []string{"pods/log"}, Verbs: []string{"get"}},
			{APIGroups: []string{"apps", "", "batch"}, Resources: []string{"deployments", "pods", "jobs"},
				Verbs: []string{"get", "list"}},
		},
		Cluster: []Rule{{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}}},
	}
	first, err := ContentHash(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ContentHash(reordered)
	if err != nil || first != second {
		t.Fatalf("same rights hash differently: %x %x %v", first, second, err)
	}
	// The name is part of what a release pins (re-review v2 H3); the part a
	// rule sits in is too.
	renamed := cloneProfile(reordered)
	renamed.Name = "developer-2"
	moved := Profile{Name: "developer", Namespaced: reordered.Namespaced,
		Cluster: []Rule{{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}}},
	}
	moved.Namespaced = moved.Namespaced[:1]
	moved.Cluster = append(moved.Cluster, Rule{APIGroups: []string{"apps", "", "batch"},
		Resources: []string{"deployments", "pods", "jobs"}, Verbs: []string{"get", "list"}})
	for name, other := range map[string]Profile{"renamed": renamed, "moved": moved} {
		hash, err := ContentHash(other)
		if err != nil || hash == first {
			t.Errorf("%s: hash %x (err %v) equals the original's", name, hash, err)
		}
	}
	if _, err := ContentHash(Profile{Name: "x"}); err == nil {
		t.Error("an empty profile hashed")
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()
	valid := developer()
	if err := Validate(valid); err != nil {
		t.Fatalf("developer: %v", err)
	}
	many := func(count int, value func(int) string) []string {
		values := make([]string, count)
		for index := range values {
			values[index] = value(index)
		}
		return values
	}
	letters := func(index int) string { return "r" + strings.Repeat("a", index%60) + string(rune('a'+index/60)) }
	rules := func(count int) []Rule {
		out := make([]Rule, count)
		for index := range out {
			out[index] = Rule{APIGroups: []string{""}, Resources: []string{letters(index)}, Verbs: []string{"get"}}
		}
		return out
	}
	for name, profile := range map[string]Profile{
		"no name":             {Namespaced: valid.Namespaced},
		"bad name":            {Name: "Developer", Namespaced: valid.Namespaced},
		"no rules":            {Name: "empty"},
		"65 namespaced":       {Name: "big", Namespaced: rules(65)},
		"65 cluster":          {Name: "big", Cluster: rules(65)},
		"no verbs":            {Name: "x", Namespaced: []Rule{{APIGroups: []string{""}, Resources: []string{"pods"}}}},
		"upper verb":          {Name: "x", Namespaced: []Rule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"Get"}}}},
		"no groups":           {Name: "x", Namespaced: []Rule{{Resources: []string{"pods"}, Verbs: []string{"get"}}}},
		"no resources":        {Name: "x", Namespaced: []Rule{{APIGroups: []string{""}, Verbs: []string{"get"}}}},
		"bad group":           {Name: "x", Namespaced: []Rule{{APIGroups: []string{"Apps"}, Resources: []string{"pods"}, Verbs: []string{"get"}}}},
		"bad resource":        {Name: "x", Namespaced: []Rule{{APIGroups: []string{""}, Resources: []string{"Pods"}, Verbs: []string{"get"}}}},
		"resource slash star": {Name: "x", Namespaced: []Rule{{APIGroups: []string{""}, Resources: []string{"pods/*"}, Verbs: []string{"get"}}}},
		"three segments":      {Name: "x", Namespaced: []Rule{{APIGroups: []string{""}, Resources: []string{"a/b/c"}, Verbs: []string{"get"}}}},
		"path in namespaced":  {Name: "x", Namespaced: []Rule{{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}}}},
		"path with resources": {Name: "x", Cluster: []Rule{{APIGroups: []string{""}, Resources: []string{"nodes"},
			NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}}}},
		"path with names":   {Name: "x", Cluster: []Rule{{ResourceNames: []string{"a"}, NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}}}},
		"relative path":     {Name: "x", Cluster: []Rule{{NonResourceURLs: []string{"metrics"}, Verbs: []string{"get"}}}},
		"inner star":        {Name: "x", Cluster: []Rule{{NonResourceURLs: []string{"/a*/b"}, Verbs: []string{"get"}}}},
		"escaped path":      {Name: "x", Cluster: []Rule{{NonResourceURLs: []string{"/a%2Fb"}, Verbs: []string{"get"}}}},
		"empty name":        {Name: "x", Namespaced: []Rule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}, ResourceNames: []string{""}}}},
		"slash in name":     {Name: "x", Namespaced: []Rule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}, ResourceNames: []string{"a/b"}}}},
		"33 verbs":          {Name: "x", Namespaced: []Rule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: many(33, letters)}}},
		"33 resource names": {Name: "x", Namespaced: []Rule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}, ResourceNames: many(33, letters)}}},
		"too large": {Name: "x", Namespaced: func() []Rule {
			out := rules(64)
			for index := range out {
				out[index].ResourceNames = many(32, func(name int) string { return strings.Repeat("n", 200) + letters(name) })
			}
			return out
		}()},
	} {
		if err := Validate(profile); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Validate = %v, want ErrInvalid", name, err)
		}
	}
	for name, profile := range map[string]Profile{
		"64 rules":     {Name: "big", Namespaced: rules(64)},
		"star forms":   {Name: "x", Namespaced: []Rule{{APIGroups: []string{"*"}, Resources: []string{"*", "*/scale"}, Verbs: []string{"*"}}}},
		"custom verb":  {Name: "x", Cluster: []Rule{{APIGroups: []string{"policy"}, Resources: []string{"podsecuritypolicies"}, Verbs: []string{"use"}}}},
		"system name":  {Name: "x", Cluster: []Rule{{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"}, Verbs: []string{"get"}, ResourceNames: []string{"system:aggregate-to-view"}}}},
		"path prefix":  {Name: "x", Cluster: []Rule{{NonResourceURLs: []string{"/logs/*", "*"}, Verbs: []string{"get"}}}},
		"cluster only": {Name: "x", Cluster: []Rule{{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"get"}}}},
		"dotted group": {Name: "x", Namespaced: []Rule{{APIGroups: []string{"subresources.kubevirt.io"}, Resources: []string{"virtualmachineinstances/console"}, Verbs: []string{"get"}}}},
	} {
		if err := Validate(profile); err != nil {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
}

func TestNewScopeNamespaces(t *testing.T) {
	t.Parallel()
	for name, namespaces := range map[string][]string{
		"none":       nil,
		"empty name": {""},
		"upper":      {"Team-a"},
		"star mixed": {"*", "team-a"},
		"too long":   {strings.Repeat("a", 64)},
		"65 names": func() []string {
			out := make([]string, 65)
			for index := range out {
				out[index] = "ns-" + strings.Repeat("a", index%40) + string(rune('a'+index/40))
			}
			return out
		}(),
	} {
		if _, err := NewScope(developer(), namespaces, false); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: NewScope = %v, want ErrInvalid", name, err)
		}
	}
	if _, err := NewScope(Profile{Name: "x"}, []string{"team-a"}, false); !errors.Is(err, ErrInvalid) {
		t.Error("an invalid profile made a scope")
	}
	scope, err := NewScope(developer(), []string{"team-b", "team-a", "team-a"}, false)
	if err != nil || !slices.Equal(scope.Namespaces(), []string{"team-a", "team-b"}) {
		t.Fatalf("namespaces %v, err %v", scope.Namespaces(), err)
	}
	// What the scope keeps is its own: changing the caller's profile later
	// changes nothing.
	profile := developer()
	scope, err = NewScope(profile, []string{"team-a"}, false)
	if err != nil {
		t.Fatal(err)
	}
	profile.Namespaced[0].Resources[0] = "secrets"
	if scope.Allows(inNamespace("get", "", "secrets", "", "team-a")) {
		t.Error("the scope shares the caller's slices")
	}
}

func cloneProfile(profile Profile) Profile {
	return Profile{Name: profile.Name, Namespaced: cloneRules(profile.Namespaced), Cluster: cloneRules(profile.Cluster)}
}

func equalProfiles(left, right Profile) bool {
	equalRules := func(a, b []Rule) bool {
		return slices.EqualFunc(a, b, func(x, y Rule) bool {
			return slices.Equal(x.APIGroups, y.APIGroups) && slices.Equal(x.Resources, y.Resources) &&
				slices.Equal(x.Verbs, y.Verbs) && slices.Equal(x.ResourceNames, y.ResourceNames) &&
				slices.Equal(x.NonResourceURLs, y.NonResourceURLs)
		})
	}
	return left.Name == right.Name && equalRules(left.Namespaced, right.Namespaced) &&
		equalRules(left.Cluster, right.Cluster)
}

func cloneRules(rules []Rule) []Rule {
	if rules == nil {
		return nil
	}
	out := make([]Rule, len(rules))
	for index, rule := range rules {
		out[index] = Rule{APIGroups: slices.Clone(rule.APIGroups), Resources: slices.Clone(rule.Resources),
			Verbs: slices.Clone(rule.Verbs), ResourceNames: slices.Clone(rule.ResourceNames),
			NonResourceURLs: slices.Clone(rule.NonResourceURLs)}
	}
	return out
}

// Releases pin this hash: the encoding, the field order and the domain must
// never change silently (review K2a M3).
func TestContentHashKnownAnswer(t *testing.T) {
	t.Parallel()
	const wantBytes = `{"format":1,"name":"developer","namespaced":[{"apiGroups":["","apps","batch"],` +
		`"resources":["configmaps","deployments","jobs","pods","pods/log","replicasets"],` +
		`"verbs":["create","delete","get","list","patch","update","watch"]}],"cluster":[{"apiGroups":[""],` +
		`"resources":["namespaces","nodes"],"verbs":["get","list","watch"]},{"verbs":["get"],` +
		`"nonResourceURLs":["/metrics"]}]}`
	encoded, err := canonical(developer())
	if err != nil || string(encoded) != wantBytes {
		t.Fatalf("canonical = %s (%v)", encoded, err)
	}
	hash, err := ContentHash(developer())
	if err != nil || fmt.Sprintf("%x", hash) != "53380bea5c74774644eba2d5af3c5bb7e7455238f188ba121c49e62f896eed78" {
		t.Fatalf("ContentHash = %x (%v)", hash, err)
	}
}

// Duplicates count against the bounds before they are dropped (review K2a M2).
func TestValidateCountsRawInput(t *testing.T) {
	t.Parallel()
	rule := Rule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}
	repeated := make([]Rule, maximumRules+1)
	for index := range repeated {
		repeated[index] = rule
	}
	verbs := make([]string, maximumElements+1)
	for index := range verbs {
		verbs[index] = "get"
	}
	for name, profile := range map[string]Profile{
		"65 equal rules": {Name: "x", Namespaced: repeated},
		"33 equal verbs": {Name: "x", Namespaced: []Rule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: verbs}}},
	} {
		if err := Validate(profile); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: Validate = %v, want ErrInvalid", name, err)
		}
	}
}
