// The cases are RBAC's own semantics, which the port in rbac.go answers
// exactly (k8s.io/kubernetes@v1.35.1 RuleAllows and evaluation_helpers.go).
package kubeprofile

import "testing"

func TestRuleAllowsResourceRequests(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		rule       Rule
		attributes Attributes
		want       bool
	}{
		"star verb": {
			Rule{Verbs: []string{"*"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			resourceAttributes("get", "", "pods", ""), true},
		"exact verb": {
			Rule{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			resourceAttributes("list", "", "pods", ""), true},
		"other verb": {
			Rule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			resourceAttributes("delete", "", "pods", ""), false},
		"star group": {
			Rule{Verbs: []string{"get"}, APIGroups: []string{"*"}, Resources: []string{"deployments"}},
			resourceAttributes("get", "apps", "deployments", ""), true},
		"other group": {
			Rule{Verbs: []string{"get"}, APIGroups: []string{"extensions"}, Resources: []string{"deployments"}},
			resourceAttributes("get", "apps", "deployments", ""), false},
		"core group is empty": {
			Rule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"deployments"}},
			resourceAttributes("get", "apps", "deployments", ""), false},
		"star resource covers subresources": {
			Rule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"*"}},
			resourceAttributes("get", "", "pods", "log"), true},
		"resource does not cover its subresource": {
			Rule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			resourceAttributes("get", "", "pods", "log"), false},
		"subresource does not cover its resource": {
			Rule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods/log"}},
			resourceAttributes("get", "", "pods", ""), false},
		"exact subresource": {
			Rule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods/log"}},
			resourceAttributes("get", "", "pods", "log"), true},
		"star slash subresource": {
			Rule{Verbs: []string{"update"}, APIGroups: []string{"*"}, Resources: []string{"*/scale"}},
			resourceAttributes("update", "apps", "deployments", "scale"), true},
		"star slash subresource needs a subresource": {
			Rule{Verbs: []string{"update"}, APIGroups: []string{"*"}, Resources: []string{"*/scale"}},
			resourceAttributes("update", "apps", "scale", ""), false},
		"star slash other subresource": {
			Rule{Verbs: []string{"update"}, APIGroups: []string{"*"}, Resources: []string{"*/scale"}},
			resourceAttributes("update", "apps", "deployments", "status"), false},
		"resource slash star is literal": {
			Rule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods/*"}},
			resourceAttributes("get", "", "pods", "log"), false},
		"names allow the named": {
			Rule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"configmaps"},
				ResourceNames: []string{"a", "b"}},
			named(resourceAttributes("get", "", "configmaps", ""), "b"), true},
		"names refuse others": {
			Rule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"configmaps"},
				ResourceNames: []string{"a"}},
			named(resourceAttributes("get", "", "configmaps", ""), "c"), false},
		"names refuse no name": {
			Rule{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"configmaps"},
				ResourceNames: []string{"a"}},
			resourceAttributes("list", "", "configmaps", ""), false},
		"no names allow any": {
			Rule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"configmaps"}},
			named(resourceAttributes("get", "", "configmaps", ""), "anything"), true},
		"a resource rule never answers a path": {
			Rule{Verbs: []string{"get"}, APIGroups: []string{"*"}, Resources: []string{"*"}},
			Attributes{Verb: "get", Path: "/healthz"}, false},
	} {
		if got := ruleAllows(&test.rule, test.attributes); got != test.want {
			t.Errorf("%s: ruleAllows = %v, want %v", name, got, test.want)
		}
	}
}

func TestRuleAllowsNonResourceRequests(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		urls []string
		path string
		want bool
	}{
		"star":             {[]string{"*"}, "/anything", true},
		"exact":            {[]string{"/metrics"}, "/metrics", true},
		"exact refuses":    {[]string{"/metrics"}, "/metrics/cadvisor", false},
		"prefix":           {[]string{"/logs/*"}, "/logs/kube-apiserver.log", true},
		"prefix itself":    {[]string{"/logs/*"}, "/logs/", true},
		"prefix refuses":   {[]string{"/logs/*"}, "/log", false},
		"bare prefix star": {[]string{"/health*"}, "/healthz", true},
	} {
		rule := Rule{Verbs: []string{"get"}, NonResourceURLs: test.urls}
		if got := ruleAllows(&rule, Attributes{Verb: "get", Path: test.path}); got != test.want {
			t.Errorf("%s: ruleAllows = %v, want %v", name, got, test.want)
		}
		post := Attributes{Verb: "post", Path: test.path}
		if ruleAllows(&rule, post) {
			t.Errorf("%s: a get rule allowed post", name)
		}
	}
	resources := Rule{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"},
		NonResourceURLs: nil}
	if ruleAllows(&resources, Attributes{Verb: "get", Path: "/metrics"}) {
		t.Error("a resource rule answered a path")
	}
}

func resourceAttributes(verb, group, resource, subresource string) Attributes {
	return Attributes{ResourceRequest: true, Verb: verb, APIGroup: group, Resource: resource,
		Subresource: subresource, Scope: ScopeNamespaced, Namespace: "team-a"}
}

func named(attributes Attributes, name string) Attributes {
	attributes.Name = name
	return attributes
}
