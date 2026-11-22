package rbaccheck

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"meshtransit.net/shared/kubeprofile"
)

// namedRight is a right a rule may give over named objects, which an access
// review without a name never matches (TD-CLI-84): in a guarded namespace,
// running code in or reading a static pod (etcd-<node>), a Secret, a
// DaemonSet such as kube-proxy, EKS's aws-auth ConfigMap, or changing the
// namespace's RBAC; anywhere, the cluster-scoped rights dangerousRights asks
// about without a name (a ClusterRoleBinding's rules show in every
// namespace's rules review). So the rules themselves are read.
type namedRight struct {
	group, resource string
	verbs           []string
}

var namedRights = func() []namedRight {
	writes := []string{"create", "update", "patch", "delete"}
	rights := []namedRight{
		{"", "pods/exec", []string{"get", "create"}},
		{"", "pods/attach", []string{"get", "create"}},
		{"", "pods/portforward", []string{"get", "create"}},
		{"", "pods", []string{"update", "patch"}},
		{"", "pods/ephemeralcontainers", []string{"update", "patch"}},
		{"", "secrets", []string{"get", "list", "watch"}},
		{"", "serviceaccounts/token", []string{"create"}},
		{"", "configmaps", []string{"update", "patch"}},
		{"apps", "deployments", []string{"update", "patch"}},
		{"apps", "replicasets", []string{"update", "patch"}},
		{"apps", "statefulsets", []string{"update", "patch"}},
		{"apps", "daemonsets", []string{"update", "patch"}},
		{"apps", "controllerrevisions", []string{"update", "patch"}},
		{"batch", "jobs", []string{"update", "patch"}},
		{"batch", "cronjobs", []string{"update", "patch"}},
		{"", "replicationcontrollers", []string{"update", "patch"}},
		{rbac, "roles", []string{"create", "update", "patch", "bind", "escalate"}},
		{rbac, "rolebindings", []string{"create", "update", "patch"}},
		{rbac, "clusterroles", []string{"create", "update", "patch", "bind", "escalate"}},
		{rbac, "clusterrolebindings", []string{"create", "update", "patch"}},
		{"", "nodes/proxy", append([]string{"get"}, writes...)},
		{"", "nodes", []string{"update", "patch"}},
		{"", "nodes/status", []string{"update", "patch"}},
		{certificates, "certificatesigningrequests/approval", []string{"update"}},
		{certificates, "signers", []string{"approve"}},
		{"", "users", []string{"impersonate"}},
		{"", "groups", []string{"impersonate"}},
		{"", "serviceaccounts", []string{"impersonate"}},
		{"authentication.k8s.io", "uids", []string{"impersonate"}},
	}
	for _, kind := range [][2]string{
		{admission, "validatingwebhookconfigurations"},
		{admission, "mutatingwebhookconfigurations"},
		{admission, "validatingadmissionpolicies"},
		{admission, "validatingadmissionpolicybindings"},
		{admission, "mutatingadmissionpolicies"},
		{admission, "mutatingadmissionpolicybindings"},
		{"apiregistration.k8s.io", "apiservices"},
		{"apiextensions.k8s.io", "customresourcedefinitions"},
		{flowControl, "flowschemas"},
		{flowControl, "prioritylevelconfigurations"},
	} {
		rights = append(rights, namedRight{kind[0], kind[1], writes})
	}
	return rights
}()

// grants reports the first verb of right a rule allows, if any, by RBAC's
// own matching: a resource is "*", exact, or "*/<subresource>".
func (right namedRight) grants(rule kubeprofile.Rule) (string, bool) {
	if !slices.Contains(rule.APIGroups, right.group) && !slices.Contains(rule.APIGroups, "*") {
		return "", false
	}
	_, sub, _ := strings.Cut(right.resource, "/")
	resource := slices.ContainsFunc(rule.Resources, func(name string) bool {
		return name == "*" || name == right.resource || (sub != "" && name == "*/"+sub)
	})
	if !resource {
		return "", false
	}
	for _, verb := range right.verbs {
		if slices.Contains(rule.Verbs, verb) || slices.Contains(rule.Verbs, "*") {
			return verb, true
		}
	}
	return "", false
}

// maxReasonName bounds a name shown in a reason (users see it).
const maxReasonName = 63

// describe names what a rule gives: the right and, when the rule names
// objects, the first (printable, bounded) and how many more.
func (right namedRight) describe(verb string, names []string) string {
	text := verb + " " + right.resource
	if right.group != "" {
		text = verb + " " + right.group + "/" + right.resource
	}
	if len(names) == 0 {
		return text
	}
	name := strings.Map(func(r rune) rune {
		if r < 0x21 || r > 0x7e {
			return '?'
		}
		return r
	}, names[0])
	if len(name) > maxReasonName {
		name = name[:maxReasonName] + "..."
	}
	text += " " + name
	if len(names) > 1 {
		text += " and " + strconv.Itoa(len(names)-1) + " more"
	}
	return text
}

// heldByName reads the group's rules in each guarded namespace and returns
// (and the gateway's own) the first right of namedRights they grant, as a
// reason, or "". incomplete names the namespaces whose answer the API server
// called incomplete (a webhook authorizer, or a binding to a missing role):
// there a right by name is not proven absent. A token the API
// server refuses is forgotten and replaced once.
func (checker *Checker) heldByName(ctx context.Context, group string, token *string) (
	reason string, incomplete []string, err error,
) {
	replaced := false
	namespaces := checker.at.guarded
	if !slices.Contains(namespaces, checker.at.namespace) {
		namespaces = append(slices.Clip(namespaces), checker.at.namespace)
	}
	for _, namespace := range namespaces {
		answer, err := checker.options.Reviewer.RulesReview(ctx, *token, namespace)
		if errors.Is(err, ErrUnauthorized) && !replaced {
			replaced = true
			checker.options.Tokens.Forget(group, *token)
			if *token, err = checker.options.Tokens.Token(ctx, group); err != nil {
				return "", nil, fmt.Errorf("rules review in %s: %w", namespace, err)
			}
			answer, err = checker.options.Reviewer.RulesReview(ctx, *token, namespace)
		}
		if err != nil {
			return "", nil, fmt.Errorf("rules review in %s: %w", namespace, err)
		}
		for _, rule := range answer.Rules {
			for _, right := range namedRights {
				if verb, ok := right.grants(rule); ok {
					return right.describe(verb, rule.ResourceNames) + " in " + namespace, nil, nil
				}
			}
		}
		if answer.Incomplete {
			incomplete = append(incomplete, namespace)
		}
	}
	return "", incomplete, nil
}
