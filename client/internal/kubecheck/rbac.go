package kubecheck

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
)

// right is a verb on a resource of an API group.
type right struct {
	group, resource, verb string
}

func (wanted right) String() string {
	if wanted.group == "" {
		return wanted.verb + " " + wanted.resource
	}
	return wanted.verb + " " + wanted.group + "/" + wanted.resource
}

// namespaceRights make a subject as good as the gateway in its namespace
// (K1c §2): running code there, reading its Secrets, minting its tokens,
// changing the controllers that make its pods, or granting itself any of
// these (review c2b M2).
var namespaceRights = []right{
	{"", "pods", "create"},
	{"", "pods/exec", "create"},
	{"", "pods/exec", "get"},
	{"", "pods/attach", "create"},
	{"", "pods/attach", "get"},
	{"", "pods/ephemeralcontainers", "update"},
	{"", "pods/ephemeralcontainers", "patch"},
	{"", "secrets", "get"},
	{"", "secrets", "list"},
	{"", "secrets", "watch"},
	{"", "serviceaccounts/token", "create"},
	{"", "serviceaccounts", "impersonate"},
	{"apps", "statefulsets", "create"},
	{"apps", "statefulsets", "update"},
	{"apps", "statefulsets", "patch"},
	{"batch", "jobs", "create"},
	{"batch", "jobs", "update"},
	{"batch", "jobs", "patch"},
	{"rbac.authorization.k8s.io", "rolebindings", "create"},
	{"rbac.authorization.k8s.io", "rolebindings", "update"},
	{"rbac.authorization.k8s.io", "rolebindings", "patch"},
	{"rbac.authorization.k8s.io", "roles", "bind"},
	{"rbac.authorization.k8s.io", "roles", "escalate"},
	{"rbac.authorization.k8s.io", "clusterroles", "bind"},
	{"rbac.authorization.k8s.io", "clusterroles", "escalate"},
}

// clusterRights reach the gateway from anywhere: past admission through
// the kubelet, acting as any account, granting rights across the cluster,
// or switching the gateway's admission policies off. A ClusterRoleBinding
// gives them.
var clusterRights = []right{
	{"", "nodes/proxy", "get"},
	{"", "nodes/proxy", "create"},
	{"", "users", "impersonate"},
	{"", "groups", "impersonate"},
	{"", "serviceaccounts", "impersonate"},
	{"rbac.authorization.k8s.io", "clusterrolebindings", "create"},
	{"rbac.authorization.k8s.io", "clusterrolebindings", "update"},
	{"rbac.authorization.k8s.io", "clusterrolebindings", "patch"},
	{"admissionregistration.k8s.io", "validatingadmissionpolicies", "update"},
	{"admissionregistration.k8s.io", "validatingadmissionpolicies", "patch"},
	{"admissionregistration.k8s.io", "validatingadmissionpolicies", "delete"},
	{"admissionregistration.k8s.io", "validatingadmissionpolicybindings", "update"},
	{"admissionregistration.k8s.io", "validatingadmissionpolicybindings", "patch"},
	{"admissionregistration.k8s.io", "validatingadmissionpolicybindings", "delete"},
}

type policyRule struct {
	APIGroups []string `json:"apiGroups"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

// grants reports whether rule allows wanted, as Kubernetes matches it: a
// resource is "*", its exact name, or "*/<subresource>" for a subresource
// (review c2b M1). A right limited to some names is still reported.
func (rule policyRule) grants(wanted right) bool {
	matches := func(values []string, value string) bool {
		return slices.Contains(values, "*") || slices.Contains(values, value)
	}
	_, sub, found := strings.Cut(wanted.resource, "/")
	resource := slices.ContainsFunc(rule.Resources, func(name string) bool {
		return name == "*" || name == wanted.resource || (found && name == "*/"+sub)
	})
	return matches(rule.APIGroups, wanted.group) && resource && matches(rule.Verbs, wanted.verb)
}

type subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type roleBinding struct {
	Metadata struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	RoleRef struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"roleRef"`
	Subjects []subject `json:"subjects"`
}

// account is a subject as RBAC matches it: a User named
// system:serviceaccount:<namespace>:<name> is that ServiceAccount (review
// c2b H1).
func account(who subject) subject {
	if who.Kind == "User" {
		if rest, ok := strings.CutPrefix(who.Name, "system:serviceaccount:"); ok {
			if namespace, name, ok := strings.Cut(rest, ":"); ok {
				return subject{Kind: "ServiceAccount", Namespace: namespace, Name: name}
			}
		}
	}
	return who
}

// trusted reports a subject Kubernetes itself runs as, or the gateway and
// its check: a fixed list, so broad groups such as system:authenticated
// are always reported.
func (checker Checker) trusted(who subject) bool {
	switch who.Kind {
	case "Group":
		return who.Name == "system:masters" || who.Name == "system:nodes"
	case "User":
		return who.Name == "system:kube-controller-manager" || who.Name == "system:kube-scheduler" ||
			strings.HasPrefix(who.Name, "system:node:")
	case "ServiceAccount":
		return who.Namespace == checker.Config.Namespace &&
			(who.Name == checker.Config.ServiceAccount || who.Name == checker.Config.CheckServiceAccount)
	}
	return false
}

// kubeadmBindings are the bindings kubeadm makes for its admin group and
// for the API server's client to kubelets: their subjects are trusted
// there only, with that role, so the same name bound elsewhere (or on a
// cluster that is not kubeadm's) is still reported (review c4).
var kubeadmBindings = map[string]struct{ role, kind, subject string }{
	"kubeadm:cluster-admins":           {"cluster-admin", "Group", "kubeadm:cluster-admins"},
	"kubeadm:apiserver-kubelet-client": {"system:kubelet-api-admin", "User", "kube-apiserver-kubelet-client"},
}

func kubeadmOwn(binding roleBinding, who subject) bool {
	expected, ok := kubeadmBindings[binding.Metadata.Name]
	return ok && binding.RoleRef.Kind == "ClusterRole" && binding.RoleRef.Name == expected.role &&
		who.Kind == expected.kind && who.Name == expected.subject
}

// rbac warns about subjects as good as the gateway (K1c §2, §8). Bindings
// Kubernetes makes for itself (kubernetes.io/bootstrapping=rbac-defaults)
// are trusted; other kube-system accounts are reported apart. Webhook
// authorizers (EKS access entries, GKE IAM) are not RBAC and not seen.
func (checker Checker) rbac(ctx context.Context, report *Report) {
	const base = "/apis/rbac.authorization.k8s.io/v1/"
	rules := map[string][]policyRule{}
	readRoles := func(kind, path string) bool {
		err := listAll(ctx, checker.API, path, func(raw json.RawMessage) error {
			var item struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
				Rules []policyRule `json:"rules"`
			}
			if err := json.Unmarshal(raw, &item); err != nil {
				return err
			}
			rules[kind+"/"+item.Metadata.Name] = item.Rules
			return nil
		})
		if err != nil {
			checker.unreadable(report, "RBAC", err)
		}
		return err == nil
	}
	if !readRoles("ClusterRole", base+"clusterroles") ||
		!readRoles("Role", checker.path(base+"namespaces/%s/roles", checker.Config.Namespace)) {
		return
	}
	seen := map[string]bool{}
	reportBinding := func(raw json.RawMessage, wanted []right, scope string, cluster bool) error {
		var binding roleBinding
		if err := json.Unmarshal(raw, &binding); err != nil {
			return err
		}
		// Kubernetes' own bindings keep its subjects; one added to them is
		// still reported (review c2b M-c).
		defaults := binding.Metadata.Labels["kubernetes.io/bootstrapping"] == "rbac-defaults"
		held := rules[binding.RoleRef.Kind+"/"+binding.RoleRef.Name]
		var granted []string
		for _, want := range wanted {
			if slices.ContainsFunc(held, func(rule policyRule) bool { return rule.grants(want) }) {
				granted = append(granted, want.String())
			}
		}
		if len(granted) == 0 {
			return nil
		}
		for _, who := range binding.Subjects {
			who = account(who)
			if checker.trusted(who) || (cluster && kubeadmOwn(binding, who)) ||
				(defaults && who.Kind == "ServiceAccount" && who.Namespace == "kube-system") {
				continue
			}
			code := "namespace_access"
			if scope != "in namespace "+checker.Config.Namespace {
				code = "cluster_access"
			}
			if who.Kind == "ServiceAccount" && who.Namespace == "kube-system" {
				code = "kube_system_access"
			}
			line := printable(qualified(who)) + " " + scope + " " + binding.Metadata.Name
			if seen[line] {
				continue // a list read again after it expired (review c2b LOW)
			}
			seen[line] = true
			report.add(Warn, code, "%s %s may %s %s (binding %s)", who.Kind, printable(qualified(who)),
				strings.Join(granted, ", "), scope, printable(binding.Metadata.Name))
		}
		return nil
	}
	inNamespace := "in namespace " + checker.Config.Namespace
	err := listAll(ctx, checker.API, base+"clusterrolebindings", func(raw json.RawMessage) error {
		if err := reportBinding(raw, namespaceRights, inNamespace, true); err != nil {
			return err
		}
		return reportBinding(raw, clusterRights, "across the cluster", true)
	})
	if err == nil {
		err = listAll(ctx, checker.API, checker.path(base+"namespaces/%s/rolebindings", checker.Config.Namespace),
			// kubeadm's bindings are ClusterRoleBindings: a RoleBinding of
			// the same name is not trusted.
			func(raw json.RawMessage) error { return reportBinding(raw, namespaceRights, inNamespace, false) })
	}
	if err != nil {
		checker.unreadable(report, "RBAC", err)
		return
	}
	report.add(Warn, "rbac_webhooks_unseen",
		"rights a webhook authorizer grants (EKS access entries, GKE IAM) are not RBAC and were not checked")
}

func qualified(who subject) string {
	if who.Namespace != "" {
		return who.Namespace + "/" + who.Name
	}
	return who.Name
}
