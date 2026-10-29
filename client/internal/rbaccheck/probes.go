package rbaccheck

import (
	"strconv"
	"strings"
)

// Attributes are a SelfSubjectAccessReview's resource attributes; an empty
// Namespace asks about the whole cluster.
type Attributes struct {
	Namespace, Verb, Group, Resource, Subresource, Name string
}

// String names the right asked about, as a group's reason shows it.
func (attributes Attributes) String() string {
	resource := attributes.Resource
	if attributes.Group != "" {
		resource = attributes.Group + "/" + resource
	}
	if attributes.Subresource != "" {
		resource += "/" + attributes.Subresource
	}
	text := attributes.Verb + " " + resource
	if attributes.Name != "" {
		text += " " + attributes.Name
	}
	switch {
	case attributes.Namespace == "":
		return text + " in the cluster"
	case strings.HasPrefix(attributes.Namespace, probePrefix):
		return text + " in every namespace"
	}
	return text + " in " + attributes.Namespace
}

// probePrefix starts the namespace, made up and never there, a pass asks
// about: a right held there comes from a ClusterRoleBinding, which a
// webhook authorizer may answer otherwise than for the whole cluster.
const probePrefix = "mt-probe-"

const (
	rbac         = "rbac.authorization.k8s.io"
	admission    = "admissionregistration.k8s.io"
	certificates = "certificates.k8s.io"
	flowControl  = "flowcontrol.apiserver.k8s.io"
)

// writes are the verbs that change an object.
var writes = []string{"create", "update", "patch", "delete"}

// gateway names what a group must not reach of the gateway itself.
type gateway struct {
	namespace, statefulSet, serviceAccount string
	pods                                   []string
	secrets                                []string // its state, join key and the like
	accounts                               []string // every group's mt-<group>
	// guarded are namespaces where running a pod reaches the gateway's node
	// (the VAP's allowlist, kube-system).
	guarded []string
}

// rights collects the attributes a pass asks about.
type rights []Attributes

func (collected *rights) add(namespace, verb, group, resource, subresource, name string) {
	*collected = append(*collected, Attributes{Namespace: namespace, Verb: verb, Group: group, Resource: resource,
		Subresource: subresource, Name: name})
}

// dangerousRights are what no non-privileged group may hold (K1b design §9;
// K1 §6): rights over the cluster, asked about the whole cluster and a
// namespace that does not exist; ways to run code in a namespace whose pods
// reach the gateway; and the gateway's own objects by name.
func dangerousRights(at gateway, probeNamespace string) []Attributes {
	var collected rights
	for _, namespace := range []string{"", probeNamespace} {
		collected.add(namespace, "*", "*", "*", "", "")
		for _, verb := range []string{"list", "get", "watch"} {
			collected.add(namespace, verb, "", "secrets", "", "")
		}
		for _, resource := range []string{"roles", "clusterroles"} {
			collected.add(namespace, "escalate", rbac, resource, "", "")
			collected.add(namespace, "bind", rbac, resource, "", "")
		}
		collected.add(namespace, "create", "", "serviceaccounts", "token", "")
		collected.add(namespace, "impersonate", "", "serviceaccounts", "", "")
		for _, resource := range []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"} {
			for _, verb := range []string{"create", "update", "patch"} {
				collected.add(namespace, verb, rbac, resource, "", "")
			}
		}
	}
	for _, resource := range []string{"users", "groups"} {
		collected.add("", "impersonate", "", resource, "", "")
	}
	collected.add("", "impersonate", "authentication.k8s.io", "uids", "", "")
	// Through nodes/proxy the kubelet runs commands in any pod (review b4
	// H1); a node's taints decide whether pods land by the gateway (H3).
	for _, verb := range append([]string{"get"}, writes...) {
		collected.add("", verb, "", "nodes", "proxy", "")
	}
	for _, verb := range []string{"update", "patch"} {
		collected.add("", verb, "", "nodes", "", "")
		collected.add("", verb, "", "nodes", "status", "")
	}
	collected.add("", "update", certificates, "certificatesigningrequests", "approval", "")
	collected.add("", "approve", certificates, "signers", "", "")
	for _, kind := range [][2]string{
		{admission, "validatingwebhookconfigurations"}, {admission, "mutatingwebhookconfigurations"},
		{admission, "validatingadmissionpolicies"}, {admission, "validatingadmissionpolicybindings"},
		{admission, "mutatingadmissionpolicies"}, {admission, "mutatingadmissionpolicybindings"},
		{"apiregistration.k8s.io", "apiservices"}, {"apiextensions.k8s.io", "customresourcedefinitions"},
		{flowControl, "flowschemas"}, {flowControl, "prioritylevelconfigurations"},
	} {
		for _, verb := range writes {
			collected.add("", verb, kind[0], kind[1], "", "")
		}
	}
	collected.add("", "create", "", "persistentvolumes", "", "")
	for _, namespace := range at.guarded {
		runsCode(&collected, namespace, nil)
	}
	gatewayObjects(&collected, at)
	return collected
}

// runsCode adds the ways to run code in a namespace, or to read what its
// pods hold: pods and every controller that makes them (review b4 C1),
// sessions in pods, secrets, tokens and configuration (EKS's aws-auth in
// kube-system, M5). Named pods are asked about by name too.
func runsCode(collected *rights, namespace string, pods []string) {
	collected.add(namespace, "create", "", "pods", "", "")
	for _, workload := range [][2]string{
		{"apps", "deployments"}, {"apps", "replicasets"}, {"apps", "statefulsets"}, {"apps", "daemonsets"},
		{"batch", "jobs"}, {"batch", "cronjobs"}, {"", "replicationcontrollers"},
	} {
		// Changing an existing workload's template runs new code as much as
		// creating one: kube-proxy's DaemonSet reaches every node (re-review
		// b4 H1).
		for _, verb := range []string{"create", "update", "patch"} {
			collected.add(namespace, verb, workload[0], workload[1], "", "")
		}
	}
	for _, verb := range []string{"create", "update", "patch"} {
		collected.add(namespace, verb, "apps", "controllerrevisions", "", "")
	}
	for _, pod := range append([]string{""}, pods...) {
		for _, verb := range []string{"update", "patch"} {
			collected.add(namespace, verb, "", "pods", "", pod) // a pod's image can be changed
			collected.add(namespace, verb, "", "pods", "ephemeralcontainers", pod)
		}
		for _, subresource := range []string{"exec", "attach", "portforward"} {
			// A WebSocket exec is authorized as get while the gate
			// AuthorizePodWebsocketUpgradeCreatePermission is off.
			collected.add(namespace, "get", "", "pods", subresource, pod)
			collected.add(namespace, "create", "", "pods", subresource, pod)
		}
	}
	for _, verb := range []string{"list", "get", "watch"} {
		collected.add(namespace, verb, "", "secrets", "", "")
	}
	collected.add(namespace, "create", "", "serviceaccounts", "token", "")
	for _, verb := range []string{"update", "patch"} {
		collected.add(namespace, verb, "", "configmaps", "", "")
	}
	collected.add(namespace, "create", rbac, "rolebindings", "", "")
}

// gatewayObjects adds the gateway's own objects by name, where a rule may
// name them (re-review HIGH-B): its pods, its Secrets, the tokens of every
// group's account and its own, its StatefulSet, the proxies to its pods.
func gatewayObjects(collected *rights, at gateway) {
	runsCode(collected, at.namespace, at.pods)
	for _, secret := range at.secrets {
		for _, verb := range []string{"get", "list", "watch", "update", "patch"} {
			collected.add(at.namespace, verb, "", "secrets", "", secret)
		}
	}
	for _, account := range append([]string{at.serviceAccount}, at.accounts...) {
		collected.add(at.namespace, "create", "", "serviceaccounts", "token", account)
	}
	for _, verb := range []string{"update", "patch"} {
		collected.add(at.namespace, verb, "apps", "statefulsets", "", at.statefulSet)
	}
	for _, resource := range []string{"pods", "services"} {
		for _, verb := range []string{"get", "create"} {
			collected.add(at.namespace, verb, "", resource, "proxy", "")
		}
	}
	for _, name := range []string{"aws-auth"} {
		for _, verb := range []string{"update", "patch"} {
			collected.add("kube-system", verb, "", "configmaps", "", name)
		}
	}
}

// replicaNames are a StatefulSet's pod names for replicas, and two more for
// a scale-up (review b4 L5).
func replicaNames(statefulSet string, replicas int) []string {
	names := make([]string, 0, replicas+2)
	for ordinal := range replicas + 2 {
		names = append(names, statefulSet+"-"+strconv.Itoa(ordinal))
	}
	return names
}

// unboundImpersonation asks whether a group may impersonate anyone: names
// made up for the pass, which no resourceNames list holds.
func unboundImpersonation(probeNamespace, made string) []Attributes {
	return []Attributes{
		{Verb: "impersonate", Resource: "users", Name: made},
		{Verb: "impersonate", Resource: "groups", Name: made},
		{Verb: "impersonate", Group: "authentication.k8s.io", Resource: "uids", Name: made},
		{Namespace: probeNamespace, Verb: "impersonate", Resource: "serviceaccounts", Name: made},
	}
}
