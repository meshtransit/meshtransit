package kubeprofile

import "slices"

// maximumNamespaces bounds the namespaces of a Policy rule (K2 §5.2);
// maximumRawNamespaces bounds them as sent, before duplicates are dropped,
// so a long list costs no sorting first (review K2a M2).
const (
	maximumNamespaces    = 64
	maximumRawNamespaces = 4 * maximumNamespaces
)

// allNamespaces stands alone for every namespace.
const allNamespaces = "*"

// ResourceScope is what the cluster's discovery says of a resource.
type ResourceScope uint8

const (
	// ScopeUnknown: discovery does not know the resource, or its versions
	// disagree. Every resource request is refused (K2-I11).
	ScopeUnknown ResourceScope = iota
	// ScopeCluster: the resource has no namespace (nodes, namespaces).
	ScopeCluster
	// ScopeNamespaced: the resource lives in a namespace.
	ScopeNamespaced
)

// Attributes are what the API server authorizes of a request: its
// RequestInfo, read on the URL the gateway sends, and what the gateway knows
// besides.
type Attributes struct {
	ResourceRequest bool
	Verb            string
	APIGroup        string
	Resource        string
	Subresource     string
	Namespace       string
	Name            string
	// Path is the path of a request that names no resource.
	Path string
	// Upgrade: the request upgrades its connection (SPDY, WebSocket).
	Upgrade bool
	// MayCreate: a PUT to a main resource or an apply patch, which creates
	// the object when it does not exist (S3).
	MayCreate bool
	// Scope is the resource's, from the cluster's discovery.
	Scope ResourceScope
}

// Scope is a profile as one Policy rule applies it: in Namespaces, with or
// without its cluster part. The zero Scope allows nothing.
type Scope struct {
	profile     Profile
	namespaces  []string
	everywhere  bool
	clusterPart bool
	valid       bool
}

// NewScope checks the profile and the rule's namespaces: every namespace
// ("*" alone) or 1 to 64 DNS labels. It keeps copies of both.
func NewScope(profile Profile, namespaces []string, clusterPart bool) (Scope, error) {
	if err := Validate(profile); err != nil {
		return Scope{}, err
	}
	names, err := checkNamespaces(namespaces)
	if err != nil {
		return Scope{}, err
	}
	return Scope{profile: Normalize(profile), namespaces: names, everywhere: names[0] == allNamespaces,
		clusterPart: clusterPart, valid: true}, nil
}

// checkNamespaces returns a rule's namespaces sorted and distinct: every
// namespace ("*" alone) or 1 to 64 DNS labels.
func checkNamespaces(namespaces []string) ([]string, error) {
	if len(namespaces) > maximumRawNamespaces {
		return nil, invalid("a rule needs 1 to %d namespaces", maximumNamespaces)
	}
	names := sortedSet(namespaces)
	switch {
	case len(names) == 0 || len(names) > maximumNamespaces:
		return nil, invalid("a rule needs 1 to %d namespaces", maximumNamespaces)
	case slices.Equal(names, []string{allNamespaces}):
	default:
		for _, name := range names {
			if !dnsLabel(name) {
				return nil, invalid("namespace %q is not a DNS label", name)
			}
		}
	}
	return names, nil
}

// Namespaces returns the rule's namespaces, sorted.
func (scope Scope) Namespaces() []string { return slices.Clone(scope.namespaces) }

// Allows reports whether the scope lets the request through (K2 §5.3).
func (scope Scope) Allows(attributes Attributes) bool {
	// A request the parser could not name allows nothing (§5.5, review K2a M1).
	if !scope.valid || attributes.Verb == "" || attributes.ResourceRequest && attributes.Resource == "" ||
		!attributes.ResourceRequest && attributes.Path == "" {
		return false
	}
	if !attributes.ResourceRequest {
		return scope.clusterPart && partAllows(scope.profile.Cluster, attributes, clusterPart)
	}
	switch attributes.Scope {
	case ScopeCluster:
		if scope.clusterPart && partAllows(scope.profile.Cluster, attributes, clusterPart) {
			return true
		}
		// A namespace object answers the namespaced part in that namespace,
		// as a RoleBinding there would (S4 still applies).
		return attributes.APIGroup == "" && attributes.Resource == "namespaces" && attributes.Namespace != "" &&
			attributes.Name == attributes.Namespace && scope.covers(attributes.Namespace) &&
			partAllows(scope.profile.Namespaced, attributes, namespacedPart)
	case ScopeNamespaced:
		if attributes.Namespace != "" {
			return scope.covers(attributes.Namespace) &&
				partAllows(scope.profile.Namespaced, attributes, namespacedPart)
		}
		// Across namespaces: only a list or watch, only for every namespace;
		// a result cannot be filtered.
		return scope.everywhere && (attributes.Verb == "list" || attributes.Verb == "watch") &&
			partAllows(scope.profile.Namespaced, attributes, namespacedPart)
	}
	return false
}

func (scope Scope) covers(namespace string) bool {
	if scope.everywhere {
		return true
	}
	_, found := slices.BinarySearch(scope.namespaces, namespace)
	return found
}

// Grant is one rule's grant of a group: the whole group, or a scope.
type Grant struct {
	Full  bool
	Scope Scope
}

// AllowsAny reports whether any of the grants of one group lets the request
// through: grants of a group join (K2-I3). The caller passes only the
// grants of the group the request uses that are in force.
func AllowsAny(grants []Grant, attributes Attributes) bool {
	for _, grant := range grants {
		if grant.Full || grant.Scope.Allows(attributes) {
			return true
		}
	}
	return false
}

// part is the profile part a rule is in.
type part uint8

const (
	namespacedPart part = iota
	clusterPart
)

// interactive subresources open a session in a container (S1, S2).
var interactive = map[string]bool{"exec": true, "attach": true, "portforward": true}

// protectedGroups are the API groups whose writes take the cluster (S6):
// RBAC, admission, CRDs, certificate approval and aggregated API servers.
var protectedGroups = map[string]bool{
	"rbac.authorization.k8s.io":    true,
	"admissionregistration.k8s.io": true,
	"apiextensions.k8s.io":         true,
	"certificates.k8s.io":          true,
	"apiregistration.k8s.io":       true,
}

// protectedCoreResources are core resources whose writes take the cluster
// (S6): namespaces, and persistent volumes (a hostPath volume reaches a node).
var protectedCoreResources = map[string]bool{"namespaces": true, "persistentvolumes": true}

// partAllows applies S1 and S3 around the rules of one part: every verb the
// API server checks must be allowed.
func partAllows(rules []Rule, attributes Attributes, in part) bool {
	verbs := []string{attributes.Verb}
	if attributes.ResourceRequest && interactive[attributes.Subresource] {
		// The proxy verb never names a session (review K2a L1).
		if attributes.Verb == "proxy" {
			return false
		}
		// S1: a session in a container needs create; one opened by a
		// WebSocket GET needs get as well, as the API server checks both
		// (AuthorizePodWebsocketUpgradeCreatePermission; K2b).
		verbs = appendCreate(verbs)
	}
	// S3: a write that may create the object needs create as well.
	if attributes.ResourceRequest && attributes.MayCreate && attributes.Subresource == "" {
		verbs = appendCreate(verbs)
	}
	for _, verb := range verbs {
		required := attributes
		required.Verb = verb
		if !anyRule(rules, required, in) {
			return false
		}
	}
	return true
}

func appendCreate(verbs []string) []string {
	if slices.Contains(verbs, "create") {
		return verbs
	}
	return append(verbs, "create")
}

func anyRule(rules []Rule, attributes Attributes, in part) bool {
	for index := range rules {
		if guardedRuleAllows(&rules[index], attributes, in) {
			return true
		}
	}
	return false
}

// guardedRuleAllows is RBAC's rule match, stricter where K2 §5.4 says.
func guardedRuleAllows(rule *Rule, attributes Attributes, in part) bool {
	if !attributes.ResourceRequest {
		// S2: an upgrade on a path needs the exact path (review K2a L3).
		if attributes.Upgrade {
			return slices.Contains(rule.NonResourceURLs, attributes.Path) && verbMatches(rule, attributes.Verb)
		}
		return ruleAllows(rule, attributes)
	}
	switch {
	case sensitive(attributes):
		// S2: sessions and proxies need their exact group and resource; the
		// proxy verb needs itself.
		return namedRuleAllows(rule, attributes) &&
			(attributes.Verb != "proxy" || slices.Contains(rule.Verbs, "proxy"))
	case in == namespacedPart && attributes.APIGroup == "" && attributes.Resource == "namespaces":
		// S4: the namespace object only by name.
		return namedRuleAllows(rule, attributes)
	case in == clusterPart && protected(attributes) && !reads(attributes.Verb):
		// S6: writes that take the cluster only by name.
		return namedRuleAllows(rule, attributes)
	}
	return ruleAllows(rule, attributes)
}

// namedRuleAllows matches with no wildcard in the group or the resource:
// the rule names the exact group and the exact resource or subresource.
func namedRuleAllows(rule *Rule, attributes Attributes) bool {
	combined := attributes.Resource
	if attributes.Subresource != "" {
		combined += "/" + attributes.Subresource
	}
	return slices.Contains(rule.Resources, combined) && slices.Contains(rule.APIGroups, attributes.APIGroup) &&
		verbMatches(rule, attributes.Verb) && resourceNameMatches(rule, attributes.Name)
}

func sensitive(attributes Attributes) bool {
	return attributes.Upgrade || interactive[attributes.Subresource] || attributes.Subresource == "proxy" ||
		attributes.Verb == "proxy"
}

func protected(attributes Attributes) bool {
	return attributes.APIGroup == "" && protectedCoreResources[attributes.Resource] || protectedGroups[attributes.APIGroup]
}

func reads(verb string) bool {
	return verb == "get" || verb == "list" || verb == "watch"
}
