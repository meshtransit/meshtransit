package mtcp

import (
	"errors"
	"strings"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
)

// gateway.ceiling1 bounds (mtcp-v1 §6.12).
const (
	// GatewayCeilingNamespaceMaximum bounds the named namespaces of a group.
	GatewayCeilingNamespaceMaximum = 16
	// GatewayCeilingRuleMaximum bounds the rules of one scope, resource and
	// path rules together.
	GatewayCeilingRuleMaximum = 576
	// GatewayCeilingListMaximum bounds each list of a rule.
	GatewayCeilingListMaximum = 64
	// GatewayCeilingStringMaximum bounds each string of a rule, and the
	// ClusterRole's name.
	GatewayCeilingStringMaximum = 253
	gatewayNamespaceMaximum     = 63
)

// ErrGatewayGroupCeiling reports a GatewayGroupCeiling that breaks §6.12.
var ErrGatewayGroupCeiling = errors.New("mtcp: invalid gateway group ceiling")

// ValidateGatewayGroupCeiling checks a ceiling as Core takes it: at most 64
// distinct groups, each with its everywhere scope and at most 16 distinct
// named namespaces, every rule within the bounds and in printable ASCII.
func ValidateGatewayGroupCeiling(ceiling *mtcpv1.GatewayGroupCeiling) error {
	groups := ceiling.GetGroups()
	if len(groups) > GatewayGroupReportMaximum || ceiling.GetCheckedAtMs() < 0 {
		return ErrGatewayGroupCeiling
	}
	seen := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		name := group.GetGroup()
		if _, twice := seen[name]; twice || !validGroupName(name) || !validCeilingGroup(group) {
			return ErrGatewayGroupCeiling
		}
		seen[name] = struct{}{}
	}
	return nil
}

func validCeilingGroup(group *mtcpv1.GatewayCeilingGroup) bool {
	role := group.GetClusterRole()
	if role != "" && !validRBACName(role) {
		return false
	}
	everywhere := group.GetEverywhere()
	if everywhere == nil || everywhere.GetNamespace() != "" || !validCeilingScope(everywhere) {
		return false
	}
	namespaces := group.GetNamespaces()
	if len(namespaces) > GatewayCeilingNamespaceMaximum {
		return false
	}
	seen := make(map[string]struct{}, len(namespaces))
	for _, scope := range namespaces {
		namespace := scope.GetNamespace()
		if _, twice := seen[namespace]; twice || len(namespace) > gatewayNamespaceMaximum ||
			!validGroupName(namespace) || !validCeilingScope(scope) {
			return false
		}
		seen[namespace] = struct{}{}
	}
	return true
}

// validCeilingScope: an unmeasured scope says nothing else; a measured one
// holds at most 576 valid rules.
func validCeilingScope(scope *mtcpv1.GatewayCeilingScope) bool {
	rules := scope.GetRules()
	if !scope.GetMeasured() {
		return len(rules) == 0 && !scope.GetIncomplete() && scope.GetRulesDropped() == 0
	}
	if len(rules) > GatewayCeilingRuleMaximum {
		return false
	}
	for _, rule := range rules {
		if !validCeilingRule(rule) {
			return false
		}
	}
	return true
}

// validCeilingRule is a resource rule (verbs, API groups, resources,
// perhaps names) or a path rule (verbs and paths), as a
// SelfSubjectRulesReview answers them.
func validCeilingRule(rule *mtcpv1.KubernetesProfileRule) bool {
	lists := [][]string{
		rule.GetVerbs(), rule.GetApiGroups(), rule.GetResources(), rule.GetResourceNames(),
		rule.GetNonResourceUrls(),
	}
	for _, list := range lists {
		if len(list) > GatewayCeilingListMaximum {
			return false
		}
		for _, value := range list {
			if !printable(value) {
				return false
			}
		}
	}
	if len(rule.GetVerbs()) == 0 {
		return false
	}
	if len(rule.GetNonResourceUrls()) > 0 {
		return len(rule.GetApiGroups()) == 0 && len(rule.GetResources()) == 0 && len(rule.GetResourceNames()) == 0
	}
	return len(rule.GetResources()) > 0 && len(rule.GetApiGroups()) > 0
}

// printable is at most 253 bytes of printable ASCII; empty is allowed, as
// the core API group is named.
func printable(value string) bool {
	if len(value) > GatewayCeilingStringMaximum {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

// validRBACName is a name the API server takes for a ClusterRole: a path
// segment of printable ASCII, never "." or "..".
func validRBACName(name string) bool {
	return name != "." && name != ".." && !strings.ContainsAny(name, "/%") && printable(name)
}
