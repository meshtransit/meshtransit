/*
Copyright 2018 The Kubernetes Authors (pkg/apis/rbac/v1/evaluation_helpers.go).
Copyright 2016 The Kubernetes Authors (plugin/pkg/auth/authorizer/rbac/rbac.go).

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Modified by The MeshTransit Authors: a port of
k8s.io/kubernetes@v1.35.1 pkg/apis/rbac/v1/evaluation_helpers.go
(VerbMatches, APIGroupMatches, ResourceMatches, ResourceNameMatches,
NonResourceURLMatches) and plugin/pkg/auth/authorizer/rbac/rbac.go
(RuleAllows), over this package's Rule and Attributes instead of
rbacv1.PolicyRule and authorizer.Attributes.
*/

package kubeprofile

import "strings"

// Wildcards of a policy rule, as rbacv1 names them.
const (
	verbAll        = "*"
	apiGroupAll    = "*"
	resourceAll    = "*"
	nonResourceAll = "*"
)

// ruleAllows reports whether the rule allows the request, as the RBAC
// authorizer decides it.
func ruleAllows(rule *Rule, attributes Attributes) bool {
	if attributes.ResourceRequest {
		combinedResource := attributes.Resource
		if len(attributes.Subresource) > 0 {
			combinedResource = attributes.Resource + "/" + attributes.Subresource
		}
		return verbMatches(rule, attributes.Verb) &&
			apiGroupMatches(rule, attributes.APIGroup) &&
			resourceMatches(rule, combinedResource, attributes.Subresource) &&
			resourceNameMatches(rule, attributes.Name)
	}
	return verbMatches(rule, attributes.Verb) &&
		nonResourceURLMatches(rule, attributes.Path)
}

func verbMatches(rule *Rule, requestedVerb string) bool {
	for _, ruleVerb := range rule.Verbs {
		if ruleVerb == verbAll {
			return true
		}
		if ruleVerb == requestedVerb {
			return true
		}
	}
	return false
}

func apiGroupMatches(rule *Rule, requestedGroup string) bool {
	for _, ruleGroup := range rule.APIGroups {
		if ruleGroup == apiGroupAll {
			return true
		}
		if ruleGroup == requestedGroup {
			return true
		}
	}
	return false
}

func resourceMatches(rule *Rule, combinedRequestedResource, requestedSubresource string) bool {
	for _, ruleResource := range rule.Resources {
		// if everything is allowed, we match
		if ruleResource == resourceAll {
			return true
		}
		// if we have an exact match, we match
		if ruleResource == combinedRequestedResource {
			return true
		}

		// We can also match a */subresource.
		// if there isn't a subresource, then continue
		if len(requestedSubresource) == 0 {
			continue
		}
		// if the rule isn't in the format */subresource, then we don't match, continue
		if len(ruleResource) == len(requestedSubresource)+2 &&
			strings.HasPrefix(ruleResource, "*/") &&
			strings.HasSuffix(ruleResource, requestedSubresource) {
			return true

		}
	}

	return false
}

func resourceNameMatches(rule *Rule, requestedName string) bool {
	if len(rule.ResourceNames) == 0 {
		return true
	}

	for _, ruleName := range rule.ResourceNames {
		if ruleName == requestedName {
			return true
		}
	}

	return false
}

func nonResourceURLMatches(rule *Rule, requestedURL string) bool {
	for _, ruleURL := range rule.NonResourceURLs {
		if ruleURL == nonResourceAll {
			return true
		}
		if ruleURL == requestedURL {
			return true
		}
		if strings.HasSuffix(ruleURL, "*") && strings.HasPrefix(requestedURL, strings.TrimRight(ruleURL, "*")) {
			return true
		}
	}

	return false
}
