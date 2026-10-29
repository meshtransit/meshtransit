/*
Copyright 2016 The Kubernetes Authors.

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
k8s.io/apiserver@v0.35.1 pkg/endpoints/request/requestinfo.go
(RequestInfoFactory with APIPrefixes api, apis and GrouplessAPIPrefixes
api), without its dependencies on k8s.io/apimachinery. The list options are
checked only as far as the name a field selector gives depends on them;
field and label selectors are not kept; a request with a label selector
gets no name from its field selector (the API server would, for a valid
one). See client/THIRD_PARTY_NOTICES.md.
*/

// Package kubereq reads a Kubernetes API request the way the API server
// does, so the gateway classifies what the API server will authorize (K1b
// design §5).
package kubereq

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Info is what the API server reads of a request: its RequestInfo.
type Info struct {
	// IsResourceRequest reports a request for a resource, as opposed to
	// one of the other paths (/version, /api, /apis/<group>, …).
	IsResourceRequest bool
	Path              string
	// Verb is the authorization verb: get, list, watch, create, update,
	// patch, delete, deletecollection, proxy; or the lower-cased method of
	// a non-resource request; empty for a method no verb answers.
	Verb        string
	APIPrefix   string
	APIGroup    string
	APIVersion  string
	Namespace   string
	Resource    string
	Subresource string
	Name        string
	// Parts are the path segments after the namespace.
	Parts []string
}

// errNoResource reports a special verb that names no resource.
var errNoResource = errors.New("kubereq: unable to determine kind and namespace from url")

// specialVerbs are verbs a path prefix gives; proxy names no subresource.
var specialVerbs = map[string]bool{"proxy": true, "watch": true}

// namespaceSubresources are a namespace's own subresources.
var namespaceSubresources = map[string]bool{"status": true, "finalize": true}

// Parse reads method and target, which must not be nil, as the API server
// does.
func Parse(method string, target *url.URL) (Info, error) {
	if target == nil {
		return Info{}, errNoResource
	}
	info := Info{Path: target.Path, Verb: strings.ToLower(method)}
	parts := splitPath(target.Path)
	if len(parts) < 3 || (parts[0] != "api" && parts[0] != "apis") {
		return info, nil
	}
	info.APIPrefix, parts = parts[0], parts[1:]
	if info.APIPrefix != "api" {
		// A group's resources need at least a group, a version and a resource.
		if len(parts) < 3 {
			return info, nil
		}
		info.APIGroup, parts = parts[0], parts[1:]
	}
	info.IsResourceRequest = true
	info.APIVersion, parts = parts[0], parts[1:]

	if specialVerbs[parts[0]] {
		if len(parts) < 2 {
			return info, errNoResource
		}
		info.Verb, parts = parts[0], parts[1:]
	} else {
		info.Verb = methodVerb(method)
	}

	if parts[0] == "namespaces" {
		if len(parts) > 1 {
			info.Namespace = parts[1]
			// Past a namespace come its resources, but for its own
			// subresources.
			if len(parts) > 2 && !namespaceSubresources[parts[2]] {
				parts = parts[2:]
			}
		}
	}
	info.Parts = parts

	switch {
	case len(parts) >= 3 && info.Verb != "proxy":
		info.Subresource = parts[2]
		fallthrough
	case len(parts) >= 2:
		info.Name = parts[1]
		fallthrough
	case len(parts) >= 1:
		info.Resource = parts[0]
	}

	// A get without a name is a list, or a watch; a field selector may
	// name its object.
	if info.Name == "" && info.Verb == "get" {
		query := target.Query()
		info.Verb = "list"
		if watching(query["watch"]) {
			info.Verb = "watch"
		}
		info.Name = selectedName(query)
	}
	if info.Name == "" && info.Verb == "delete" {
		info.Verb = "deletecollection"
	}
	return info, nil
}

// methodVerb is the verb of a method on a resource path.
func methodVerb(method string) string {
	switch method {
	case http.MethodPost:
		return "create"
	case http.MethodGet, http.MethodHead:
		return "get"
	case http.MethodPut:
		return "update"
	case http.MethodPatch:
		return "patch"
	case http.MethodDelete:
		return "delete"
	}
	return ""
}

// watching is apimachinery's conversion of a query value to a bool: any
// first value but "0" or "false" (any case) is true. When the list options
// do not decode the API server compares strings.ToLower(value) instead,
// which differs only for "false" spelt with U+017F: list versus watch,
// never another class.
func watching(values []string) bool {
	return len(values) > 0 && values[0] != "0" && !strings.EqualFold(values[0], "false")
}

// selectedName is the name an exact metadata.name field selector gives a
// list or watch, when the list options decode as the API server decodes
// them and the name is a valid path segment.
func selectedName(query url.Values) string {
	for _, key := range []string{"limit", "timeoutSeconds"} {
		if values := query[key]; len(values) > 0 {
			if _, err := strconv.ParseInt(values[0], 10, 64); err != nil {
				return ""
			}
		}
	}
	// The API server decodes the label selector too: an invalid one fails
	// the whole decode, and no name is taken (difftest b7b).
	if labels, labelled := query["labelSelector"]; labelled && !validLabelSelector(labels[0]) {
		return ""
	}
	selectors := query["fieldSelector"]
	if len(selectors) == 0 {
		return ""
	}
	name, ok := exactMatch(selectors[0], "metadata.name")
	if !ok || name == "." || name == ".." || strings.ContainsAny(name, "/%") {
		return ""
	}
	return name
}

func splitPath(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return []string{}
	}
	return strings.Split(path, "/")
}

// validLabelSelector reports a label selector the API server parses:
// comma-separated requirements, each "key", "!key", "key=value",
// "key==value", "key!=value", "key in (values)" or "key notin (values)",
// with Kubernetes' qualified names and label values.
func validLabelSelector(selector string) bool {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return true
	}
	for _, requirement := range splitRequirements(selector) {
		if !validRequirement(strings.TrimSpace(requirement)) {
			return false
		}
	}
	return true
}

// splitRequirements splits on commas outside parentheses.
func splitRequirements(selector string) []string {
	var parts []string
	depth, start := 0, 0
	for index, character := range selector {
		switch character {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, selector[start:index])
				start = index + 1
			}
		}
	}
	return append(parts, selector[start:])
}

func validRequirement(requirement string) bool {
	if key, found := strings.CutPrefix(requirement, "!"); found {
		return validLabelKey(strings.TrimSpace(key))
	}
	for _, operator := range []string{"!=", "==", "="} {
		if key, value, found := strings.Cut(requirement, operator); found {
			return validLabelKey(strings.TrimSpace(key)) && validLabelValue(strings.TrimSpace(value))
		}
	}
	fields := strings.Fields(requirement)
	if len(fields) == 1 {
		return validLabelKey(fields[0])
	}
	key, rest, found := strings.Cut(requirement, " ")
	if !found || !validLabelKey(key) {
		return false
	}
	rest = strings.TrimSpace(rest)
	for _, operator := range []string{"notin", "in"} {
		if set, found := strings.CutPrefix(rest, operator); found {
			set = strings.TrimSpace(set)
			if !strings.HasPrefix(set, "(") || !strings.HasSuffix(set, ")") {
				return false
			}
			for _, value := range strings.Split(set[1:len(set)-1], ",") {
				if !validLabelValue(strings.TrimSpace(value)) {
					return false
				}
			}
			return true
		}
	}
	return false
}

// validLabelKey is a qualified name with an optional DNS subdomain prefix.
func validLabelKey(key string) bool {
	prefix, name, prefixed := strings.Cut(key, "/")
	if !prefixed {
		name, prefix = prefix, ""
	} else if prefix == "" || len(prefix) > 253 || !dnsSubdomain(prefix) {
		return false
	}
	return name != "" && len(name) <= 63 && labelCharacters(name)
}

// validLabelValue is empty or a label value of at most 63 characters.
func validLabelValue(value string) bool {
	return value == "" || len(value) <= 63 && labelCharacters(value)
}

// labelCharacters: alphanumerics at both ends, '-', '_' and '.' inside.
func labelCharacters(text string) bool {
	alphanumeric := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }
	for index := range len(text) {
		c := text[index]
		if !alphanumeric(c) && (index == 0 || index == len(text)-1 || (c != '-' && c != '_' && c != '.')) {
			return false
		}
	}
	return true
}

func dnsSubdomain(name string) bool {
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for index := range len(label) {
			c := label[index]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') && (index == 0 || index == len(label)-1 || c != '-') {
				return false
			}
		}
	}
	return true
}
