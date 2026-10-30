package kubediscovery

import (
	"encoding/json"
	"errors"

	"meshtransit.net/shared/kubeprofile"
)

// The parts of apidiscovery.k8s.io/v2 the table needs.
type (
	discoveryList struct {
		APIVersion string           `json:"apiVersion"`
		Kind       string           `json:"kind"`
		Items      []groupDiscovery `json:"items"`
	}
	groupDiscovery struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Versions []versionDiscovery `json:"versions"`
	}
	versionDiscovery struct {
		Version   string              `json:"version"`
		Resources []resourceDiscovery `json:"resources"`
	}
	resourceDiscovery struct {
		Resource string `json:"resource"`
		Scope    string `json:"scope"`
	}
)

// decode reads an aggregated document; any other answer is an error, never
// an empty table that would read as "no such resource" for good.
func decode(payload []byte) ([]groupDiscovery, error) {
	var list discoveryList
	if err := json.Unmarshal(payload, &list); err != nil {
		return nil, errors.New("not an aggregated discovery document")
	}
	if list.APIVersion != discoveryVersion || list.Kind != discoveryKind {
		return nil, errors.New("not an aggregated discovery document")
	}
	return list.Items, nil
}

// build joins both documents: a resource whose versions disagree about its
// scope, or name one the table does not know, is unknown (K2 §10.2).
func build(documents [2]document) map[key]kubeprofile.ResourceScope {
	scopes := make(map[key]kubeprofile.ResourceScope)
	conflicting := make(map[key]bool)
	for _, document := range documents {
		for _, group := range document.items {
			for _, version := range group.Versions {
				for _, resource := range version.Resources {
					if resource.Resource == "" {
						continue
					}
					at := key{group.Metadata.Name, resource.Resource}
					scope := scopeOf(resource.Scope)
					if held, found := scopes[at]; scope == kubeprofile.ScopeUnknown || found && held != scope {
						conflicting[at] = true
					}
					scopes[at] = scope
				}
			}
		}
	}
	for at := range conflicting {
		delete(scopes, at)
	}
	return scopes
}

func scopeOf(scope string) kubeprofile.ResourceScope {
	switch scope {
	case "Cluster":
		return kubeprofile.ScopeCluster
	case "Namespaced":
		return kubeprofile.ScopeNamespaced
	}
	return kubeprofile.ScopeUnknown
}
