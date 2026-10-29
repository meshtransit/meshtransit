package kubeproxy

import (
	"encoding/json"
	"net/http"
	"strings"
)

// whoamiAnswer is /mt/v1/whoami (K1b design §6): who the gateway takes the
// connection for, for display and diagnosis only.
type whoamiAnswer struct {
	Person       string   `json:"person,omitempty"`
	Device       string   `json:"device"`
	DeviceName   string   `json:"device_name"`
	Groups       []string `json:"groups"`
	DefaultGroup string   `json:"default_group,omitempty"`
	Cluster      string   `json:"cluster"`
	Version      string   `json:"version"`
	Username     string   `json:"username,omitempty"`
}

func (server *Server) whoami(w http.ResponseWriter, _ *http.Request, peer Peer) {
	answer := whoamiAnswer{Device: peer.DeviceID, DeviceName: peer.Name, Cluster: server.options.Cluster,
		Version: server.options.Version, Groups: peer.Access.GroupsAt(server.options.CoreNow())}
	if peer.Access != nil {
		answer.Person = peer.Access.OwnerRef
	}
	if group, reason := server.choose(peer, ""); reason == "" {
		answer.DefaultGroup, answer.Username = group.Name, server.username(group)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(answer)
}

// username is the account the API server sees for a group.
func (server *Server) username(group Group) string {
	return "system:serviceaccount:" + server.options.Namespace + ":mt-" + group.Name
}

// selfSubjectReview reports kubectl auth whoami's request, which the
// gateway answers itself.
func selfSubjectReview(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	version, found := strings.CutPrefix(path, "/apis/authentication.k8s.io/")
	if !found {
		return false
	}
	version, found = strings.CutSuffix(version, "/selfsubjectreviews")
	return found && (version == "v1" || version == "v1beta1" || version == "v1alpha1")
}

// selfReview answers a SelfSubjectReview: the account the API server sees,
// with the person, Device and group in its extra (K1b design §6).
func (server *Server) selfReview(w http.ResponseWriter, path string, peer Peer, group Group) {
	version := strings.TrimSuffix(strings.TrimPrefix(path, "/apis/authentication.k8s.io/"),
		"/selfsubjectreviews")
	extra := map[string][]string{"meshtransit.net/device": {peer.DeviceID},
		"meshtransit.net/group": {group.Name}, "meshtransit.net/cluster": {server.options.Cluster}}
	if peer.Access != nil && peer.Access.OwnerRef != "" {
		extra["meshtransit.net/person"] = []string{peer.Access.OwnerRef}
	}
	answer := map[string]any{
		"apiVersion": "authentication.k8s.io/" + version, "kind": "SelfSubjectReview",
		"metadata": map[string]any{},
		"status": map[string]any{"userInfo": map[string]any{
			"username": server.username(group),
			"groups": []string{"system:serviceaccounts", "system:serviceaccounts:" + server.options.Namespace,
				"system:authenticated"},
			"extra": extra,
		}},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(answer)
}
