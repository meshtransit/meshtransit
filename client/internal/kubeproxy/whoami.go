package kubeproxy

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"
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
	// Profiles narrow the groups held through scoped grants (K2 §9.4).
	Profiles []whoamiProfile `json:"profiles,omitempty"`
}

// whoamiProfile is one scoped grant as whoami shows it.
type whoamiProfile struct {
	Group       string     `json:"group"`
	Profile     string     `json:"profile"`
	Namespaces  []string   `json:"namespaces"`
	ClusterPart bool       `json:"cluster_part"`
	Mode        string     `json:"mode"` // enforce or report
	ReportUntil *time.Time `json:"report_until,omitempty"`
	ValidUntil  time.Time  `json:"valid_until"`
}

// profilesOf lists the peer's scoped grants in force for groups it does
// not hold whole, as whoami shows them.
func (server *Server) profilesOf(peer Peer, now time.Time) []whoamiProfile {
	var profiles []whoamiProfile
	for _, group := range peer.Access.HeldAt(now) {
		if peer.Access.WholeAt(now, group) {
			continue
		}
		for _, grant := range peer.Access.ScopedAt(now, group) {
			scope, named := peer.Scopes[grant.Scope]
			if !named {
				continue
			}
			shown := whoamiProfile{
				Group: group, Profile: scope.ProfileName, Namespaces: scope.Scope.Namespaces(),
				ClusterPart: scope.Scope.ClusterPart(), Mode: "enforce", ValidUntil: grant.ValidUntil.UTC(),
			}
			// A privileged group never reports (§9.5): decide enforces it.
			if grant.Report && now.Before(grant.ReportUntil) && !server.groups[group].Privileged {
				until := grant.ReportUntil.UTC()
				shown.Mode, shown.ReportUntil = "report", &until
			}
			profiles = append(profiles, shown)
		}
	}
	return profiles
}

func (server *Server) whoami(w http.ResponseWriter, _ *http.Request, peer Peer) {
	answer := whoamiAnswer{
		Device: peer.DeviceID, DeviceName: peer.Name, Cluster: server.options.Cluster,
		Version: server.options.Version, Groups: peer.Access.HeldAt(server.options.CoreNow()),
	}
	if peer.Access != nil {
		answer.Person = peer.Access.OwnerRef
	}
	answer.Profiles = server.profilesOf(peer, server.options.CoreNow())
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
	extra := map[string][]string{
		"meshtransit.net/device": {peer.DeviceID},
		"meshtransit.net/group":  {group.Name}, "meshtransit.net/cluster": {server.options.Cluster},
	}
	if peer.Access != nil && peer.Access.OwnerRef != "" {
		extra["meshtransit.net/person"] = []string{peer.Access.OwnerRef}
	}
	for _, profile := range server.profilesOf(peer, server.options.CoreNow()) {
		if profile.Group == group.Name && !slices.Contains(extra["meshtransit.net/profile"], profile.Profile) {
			extra["meshtransit.net/profile"] = append(extra["meshtransit.net/profile"], profile.Profile)
		}
	}
	answer := map[string]any{
		"apiVersion": "authentication.k8s.io/" + version, "kind": "SelfSubjectReview",
		"metadata": map[string]any{},
		"status": map[string]any{"userInfo": map[string]any{
			"username": server.username(group),
			"groups": []string{
				"system:serviceaccounts", "system:serviceaccounts:" + server.options.Namespace,
				"system:authenticated",
			},
			"extra": extra,
		}},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(answer)
}
