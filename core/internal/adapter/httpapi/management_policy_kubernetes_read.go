package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/shared/kubeprofile"
)

// The Kubernetes access of a release (K2f f1): its access profiles and how
// each rule to a cluster grants its groups, read apart from GET …/policy so
// a Console that checks that answer's exact keys keeps working.
//
//	GET …/networks/{n}/policy/kubernetes-access?policy_revision=R[&cluster_id=C]
//
// With cluster_id, only the cluster's rules, its permission sets and the
// sets of every cluster its rules apply (K2h): for showing one cluster,
// never for publishing the whole set again.

type policyKubernetesAccessResponse struct {
	Data          policyKubernetesAccessData `json:"data"`
	CorrelationID string                     `json:"correlation_id"`
}

type policyKubernetesAccessData struct {
	PolicyRevision int64                          `json:"policy_revision"`
	Profiles       []policyKubernetesProfileRead  `json:"profiles"`
	Rules          []policyKubernetesRuleReadItem `json:"rules"`
	// ClusteredProfiles: sets of different clusters may share a name, as
	// every Core knows clusters (K2h flag).
	ClusteredProfiles bool `json:"clustered_profiles"`
}

type policyKubernetesProfileRead struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Namespaced  []kubeprofile.Rule `json:"namespaced"`
	Cluster     []kubeprofile.Rule `json:"cluster"`
	ContentHash string             `json:"content_hash"`
	// ClusterID is the cluster the set belongs to; null for a set of every
	// cluster (K2h).
	ClusterID *string `json:"cluster_id"`
	// CopiedFrom names the set this one was copied from, when it was.
	CopiedFrom *string `json:"copied_from,omitempty"`
}

// policyKubernetesRuleReadItem is a rule to a cluster. A rule released
// before groups (K1a3) has null groups and no access: it grants nothing
// through the cluster's gateways.
type policyKubernetesRuleReadItem struct {
	RuleID    string                      `json:"rule_id"`
	ClusterID string                      `json:"cluster_id"`
	Groups    []string                    `json:"groups"`
	Access    *policyKubernetesAccessRead `json:"access,omitempty"`
}

// policyKubernetesAccessRead is a rule's access as publish takes it:
// {"full": true} or a profile applied in namespaces.
type policyKubernetesAccessRead struct {
	Full        bool       `json:"full,omitempty"`
	ProfileID   string     `json:"profile_id,omitempty"`
	Namespaces  []string   `json:"namespaces,omitempty"`
	ClusterPart bool       `json:"cluster_part,omitempty"`
	Mode        string     `json:"mode,omitempty"`
	ReportUntil *time.Time `json:"report_until,omitempty"`
	// ScopeHash names the profile as applied: the scope a gateway's denial
	// samples carry (K2f f4).
	ScopeHash string `json:"scope_hash,omitempty"`
}

type policyKubernetesAccessPath struct {
	workspaceID, networkID string
	revision               int64
	// cluster, when valid, keeps only what one cluster's page shows.
	cluster kubecluster.ID
}

// policyKubernetesAccessQuery is the read's whole query: one
// policy_revision, a canonical positive decimal, then at most one
// cluster_id, a lower-case UUID.
var policyKubernetesAccessQuery = regexp.MustCompile(
	`^policy_revision=([1-9][0-9]{0,17})(?:&cluster_id=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))?$`)

// parsePolicyKubernetesAccessPath admits only policy_revision, a positive
// decimal, as the query.
func parsePolicyKubernetesAccessPath(request *http.Request) (policyKubernetesAccessPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" {
		return policyKubernetesAccessPath{}, false
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(parts) != 8 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "workspaces" ||
		parts[4] != "networks" || parts[6] != "policy" || parts[7] != "kubernetes-access" {
		return policyKubernetesAccessPath{}, false
	}
	invalid := policyKubernetesAccessPath{workspaceID: parts[3], networkID: parts[5]}
	match := policyKubernetesAccessQuery.FindStringSubmatch(request.URL.RawQuery)
	if match == nil {
		return invalid, true
	}
	revision, err := strconv.ParseInt(match[1], 10, 64)
	if err != nil {
		return invalid, true
	}
	path := policyKubernetesAccessPath{workspaceID: parts[3], networkID: parts[5], revision: revision}
	if match[2] != "" {
		if path.cluster, err = kubecluster.ParseID(match[2]); err != nil {
			return invalid, true
		}
	}
	return path, true
}

func (handler *ManagementHandler) readPolicyKubernetesAccess(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path policyKubernetesAccessPath, session accountsession.Session,
) string {
	workspaceID, err := workspace.ParseID(path.workspaceID)
	networkID, networkErr := network.ParseID(path.networkID)
	scope, scopeErr := network.NewScope(workspaceID, networkID)
	if err != nil || networkErr != nil || scopeErr != nil || path.revision < 1 {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	if nilContinuationDependency(handler.policyKubernetesAccess) {
		writeManagementError(ctx, handler.logger, response, correlationID, policyKubernetesAccessUnavailable)
		return "unavailable"
	}
	released, err := handler.policyKubernetesAccess.ReadPolicyKubernetesAccess(ctx, session, scope, path.revision)
	switch {
	case errors.Is(err, compilation.ErrForbidden):
		// The session may not read the Network's policy, as GET …/policy
		// answers. A revision with no release reads as empty (the compile
		// path reads it so); the Console asks only the active revision
		// (TD-CORE-115).
		writeManagementError(ctx, handler.logger, response, correlationID, policyKubernetesAccessForbidden)
		return "forbidden"
	case err != nil:
		writeManagementError(ctx, handler.logger, response, correlationID, policyKubernetesAccessUnavailable)
		return "unavailable"
	}
	// A read of one cluster is no base for publishing the whole set again:
	// it carries no ETag (review h1 L9).
	if !path.cluster.IsValid() {
		response.Header().Set("ETag", strongVersionETag(path.revision))
	}
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, policyKubernetesAccessResponse{
		Data: policyKubernetesAccessProjection(path.revision, released, path.cluster,
			handler.policyKubernetesClustered),
		CorrelationID: correlationID.String(),
	})
	return "success"
}

func policyKubernetesAccessProjection(revision int64, released compilation.ReleasedKubernetesAccess,
	only kubecluster.ID, clustered bool,
) policyKubernetesAccessData {
	data := policyKubernetesAccessData{PolicyRevision: revision, ClusteredProfiles: clustered,
		Profiles: make([]policyKubernetesProfileRead, 0, len(released.Profiles)),
		Rules:    make([]policyKubernetesRuleReadItem, 0, len(released.Rules))}
	// One cluster's read keeps its sets, and the sets of every cluster its
	// rules apply.
	applied := make(map[string]struct{})
	for _, rule := range released.Rules {
		if only.IsValid() && rule.Cluster == only && !rule.Access.IsZero() {
			applied[rule.Access.ProfileID().String()] = struct{}{}
		}
	}
	for _, profile := range released.Profiles {
		id := profile.ID().String()
		if _, used := applied[id]; only.IsValid() && profile.Cluster() != only &&
			(profile.Cluster().IsValid() || !used) {
			continue
		}
		rules := profile.Profile()
		hash := profile.ContentHash()
		read := policyKubernetesProfileRead{
			ID: id, Name: profile.Name(), Description: profile.Description(),
			Namespaced: nonNilRules(rules.Namespaced), Cluster: nonNilRules(rules.Cluster),
			ContentHash: hex.EncodeToString(hash[:]),
		}
		if cluster := profile.Cluster(); cluster.IsValid() {
			value := cluster.String()
			read.ClusterID = &value
		}
		if origin := profile.CopiedFrom(); origin.IsValid() {
			value := origin.String()
			read.CopiedFrom = &value
		}
		data.Profiles = append(data.Profiles, read)
	}
	for id, rule := range released.Rules {
		if only.IsValid() && rule.Cluster != only {
			continue
		}
		item := policyKubernetesRuleReadItem{RuleID: id.String(), ClusterID: rule.Cluster.String(),
			Groups: slices.Clone(rule.Groups)}
		switch access := rule.Access; {
		case rule.Groups == nil:
			// Released before groups: no access to show (review f1a M2).
		case access.IsZero():
			item.Access = &policyKubernetesAccessRead{Full: true}
		default:
			item.Access = &policyKubernetesAccessRead{ProfileID: access.ProfileID().String(),
				Namespaces: access.Namespaces(), ClusterPart: access.ClusterPart(), Mode: "enforce"}
			scope := access.ScopeHash()
			item.Access.ScopeHash = hex.EncodeToString(scope[:])
			if access.Report() {
				until := access.ReportUntil().UTC()
				item.Access.Mode, item.Access.ReportUntil = "report", &until
			}
		}
		data.Rules = append(data.Rules, item)
	}
	// By name, then ID: sets of different clusters may share a name.
	slices.SortFunc(data.Profiles, func(left, right policyKubernetesProfileRead) int {
		if order := strings.Compare(left.Name, right.Name); order != 0 {
			return order
		}
		return strings.Compare(left.ID, right.ID)
	})
	slices.SortFunc(data.Rules, func(left, right policyKubernetesRuleReadItem) int {
		return strings.Compare(left.RuleID, right.RuleID)
	})
	return data
}

func nonNilRules(rules []kubeprofile.Rule) []kubeprofile.Rule {
	if rules == nil {
		return []kubeprofile.Rule{}
	}
	return rules
}

var (
	policyKubernetesAccessUnavailable = managementError{Status: http.StatusServiceUnavailable,
		Code: "policy_kubernetes_access_unavailable", Message: "the policy's Kubernetes access cannot be read now",
		Retryable: true}
	policyKubernetesAccessForbidden = managementError{Status: http.StatusForbidden, Code: "forbidden",
		Message: "the session may not read this Network's policy"}
)

// isPolicyKubernetesAccessRead admits the read's policy_revision query on
// the browser path; the handler checks it again.
func isPolicyKubernetesAccessRead(request *http.Request) bool {
	path, matched := parsePolicyKubernetesAccessPath(request)
	return matched && path.revision > 0 && request.Method == http.MethodGet
}
