package httpapi

import (
	"errors"
	"net/http"
	"time"

	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	policypublication "meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/shared/kubeprofile"
)

// publishPolicyKubernetesProfileRequest is one access profile of the
// release (K2 §5.1): its rules as RBAC's PolicyRule, keyed as RBAC writes
// them. The ID is the client's, a UUIDv7 kept across edits.
type publishPolicyKubernetesProfileRequest struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Namespaced  []kubeprofile.Rule `json:"namespaced"`
	Cluster     []kubeprofile.Rule `json:"cluster"`
}

// publishPolicyKubernetesAccessRequest is how a rule to a cluster applies
// its groups: {"full": true}, or a profile in namespaces, enforcing (the
// default) or reporting until a deadline at most 14 days ahead.
type publishPolicyKubernetesAccessRequest struct {
	Full        *bool    `json:"full"`
	ProfileID   *string  `json:"profile_id"`
	Namespaces  []string `json:"namespaces"`
	ClusterPart *bool    `json:"cluster_part"`
	Mode        *string  `json:"mode"`
	ReportUntil *string  `json:"report_until"`
}

// decodePolicyKubernetesProfiles returns the release's profiles: nil when
// the request keeps those of the release it replaces, empty when it removes
// them all.
func decodePolicyKubernetesProfiles(
	input *[]publishPolicyKubernetesProfileRequest,
) ([]policypublication.KubernetesProfile, error) {
	if input == nil {
		return nil, nil
	}
	if len(*input) > policypublication.MaximumKubernetesProfiles {
		return nil, policypublication.ErrInvalidKubernetesProfile
	}
	profiles := make([]policypublication.KubernetesProfile, 0, len(*input))
	for _, entry := range *input {
		id, err := policypublication.ParseKubernetesProfileID(entry.ID)
		if err != nil {
			return nil, err
		}
		profile, err := policypublication.NewKubernetesProfile(policypublication.KubernetesProfileParams{ID: id,
			Description: entry.Description, Profile: kubeprofile.Profile{Name: entry.Name,
				Namespaced: entry.Namespaced, Cluster: entry.Cluster}})
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

// decodePolicyKubernetesAccess returns a rule's access: nil keeps what the
// rule has; an object is full or a profile, never neither ({} is refused).
func decodePolicyKubernetesAccess(
	input *publishPolicyKubernetesAccessRequest,
) (*compilation.KubernetesAccessIntent, error) {
	if input == nil {
		return nil, nil
	}
	if input.Full != nil {
		if !*input.Full || input.ProfileID != nil || input.Namespaces != nil || input.ClusterPart != nil ||
			input.Mode != nil || input.ReportUntil != nil {
			return nil, policy.ErrInvalidRule
		}
		return &compilation.KubernetesAccessIntent{Full: true}, nil
	}
	if input.ProfileID == nil || input.Namespaces == nil {
		return nil, policy.ErrInvalidRule
	}
	id, err := policypublication.ParseKubernetesProfileID(*input.ProfileID)
	if err != nil {
		return nil, err
	}
	access := &compilation.KubernetesAccessIntent{ProfileID: id, Namespaces: input.Namespaces}
	if input.ClusterPart != nil {
		access.ClusterPart = *input.ClusterPart
	}
	mode := "enforce"
	if input.Mode != nil {
		mode = *input.Mode
	}
	switch {
	case mode == "enforce" && input.ReportUntil == nil:
	case mode == "report" && input.ReportUntil != nil:
		until, parseErr := time.Parse(time.RFC3339Nano, *input.ReportUntil)
		if parseErr != nil {
			return nil, parseErr
		}
		access.Report, access.ReportUntil = true, until.UTC()
	default:
		return nil, policy.ErrInvalidRule
	}
	if !access.IsValid() {
		return nil, policy.ErrInvalidRule
	}
	return access, nil
}

// classifyKubernetesAccessError answers what compiling or publishing a
// rule's Kubernetes access refuses, if err is that.
func classifyKubernetesAccessError(err error) (managementError, bool) {
	switch {
	case errors.Is(err, compilation.ErrKubernetesGroupsRequired):
		return kubernetesGroupsRequiredError, true
	case errors.Is(err, compilation.ErrKubernetesAccessRequired):
		return managementError{
			Status: http.StatusUnprocessableEntity, Code: "kubernetes_access_required",
			Message: "a rule to a Kubernetes cluster must say how it grants its groups: in full or through " +
				"an access profile; a rule with a profile that moves to another source or cluster says it again",
		}, true
	case errors.Is(err, compilation.ErrKubernetesProfileUnknown):
		return managementError{
			Status: http.StatusUnprocessableEntity, Code: "kubernetes_profile_unknown",
			Message: "a rule applies a Kubernetes access profile the release does not hold",
		}, true
	case errors.Is(err, compilation.ErrKubernetesProfileInUse):
		return managementError{
			Status: http.StatusUnprocessableEntity, Code: "kubernetes_profile_in_use",
			Message: "the release drops a Kubernetes access profile a rule still applies",
		}, true
	case errors.Is(err, compilation.ErrKubernetesReportWindow):
		return managementError{
			Status: http.StatusUnprocessableEntity, Code: "kubernetes_report_window",
			Message: "a rule reports until a time that is not within the next 14 days",
		}, true
	case errors.Is(err, compilation.ErrKubernetesAccessLimit):
		return managementError{
			Status: http.StatusUnprocessableEntity, Code: "kubernetes_access_limit",
			Message: "the rules to one Kubernetes cluster make more than 64 grants, or more profiles, scopes " +
				"or bytes than a gateway takes",
		}, true
	case errors.Is(err, policypublication.ErrKubernetesProfile):
		return managementError{
			Status: http.StatusConflict, Code: "kubernetes_profile_conflict",
			Message: "a Kubernetes access profile's content hash names other content; send the profile again",
		}, true
	default:
		return managementError{}, false
	}
}
