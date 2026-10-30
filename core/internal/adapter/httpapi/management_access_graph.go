package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/netip"
	"strings"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/domain/workspace"
)

const maximumAccessGraphBodyBytes = 64 * 1024

type explainPolicyRequest struct {
	SourceDeviceID                string `json:"source_device_id"`
	DestinationDeviceID           string `json:"destination_device_id"`
	DestinationResourceID         string `json:"destination_resource_id"`
	DestinationImportedResourceID string `json:"destination_imported_resource_id"`
	// DestinationKubernetesClusterID asks about a cluster through one of its
	// active replicas (K1d d4c).
	DestinationKubernetesClusterID string `json:"destination_kubernetes_cluster_id"`
	// DestinationAddress asks about an address inside a Site.
	DestinationAddress string `json:"destination_address"`
	Protocol           string `json:"protocol"`
	DestinationPort    *int   `json:"destination_port"`
}

type explainPolicyResponse struct {
	Data          explainedPolicy `json:"data"`
	CorrelationID string          `json:"correlation_id"`
}

type explainedPolicy struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	// DenyReason is present exactly when Decision is deny.
	DenyReason *string                 `json:"deny_reason,omitempty"`
	Action     explainedPolicyAction   `json:"action"`
	Subject    explainedPolicySubject  `json:"subject"`
	Target     explainedPolicyTarget   `json:"target"`
	Evidence   explainedPolicyEvidence `json:"evidence"`
	Paths      []explainedPolicyPath   `json:"paths"`
	Truncated  bool                    `json:"truncated"`
	Context    explainedPolicyContext  `json:"context"`
}

type explainedPolicyAction struct {
	Name            string `json:"name"`
	Protocol        string `json:"protocol"`
	DestinationPort *int   `json:"destination_port,omitempty"`
}

type explainedPolicySubject struct {
	DeviceID string `json:"device_id"`
}

type explainedPolicyTarget struct {
	DeviceID           string `json:"device_id,omitempty"`
	ResourceID         string `json:"resource_id,omitempty"`
	ImportedResourceID string `json:"imported_resource_id,omitempty"`
	// KubernetesClusterID names the cluster asked about; DeviceID is then
	// the replica its answer came through.
	KubernetesClusterID string `json:"kubernetes_cluster_id,omitempty"`
	Address             string `json:"address,omitempty"`
	// SiteID names the Site that holds Address, when one does.
	SiteID string `json:"site_id,omitempty"`
	// ExitPoolID names the Exit Pool an Internet address no Site holds is
	// reached through, when a pool's rules grant it.
	ExitPoolID string `json:"exit_pool_id,omitempty"`
}

type explainedPolicyEvidence struct {
	NetworkRevision       int64  `json:"network_revision"`
	InventoryRevision     int64  `json:"inventory_revision"`
	GroupRevision         int64  `json:"group_revision"`
	PolicyRevision        int64  `json:"policy_revision"`
	DNSRevision           int64  `json:"dns_revision"`
	RouteRevision         int64  `json:"route_revision"`
	SharingRevision       int64  `json:"sharing_revision"`
	IsolationGeneration   int64  `json:"isolation_generation"`
	HasActiveRelease      bool   `json:"has_active_release"`
	ReleaseID             string `json:"release_id,omitempty"`
	CompilerFormatVersion int    `json:"compiler_format_version,omitempty"`
	SemanticHash          string `json:"semantic_hash,omitempty"`
}

type explainedPolicyPath struct {
	ProjectionID   string `json:"projection_id"`
	AccessRuleID   string `json:"access_rule_id"`
	SourceDeviceID string `json:"source_device_id"`
	// DestinationDeviceID is absent for a path to a shared Device, which names
	// DestinationImportedResourceID and TrustContractID instead.
	DestinationDeviceID           string                          `json:"destination_device_id,omitempty"`
	Protocol                      string                          `json:"protocol"`
	DestinationPortRanges         []publishPolicyPortRangeRequest `json:"destination_port_ranges"`
	SelectorKind                  string                          `json:"selector_kind"`
	DestinationResourceID         string                          `json:"destination_resource_id,omitempty"`
	DestinationGroupID            string                          `json:"destination_resource_group_id,omitempty"`
	DestinationImportedResourceID string                          `json:"destination_imported_resource_id,omitempty"`
	TrustContractID               string                          `json:"trust_contract_id,omitempty"`
	// Set when the path comes from a rule that selects Device Groups.
	SourceDeviceGroupID      string `json:"source_device_group_id,omitempty"`
	DestinationDeviceGroupID string `json:"destination_device_group_id,omitempty"`
	// A rule to a Kubernetes cluster names the cluster, not its own group.
	DestinationKubernetesClusterID string `json:"destination_kubernetes_cluster_id,omitempty"`
	// KubernetesGroups are the groups the rule to the cluster grants; absent
	// when the reader may not read the policy's rules.
	KubernetesGroups       []string `json:"kubernetes_groups,omitempty"`
	SourceIdentityGroupID  string   `json:"source_identity_group_id,omitempty"`
	SourceDeviceTagID      string   `json:"source_device_tag_id,omitempty"`
	DestinationDeviceTagID string   `json:"destination_device_tag_id,omitempty"`
	// Set for a path to a Site: the Site and the prefixes the rule grants.
	DestinationSiteID   string   `json:"destination_site_id,omitempty"`
	DestinationPrefixes []string `json:"destination_prefixes,omitempty"`
	// Set for a path to an Exit Pool.
	DestinationExitPoolID string `json:"destination_exit_pool_id,omitempty"`
}

type accessGraphExplainPath struct {
	workspaceID string
	networkID   string
}

func parseAccessGraphExplainPath(request *http.Request) (accessGraphExplainPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawQuery != "" || request.URL.RawPath != "" {
		return accessGraphExplainPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) != 9 || segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "workspaces" || segments[4] != "networks" ||
		segments[6] != "access-graph" || segments[7] != "actions" || segments[8] != "explain" {
		return accessGraphExplainPath{}, false
	}
	return accessGraphExplainPath{workspaceID: segments[3], networkID: segments[5]}, true
}

type managementAccessGraphRequest struct {
	response      http.ResponseWriter
	request       *http.Request
	correlationID publicid.ID
	path          accessGraphExplainPath
	session       accountsession.Session
	browser       *browserManagementAdmission
}

func (handler *ManagementHandler) explainPolicy(
	ctx context.Context,
	input managementAccessGraphRequest,
) string {
	params, clusterID, decodeErr := decodeAccessGraphQuery(input.response, input.request, input.path)
	if decodeErr != nil {
		writeManagementError(ctx, handler.logger, input.response, input.correlationID, *decodeErr)
		return decodeErr.Code
	}
	if err := input.browser.validate(ctx); err != nil {
		classified := classifyAuthenticationError(err)
		writeManagementError(ctx, handler.logger, input.response, input.correlationID, classified)
		return classified.Code
	}
	if clusterID.IsValid() {
		replicaID, replicaErr := handler.explainedKubernetesReplica(ctx, input.session, params.Scope, clusterID)
		if replicaErr != nil {
			writeManagementError(ctx, handler.logger, input.response, input.correlationID, *replicaErr)
			return replicaErr.Code
		}
		params.DestinationNodeID = replicaID
	}
	query, err := accessgraph.NewQuery(params)
	if err != nil {
		apiError := invalidManagementRequest()
		writeManagementError(ctx, handler.logger, input.response, input.correlationID, *apiError)
		return apiError.Code
	}
	result, err := handler.policyExplainer.Explain(ctx, input.session, query)
	if err != nil {
		classified := classifyAccessGraphError(err)
		writeManagementError(ctx, handler.logger, input.response, input.correlationID, classified)
		return classified.Code
	}
	if !result.IsValid() || result.Query() != query {
		apiError := managementError{
			Status: http.StatusInternalServerError, Code: "internal_failure",
			Message: "the request could not be completed",
		}
		writeManagementError(ctx, handler.logger, input.response, input.correlationID, apiError)
		return apiError.Code
	}

	snapshot := result.Snapshot()
	explained := newExplainedPolicy(query, result, handler.dnsSuffix)
	if clusterID.IsValid() {
		explained.Target.KubernetesClusterID = clusterID.String()
	}
	input.response.Header().Set("ETag", strongVersionETag(snapshot.PolicyRevision()))
	input.response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, input.response, http.StatusOK, explainPolicyResponse{
		Data:          explained,
		CorrelationID: input.correlationID.String(),
	})
	return "success"
}

// explainedKubernetesReplica returns the replica a question about a cluster
// is answered through: its active replica with the lowest ordinal (K1d d4c,
// Q179).
func (handler *ManagementHandler) explainedKubernetesReplica(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	clusterID kubecluster.ID,
) (node.ID, *managementError) {
	if handler.kubernetesClusters == nil {
		return node.ID{}, &managementError{
			Status: http.StatusServiceUnavailable, Code: "operation_unavailable",
			Message: "the operation is temporarily unavailable", Retryable: true,
		}
	}
	replica, err := handler.kubernetesClusters.ReadExplainReplica(ctx, session, scope, clusterID)
	if err != nil {
		classified := classifyKubernetesClusterError(err)
		return node.ID{}, &classified
	}
	return replica, nil
}

// decodeAccessGraphQuery reads an explain request; a cluster destination
// leaves DestinationNodeID to the replica chosen once the caller is admitted.
func decodeAccessGraphQuery(
	response http.ResponseWriter,
	request *http.Request,
	path accessGraphExplainPath,
) (accessgraph.QueryParams, kubecluster.ID, *managementError) {
	workspaceID, err := workspace.ParseID(path.workspaceID)
	if err != nil {
		return accessgraph.QueryParams{}, kubecluster.ID{}, invalidManagementRequest()
	}
	networkID, err := network.ParseID(path.networkID)
	if err != nil {
		return accessgraph.QueryParams{}, kubecluster.ID{}, invalidManagementRequest()
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil || request.Body == nil ||
		!validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return accessgraph.QueryParams{}, kubecluster.ID{}, invalidManagementRequest()
	}
	var body explainPolicyRequest
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, maximumAccessGraphBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || ensureJSONEnd(decoder) != nil {
		return accessgraph.QueryParams{}, kubecluster.ID{}, invalidManagementRequest()
	}
	sourceID, err := node.ParseID(body.SourceDeviceID)
	if err != nil {
		return accessgraph.QueryParams{}, kubecluster.ID{}, invalidManagementRequest()
	}
	var destinationID node.ID
	if body.DestinationDeviceID != "" {
		destinationID, err = node.ParseID(body.DestinationDeviceID)
		if err != nil {
			return accessgraph.QueryParams{}, kubecluster.ID{}, invalidManagementRequest()
		}
	}
	var destinationResourceID resource.ID
	if body.DestinationResourceID != "" {
		destinationResourceID, err = resource.ParseID(body.DestinationResourceID)
		if err != nil {
			return accessgraph.QueryParams{}, kubecluster.ID{}, invalidManagementRequest()
		}
	}
	var destinationImportedResourceID sharing.ImportedResourceID
	if body.DestinationImportedResourceID != "" {
		destinationImportedResourceID, err = sharing.ParseImportedResourceID(
			body.DestinationImportedResourceID,
		)
		if err != nil {
			return accessgraph.QueryParams{}, kubecluster.ID{}, invalidManagementRequest()
		}
	}
	var destinationAddress netip.Addr
	if body.DestinationAddress != "" {
		destinationAddress, err = netip.ParseAddr(body.DestinationAddress)
		if err != nil {
			return accessgraph.QueryParams{}, kubecluster.ID{}, invalidManagementRequest()
		}
	}
	protocol := parsePolicyProtocol(body.Protocol)
	var destinationPort int
	if protocol == policy.ProtocolICMP {
		if body.DestinationPort != nil {
			return accessgraph.QueryParams{}, kubecluster.ID{}, invalidManagementRequest()
		}
	} else {
		if body.DestinationPort == nil || *body.DestinationPort < 1 ||
			*body.DestinationPort > math.MaxUint16 {
			return accessgraph.QueryParams{}, kubecluster.ID{}, invalidManagementRequest()
		}
		destinationPort = *body.DestinationPort
	}
	params := accessgraph.QueryParams{
		Scope: scope, SourceNodeID: sourceID, DestinationNodeID: destinationID,
		DestinationResourceID:         destinationResourceID,
		DestinationImportedResourceID: destinationImportedResourceID,
		DestinationAddress:            destinationAddress,
		Protocol:                      protocol,
		DestinationPort:               uint16(destinationPort),
	}
	var clusterID kubecluster.ID
	if body.DestinationKubernetesClusterID != "" {
		// A cluster stands alone as the destination.
		clusterID, err = kubecluster.ParseID(body.DestinationKubernetesClusterID)
		if err != nil || body.DestinationDeviceID != "" || body.DestinationResourceID != "" ||
			body.DestinationImportedResourceID != "" || body.DestinationAddress != "" {
			return accessgraph.QueryParams{}, kubecluster.ID{}, invalidManagementRequest()
		}
		return params, clusterID, nil
	}
	// Checked here too, so a malformed request fails before admission.
	if _, err := accessgraph.NewQuery(params); err != nil {
		return accessgraph.QueryParams{}, kubecluster.ID{}, invalidManagementRequest()
	}
	return params, clusterID, nil
}

func classifyAccessGraphError(err error) managementError {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return managementError{
			Status: http.StatusGatewayTimeout, Code: "request_timeout",
			Message: "the request deadline expired", Retryable: true,
		}
	case errors.Is(err, accessgraph.ErrForbidden):
		return managementError{
			Status: http.StatusForbidden, Code: "forbidden",
			Message: "the request is not authorized",
		}
	case errors.Is(err, accessgraph.ErrInvalidQuery):
		return *invalidManagementRequest()
	case errors.Is(err, accessgraph.ErrInvalidSnapshot):
		return managementError{
			Status: http.StatusInternalServerError, Code: "internal_failure",
			Message: "the request could not be completed",
		}
	default:
		return managementError{
			Status: http.StatusServiceUnavailable, Code: "operation_unavailable",
			Message: "the operation is temporarily unavailable", Retryable: true,
		}
	}
}
