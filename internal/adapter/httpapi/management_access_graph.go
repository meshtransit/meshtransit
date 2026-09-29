package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strings"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/sharing"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const maximumAccessGraphBodyBytes = 64 * 1024

type explainPolicyRequest struct {
	SourceDeviceID                string `json:"source_device_id"`
	DestinationDeviceID           string `json:"destination_device_id"`
	DestinationResourceID         string `json:"destination_resource_id"`
	DestinationImportedResourceID string `json:"destination_imported_resource_id"`
	Protocol                      string `json:"protocol"`
	DestinationPort               *int   `json:"destination_port"`
}

type explainPolicyResponse struct {
	Data          explainedPolicy `json:"data"`
	CorrelationID string          `json:"correlation_id"`
}

type explainedPolicy struct {
	Decision  string                  `json:"decision"`
	Reason    string                  `json:"reason"`
	Action    explainedPolicyAction   `json:"action"`
	Subject   explainedPolicySubject  `json:"subject"`
	Target    explainedPolicyTarget   `json:"target"`
	Evidence  explainedPolicyEvidence `json:"evidence"`
	Paths     []explainedPolicyPath   `json:"paths"`
	Truncated bool                    `json:"truncated"`
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
	ProjectionID          string                          `json:"projection_id"`
	AccessRuleID          string                          `json:"access_rule_id"`
	SourceDeviceID        string                          `json:"source_device_id"`
	DestinationDeviceID   string                          `json:"destination_device_id"`
	Protocol              string                          `json:"protocol"`
	DestinationPortRanges []publishPolicyPortRangeRequest `json:"destination_port_ranges"`
	SelectorKind          string                          `json:"selector_kind"`
	DestinationResourceID string                          `json:"destination_resource_id,omitempty"`
	DestinationGroupID    string                          `json:"destination_resource_group_id,omitempty"`
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
	query, decodeErr := decodeAccessGraphQuery(input.response, input.request, input.path)
	if decodeErr != nil {
		writeManagementError(ctx, handler.logger, input.response, input.correlationID, *decodeErr)
		return decodeErr.Code
	}
	if err := input.browser.validate(ctx); err != nil {
		classified := classifyAuthenticationError(err)
		writeManagementError(ctx, handler.logger, input.response, input.correlationID, classified)
		return classified.Code
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
	releaseID, compilerFormat, semanticHash, hasActiveRelease := snapshot.ActiveRelease()
	evidence := explainedPolicyEvidence{
		NetworkRevision: snapshot.NetworkRevision(), InventoryRevision: snapshot.InventoryRevision(),
		GroupRevision: snapshot.GroupRevision(), PolicyRevision: snapshot.PolicyRevision(),
		DNSRevision: snapshot.DNSRevision(), RouteRevision: snapshot.RouteRevision(),
		SharingRevision: snapshot.SharingRevision(), IsolationGeneration: snapshot.IsolationGeneration(),
		HasActiveRelease: hasActiveRelease,
	}
	if hasActiveRelease {
		hash := semanticHash.Bytes()
		evidence.ReleaseID = releaseID.String()
		evidence.CompilerFormatVersion = compilerFormat
		evidence.SemanticHash = hex.EncodeToString(hash[:])
	}
	action := explainedPolicyAction{Name: "network.connect", Protocol: query.Protocol().String()}
	if query.Protocol() != policy.ProtocolICMP {
		port := int(query.DestinationPort())
		action.DestinationPort = &port
	}
	target := explainedPolicyTarget{}
	if query.DestinationNodeID().IsValid() {
		target.DeviceID = query.DestinationNodeID().String()
	} else if query.DestinationResourceID().IsValid() {
		target.ResourceID = query.DestinationResourceID().String()
	} else {
		target.ImportedResourceID = query.DestinationImportedResourceID().String()
	}
	paths := make([]explainedPolicyPath, len(result.Paths()))
	for index, path := range result.Paths() {
		ranges := path.DestinationPortRanges()
		ports := make([]publishPolicyPortRangeRequest, len(ranges))
		for rangeIndex, portRange := range ranges {
			ports[rangeIndex] = publishPolicyPortRangeRequest{
				First: int(portRange.First()), Last: int(portRange.Last()),
			}
		}
		paths[index] = explainedPolicyPath{
			ProjectionID: path.ProjectionID().String(), AccessRuleID: path.RuleID().String(),
			SourceDeviceID: path.SourceNodeID().String(), DestinationDeviceID: path.DestinationNodeID().String(),
			Protocol: path.Protocol().String(), DestinationPortRanges: ports,
			SelectorKind: path.SelectorKind().String(),
		}
		if path.DestinationResourceID().IsValid() {
			paths[index].DestinationResourceID = path.DestinationResourceID().String()
		}
		if path.DestinationGroupID().IsValid() {
			paths[index].DestinationGroupID = path.DestinationGroupID().String()
		}
	}
	input.response.Header().Set("ETag", strongVersionETag(snapshot.PolicyRevision()))
	input.response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, input.response, http.StatusOK, explainPolicyResponse{
		Data: explainedPolicy{
			Decision: result.Decision().String(), Reason: result.Reason().String(),
			Action: action, Subject: explainedPolicySubject{DeviceID: query.SourceNodeID().String()},
			Target: target, Evidence: evidence, Paths: paths, Truncated: result.Truncated(),
		},
		CorrelationID: input.correlationID.String(),
	})
	return "success"
}

func decodeAccessGraphQuery(
	response http.ResponseWriter,
	request *http.Request,
	path accessGraphExplainPath,
) (accessgraph.Query, *managementError) {
	workspaceID, err := workspace.ParseID(path.workspaceID)
	if err != nil {
		return accessgraph.Query{}, invalidManagementRequest()
	}
	networkID, err := network.ParseID(path.networkID)
	if err != nil {
		return accessgraph.Query{}, invalidManagementRequest()
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil || request.Body == nil ||
		!validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return accessgraph.Query{}, invalidManagementRequest()
	}
	var body explainPolicyRequest
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, maximumAccessGraphBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || ensureJSONEnd(decoder) != nil {
		return accessgraph.Query{}, invalidManagementRequest()
	}
	sourceID, err := node.ParseID(body.SourceDeviceID)
	if err != nil {
		return accessgraph.Query{}, invalidManagementRequest()
	}
	var destinationID node.ID
	if body.DestinationDeviceID != "" {
		destinationID, err = node.ParseID(body.DestinationDeviceID)
		if err != nil {
			return accessgraph.Query{}, invalidManagementRequest()
		}
	}
	var destinationResourceID resource.ID
	if body.DestinationResourceID != "" {
		destinationResourceID, err = resource.ParseID(body.DestinationResourceID)
		if err != nil {
			return accessgraph.Query{}, invalidManagementRequest()
		}
	}
	var destinationImportedResourceID sharing.ImportedResourceID
	if body.DestinationImportedResourceID != "" {
		destinationImportedResourceID, err = sharing.ParseImportedResourceID(
			body.DestinationImportedResourceID,
		)
		if err != nil {
			return accessgraph.Query{}, invalidManagementRequest()
		}
	}
	protocol := parsePolicyProtocol(body.Protocol)
	var destinationPort int
	if protocol == policy.ProtocolICMP {
		if body.DestinationPort != nil {
			return accessgraph.Query{}, invalidManagementRequest()
		}
	} else {
		if body.DestinationPort == nil || *body.DestinationPort < 1 ||
			*body.DestinationPort > math.MaxUint16 {
			return accessgraph.Query{}, invalidManagementRequest()
		}
		destinationPort = *body.DestinationPort
	}
	query, err := accessgraph.NewQuery(accessgraph.QueryParams{
		Scope: scope, SourceNodeID: sourceID, DestinationNodeID: destinationID,
		DestinationResourceID:         destinationResourceID,
		DestinationImportedResourceID: destinationImportedResourceID,
		Protocol:                      protocol,
		DestinationPort:               uint16(destinationPort),
	})
	if err != nil {
		return accessgraph.Query{}, invalidManagementRequest()
	}
	return query, nil
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
