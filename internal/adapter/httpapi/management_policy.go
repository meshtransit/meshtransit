package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strings"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/compilation"
	policypublication "github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/sharing"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const maximumPolicyPublicationBodyBytes = 8 * 1024 * 1024

type publishPolicyRequest struct {
	Reason             string                     `json:"reason"`
	ApprovalEvidenceID json.RawMessage            `json:"approval_evidence_id"`
	Rules              []publishPolicyRuleRequest `json:"rules"`
}

type publishPolicyRuleRequest struct {
	ID                            string                          `json:"id"`
	SourceDeviceID                string                          `json:"source_device_id"`
	DestinationDeviceID           string                          `json:"destination_device_id"`
	DestinationResourceID         string                          `json:"destination_resource_id"`
	DestinationGroupID            string                          `json:"destination_resource_group_id"`
	DestinationImportedResourceID string                          `json:"destination_imported_resource_id"`
	Protocol                      string                          `json:"protocol"`
	DestinationPortRanges         []publishPolicyPortRangeRequest `json:"destination_port_ranges"`
}

type publishPolicyPortRangeRequest struct {
	First int `json:"first"`
	Last  int `json:"last"`
}

type publishPolicyResponse struct {
	Data          publishedPolicy `json:"data"`
	CorrelationID string          `json:"correlation_id"`
}

type publishedPolicy struct {
	ReleaseID       string `json:"release_id"`
	PolicyRevision  int64  `json:"policy_revision"`
	NetworkRevision int64  `json:"network_revision"`
	SemanticHash    string `json:"semantic_hash"`
	RuleCount       int    `json:"rule_count"`
}

type policyPublishPath struct {
	workspaceID string
	networkID   string
}

func parsePolicyPublishPath(request *http.Request) (policyPublishPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawQuery != "" || request.URL.RawPath != "" {
		return policyPublishPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) != 9 || segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "workspaces" || segments[4] != "networks" ||
		segments[6] != "policy" || segments[7] != "actions" || segments[8] != "publish" {
		return policyPublishPath{}, false
	}
	return policyPublishPath{workspaceID: segments[3], networkID: segments[5]}, true
}

type managementPolicyRequest struct {
	response      http.ResponseWriter
	request       *http.Request
	correlationID publicid.ID
	path          policyPublishPath
	session       accountsession.Session
	browser       *browserManagementAdmission
}

func (handler *ManagementHandler) publishPolicy(ctx context.Context, input managementPolicyRequest) string {
	response, request, correlationID := input.response, input.request, input.correlationID
	path, session := input.path, input.session
	decoded, decodeErr := decodePolicyPublicationRequest(response, request, path)
	if decodeErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *decodeErr)
		return decodeErr.Code
	}
	if err := input.browser.validate(ctx); err != nil {
		classified := classifyAuthenticationError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	candidate, err := handler.policyCompiler.Compile(ctx, session, decoded.request)
	if err != nil {
		classified := classifyPolicyCompilationError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	command, err := policypublication.NewManagementCommand(policypublication.ManagementCommandParams{
		Candidate: candidate, BasePolicyRevision: decoded.baseRevision,
		AccountSession: session, ApprovalEvidenceID: decoded.approvalEvidenceID,
		AuditReason: decoded.reason,
	})
	if err != nil {
		apiError := invalidManagementRequest()
		writeManagementError(ctx, handler.logger, response, correlationID, *apiError)
		return apiError.Code
	}
	result, err := handler.policies.Publish(ctx, command)
	if err != nil {
		classified := classifyPolicyPublicationError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	if !resultMatchesPolicyPublication(result, command) {
		apiError := managementError{
			Status: http.StatusInternalServerError, Code: "internal_failure",
			Message: "the request could not be completed",
		}
		writeManagementError(ctx, handler.logger, response, correlationID, apiError)
		return apiError.Code
	}

	semanticHash := result.SemanticHash().Bytes()
	response.Header().Set("ETag", strongVersionETag(result.PolicyRevision()))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, publishPolicyResponse{
		Data: publishedPolicy{
			ReleaseID:       result.ReleaseID().String(),
			PolicyRevision:  result.PolicyRevision(),
			NetworkRevision: result.NetworkRevision(),
			SemanticHash:    hex.EncodeToString(semanticHash[:]),
			RuleCount:       len(command.Candidate().Snapshot().Rules()) + len(command.Candidate().ImportedResourceDestinations()),
		},
		CorrelationID: correlationID.String(),
	})
	return "success"
}

type decodedPolicyPublication struct {
	request            compilation.Request
	baseRevision       int64
	reason             policypublication.AuditReason
	approvalEvidenceID policypublication.ApprovalEvidenceID
}

func decodePolicyPublicationRequest(
	response http.ResponseWriter,
	request *http.Request,
	path policyPublishPath,
) (decodedPolicyPublication, *managementError) {
	workspaceID, err := workspace.ParseID(path.workspaceID)
	if err != nil {
		return decodedPolicyPublication{}, invalidManagementRequest()
	}
	networkID, err := network.ParseID(path.networkID)
	if err != nil {
		return decodedPolicyPublication{}, invalidManagementRequest()
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return decodedPolicyPublication{}, invalidManagementRequest()
	}
	baseRevision, preconditionErr := parsePolicyIfMatch(request.Header.Values("If-Match"))
	if preconditionErr != nil {
		return decodedPolicyPublication{}, preconditionErr
	}
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return decodedPolicyPublication{}, invalidManagementRequest()
	}
	var body publishPolicyRequest
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, maximumPolicyPublicationBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || ensureJSONEnd(decoder) != nil || body.Rules == nil {
		return decodedPolicyPublication{}, invalidManagementRequest()
	}
	reason, err := policypublication.NewAuditReason(body.Reason)
	if err != nil || len(body.Rules) > policy.MaximumRules {
		return decodedPolicyPublication{}, invalidManagementRequest()
	}
	rules := make([]compilation.RuleIntent, len(body.Rules))
	for index, input := range body.Rules {
		rule, ruleErr := decodePolicyRuleIntent(scope, input)
		if ruleErr != nil {
			return decodedPolicyPublication{}, invalidManagementRequest()
		}
		rules[index] = rule
	}
	var approvalEvidenceID policypublication.ApprovalEvidenceID
	if len(body.ApprovalEvidenceID) > 0 {
		var encodedEvidenceID string
		if err := json.Unmarshal(body.ApprovalEvidenceID, &encodedEvidenceID); err != nil {
			return decodedPolicyPublication{}, invalidManagementRequest()
		}
		approvalEvidenceID, err = policypublication.ParseApprovalEvidenceID(encodedEvidenceID)
		if err != nil {
			return decodedPolicyPublication{}, invalidManagementRequest()
		}
	}
	compilationRequest, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: baseRevision + 1, Rules: rules,
	})
	if err != nil {
		return decodedPolicyPublication{}, invalidManagementRequest()
	}
	return decodedPolicyPublication{
		request: compilationRequest, baseRevision: baseRevision, reason: reason,
		approvalEvidenceID: approvalEvidenceID,
	}, nil
}

func decodePolicyRuleIntent(
	scope network.Scope,
	input publishPolicyRuleRequest,
) (compilation.RuleIntent, error) {
	if input.DestinationPortRanges == nil {
		return compilation.RuleIntent{}, policy.ErrInvalidRule
	}
	ruleID, err := policy.ParseRuleID(input.ID)
	if err != nil {
		return compilation.RuleIntent{}, err
	}
	sourceID, err := node.ParseID(input.SourceDeviceID)
	if err != nil {
		return compilation.RuleIntent{}, err
	}
	var destinationID node.ID
	if input.DestinationDeviceID != "" {
		destinationID, err = node.ParseID(input.DestinationDeviceID)
		if err != nil {
			return compilation.RuleIntent{}, err
		}
	}
	var destinationResourceID resource.ID
	if input.DestinationResourceID != "" {
		destinationResourceID, err = resource.ParseID(input.DestinationResourceID)
		if err != nil {
			return compilation.RuleIntent{}, err
		}
	}
	var destinationGroupID resource.GroupID
	if input.DestinationGroupID != "" {
		destinationGroupID, err = resource.ParseGroupID(input.DestinationGroupID)
		if err != nil {
			return compilation.RuleIntent{}, err
		}
	}
	var destinationImportedResourceID sharing.ImportedResourceID
	if input.DestinationImportedResourceID != "" {
		destinationImportedResourceID, err = sharing.ParseImportedResourceID(
			input.DestinationImportedResourceID,
		)
		if err != nil {
			return compilation.RuleIntent{}, err
		}
	}
	protocol := parsePolicyProtocol(input.Protocol)
	if !protocol.IsValid() {
		return compilation.RuleIntent{}, policy.ErrInvalidRule
	}
	portRanges := make([]policy.PortRange, len(input.DestinationPortRanges))
	for index, inputRange := range input.DestinationPortRanges {
		if inputRange.First <= 0 || inputRange.First > math.MaxUint16 ||
			inputRange.Last <= 0 || inputRange.Last > math.MaxUint16 {
			return compilation.RuleIntent{}, policy.ErrInvalidPortRange
		}
		portRange, rangeErr := policy.NewPortRange(uint16(inputRange.First), uint16(inputRange.Last))
		if rangeErr != nil {
			return compilation.RuleIntent{}, rangeErr
		}
		portRanges[index] = portRange
	}
	return compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: ruleID, Scope: scope, SourceNodeID: sourceID, DestinationNodeID: destinationID,
		DestinationResourceID: destinationResourceID, DestinationGroupID: destinationGroupID,
		DestinationImportedResourceID: destinationImportedResourceID,
		Protocol:                      protocol, DestinationPortRanges: portRanges,
	})
}

func parsePolicyProtocol(value string) policy.Protocol {
	switch value {
	case "tcp":
		return policy.ProtocolTCP
	case "udp":
		return policy.ProtocolUDP
	case "icmp":
		return policy.ProtocolICMP
	default:
		return policy.ProtocolUnknown
	}
}

func parsePolicyIfMatch(values []string) (int64, *managementError) {
	if len(values) == 0 {
		return 0, &managementError{
			Status: http.StatusPreconditionRequired, Code: "precondition_required",
			Message: "a strong Policy revision precondition is required",
		}
	}
	revision, apiError := parseIfMatch(values)
	if apiError != nil && apiError.Status == http.StatusPreconditionRequired {
		apiError.Message = "a strong Policy revision precondition is required"
	}
	return revision, apiError
}

func classifyPolicyPublicationError(err error) managementError {
	if violation, ok := guardrailViolation(err); ok {
		return violation
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return managementError{
			Status: http.StatusGatewayTimeout, Code: "request_timeout",
			Message: "the request deadline expired", Retryable: true,
		}
	case errors.Is(err, policypublication.ErrForbidden):
		return managementError{
			Status: http.StatusForbidden, Code: "forbidden",
			Message: "the request is not authorized",
		}
	case errors.Is(err, policypublication.ErrConflict):
		return managementError{
			Status: http.StatusPreconditionFailed, Code: "precondition_failed",
			Message: "the Policy revision precondition is stale",
		}
	case errors.Is(err, policypublication.ErrApprovalRequired),
		errors.Is(err, policypublication.ErrApprovalUnavailable):
		return managementError{
			Status: http.StatusConflict, Code: "approval_conflict",
			Message: "approval evidence is stale, expired, consumed, or unavailable",
		}
	case errors.Is(err, context.Canceled), errors.Is(err, policypublication.ErrRetryableTransaction),
		errors.Is(err, policypublication.ErrCommitOutcomeUnknown),
		errors.Is(err, policypublication.ErrRetryExhausted):
		return managementError{
			Status: http.StatusServiceUnavailable, Code: "operation_unavailable",
			Message: "the operation is temporarily unavailable", Retryable: true,
		}
	default:
		return managementError{
			Status: http.StatusInternalServerError, Code: "internal_failure",
			Message: "the request could not be completed",
		}
	}
}

func classifyPolicyCompilationError(err error) managementError {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return managementError{
			Status: http.StatusGatewayTimeout, Code: "request_timeout",
			Message: "the request deadline expired", Retryable: true,
		}
	case errors.Is(err, compilation.ErrForbidden):
		return managementError{
			Status: http.StatusForbidden, Code: "forbidden",
			Message: "the request is not authorized",
		}
	case errors.Is(err, compilation.ErrResourceConflict):
		return managementError{
			Status: http.StatusConflict, Code: "resource_conflict",
			Message: "a Resource destination is not active or changed",
		}
	case errors.Is(err, compilation.ErrInvalidRequest):
		return *invalidManagementRequest()
	default:
		return managementError{
			Status: http.StatusServiceUnavailable, Code: "operation_unavailable",
			Message: "the operation is temporarily unavailable", Retryable: true,
		}
	}
}

func resultMatchesPolicyPublication(
	result policypublication.Result,
	command policypublication.Command,
) bool {
	return result.IsValid() && result.Scope() == command.Candidate().Snapshot().Scope() &&
		result.PolicyRevision() == command.BasePolicyRevision()+1 &&
		result.SemanticHash() == command.Candidate().SemanticHash()
}
