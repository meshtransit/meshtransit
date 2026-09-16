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
	policypublication "github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const maximumPolicyPublicationBodyBytes = 8 * 1024 * 1024

type publishPolicyRequest struct {
	Reason string                     `json:"reason"`
	Rules  []publishPolicyRuleRequest `json:"rules"`
}

type publishPolicyRuleRequest struct {
	ID                    string                          `json:"id"`
	SourceDeviceID        string                          `json:"source_device_id"`
	DestinationDeviceID   string                          `json:"destination_device_id"`
	Protocol              string                          `json:"protocol"`
	DestinationPortRanges []publishPolicyPortRangeRequest `json:"destination_port_ranges"`
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

func (handler *ManagementHandler) publishPolicy(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path policyPublishPath,
	session accountsession.Session,
) string {
	command, commandErr := decodePolicyPublicationCommand(response, request, path, session)
	if commandErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *commandErr)
		return commandErr.Code
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
			RuleCount:       len(command.Candidate().Snapshot().Rules()),
		},
		CorrelationID: correlationID.String(),
	})
	return "success"
}

func decodePolicyPublicationCommand(
	response http.ResponseWriter,
	request *http.Request,
	path policyPublishPath,
	session accountsession.Session,
) (policypublication.Command, *managementError) {
	workspaceID, err := workspace.ParseID(path.workspaceID)
	if err != nil {
		return policypublication.Command{}, invalidManagementRequest()
	}
	networkID, err := network.ParseID(path.networkID)
	if err != nil {
		return policypublication.Command{}, invalidManagementRequest()
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return policypublication.Command{}, invalidManagementRequest()
	}
	baseRevision, preconditionErr := parsePolicyIfMatch(request.Header.Values("If-Match"))
	if preconditionErr != nil {
		return policypublication.Command{}, preconditionErr
	}
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return policypublication.Command{}, invalidManagementRequest()
	}
	var body publishPolicyRequest
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, maximumPolicyPublicationBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || ensureJSONEnd(decoder) != nil || body.Rules == nil {
		return policypublication.Command{}, invalidManagementRequest()
	}
	reason, err := policypublication.NewAuditReason(body.Reason)
	if err != nil || len(body.Rules) > policy.MaximumRules {
		return policypublication.Command{}, invalidManagementRequest()
	}
	rules := make([]policy.Rule, len(body.Rules))
	for index, input := range body.Rules {
		rule, ruleErr := decodePolicyRule(scope, input)
		if ruleErr != nil {
			return policypublication.Command{}, invalidManagementRequest()
		}
		rules[index] = rule
	}
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: scope, Revision: baseRevision + 1, Rules: rules,
	})
	if err != nil {
		return policypublication.Command{}, invalidManagementRequest()
	}
	candidate, err := policypublication.NewCandidate(snapshot, 1)
	if err != nil {
		return policypublication.Command{}, invalidManagementRequest()
	}
	command, err := policypublication.NewManagementCommand(policypublication.ManagementCommandParams{
		Candidate: candidate, BasePolicyRevision: baseRevision,
		AccountSession: session, AuditReason: reason,
	})
	if err != nil {
		return policypublication.Command{}, invalidManagementRequest()
	}
	return command, nil
}

func decodePolicyRule(scope network.Scope, input publishPolicyRuleRequest) (policy.Rule, error) {
	if input.DestinationPortRanges == nil {
		return policy.Rule{}, policy.ErrInvalidRule
	}
	ruleID, err := policy.ParseRuleID(input.ID)
	if err != nil {
		return policy.Rule{}, err
	}
	sourceID, err := node.ParseID(input.SourceDeviceID)
	if err != nil {
		return policy.Rule{}, err
	}
	destinationID, err := node.ParseID(input.DestinationDeviceID)
	if err != nil {
		return policy.Rule{}, err
	}
	protocol := parsePolicyProtocol(input.Protocol)
	if !protocol.IsValid() {
		return policy.Rule{}, policy.ErrInvalidRule
	}
	portRanges := make([]policy.PortRange, len(input.DestinationPortRanges))
	for index, inputRange := range input.DestinationPortRanges {
		if inputRange.First <= 0 || inputRange.First > math.MaxUint16 ||
			inputRange.Last <= 0 || inputRange.Last > math.MaxUint16 {
			return policy.Rule{}, policy.ErrInvalidPortRange
		}
		portRange, rangeErr := policy.NewPortRange(uint16(inputRange.First), uint16(inputRange.Last))
		if rangeErr != nil {
			return policy.Rule{}, rangeErr
		}
		portRanges[index] = portRange
	}
	return policy.NewRule(policy.RuleParams{
		ID: ruleID, Scope: scope, SourceNodeID: sourceID, DestinationNodeID: destinationID,
		Protocol: protocol, DestinationPortRanges: portRanges,
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

func resultMatchesPolicyPublication(
	result policypublication.Result,
	command policypublication.Command,
) bool {
	return result.IsValid() && result.Scope() == command.Candidate().Snapshot().Scope() &&
		result.PolicyRevision() == command.BasePolicyRevision()+1 &&
		result.SemanticHash() == command.Candidate().SemanticHash()
}
