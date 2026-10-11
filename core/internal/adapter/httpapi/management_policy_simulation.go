package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

type simulatePolicyRequest struct {
	Rules []publishPolicyRuleRequest `json:"rules"`
}

type simulatePolicyResponse struct {
	Data          simulatedPolicy `json:"data"`
	CorrelationID string          `json:"correlation_id"`
}

type simulatedPolicy struct {
	Baseline simulatedPolicyBaseline `json:"baseline"`
	Proposed simulatedPolicyProposed `json:"proposed"`
	Impact   simulatedPolicyImpact   `json:"impact"`
	// PeerEstimate warns when the proposed policy would put more peers in
	// a Device's map than Core sends.
	PeerEstimate peerEstimateBody `json:"peer_estimate"`
}

// Peer thresholds the Console warns at: a map grows heavy past
// peerEstimateWarning peers, and Core sends at most mapsession's default
// limit (a deployment may lower MESHTRANSIT_CONTROL_MAP_PEER_LIMIT).
const peerEstimateWarning = 5_000

type peerEstimateBody struct {
	// MaxPeers is the largest number of peers one Device would see; an
	// upper bound unless Exact.
	MaxPeers           int  `json:"max_peers"`
	Exact              bool `json:"exact"`
	Warning            int  `json:"warning"`
	Limit              int  `json:"limit"`
	DevicesOverWarning int  `json:"devices_over_warning"`
	DevicesOverLimit   int  `json:"devices_over_limit"`
}

func encodePeerEstimate(peers simulation.PeerEstimate) peerEstimateBody {
	return peerEstimateBody{MaxPeers: peers.MaxPeers(), Exact: peers.Exact(), Warning: peerEstimateWarning,
		Limit: mapsession.DefaultPeerLimit, DevicesOverWarning: peers.DevicesOver(peerEstimateWarning),
		DevicesOverLimit: peers.DevicesOver(mapsession.DefaultPeerLimit)}
}

type simulatedPolicyRevisionVector struct {
	NetworkRevision     int64 `json:"network_revision"`
	InventoryRevision   int64 `json:"inventory_revision"`
	GroupRevision       int64 `json:"group_revision"`
	PolicyRevision      int64 `json:"policy_revision"`
	DNSRevision         int64 `json:"dns_revision"`
	RouteRevision       int64 `json:"route_revision"`
	SharingRevision     int64 `json:"sharing_revision"`
	IsolationGeneration int64 `json:"isolation_generation"`
}

type simulatedPolicyBaseline struct {
	RevisionVector        simulatedPolicyRevisionVector `json:"revision_vector"`
	HasActiveRelease      bool                          `json:"has_active_release"`
	ReleaseID             string                        `json:"release_id,omitempty"`
	CompilerFormatVersion int                           `json:"compiler_format_version"`
	SemanticHash          string                        `json:"semantic_hash"`
}

type simulatedPolicyProposed struct {
	RevisionVector        simulatedPolicyRevisionVector `json:"revision_vector"`
	CompilerFormatVersion int                           `json:"compiler_format_version"`
	SemanticHash          string                        `json:"semantic_hash"`
	RuleCount             int                           `json:"rule_count"`
}

type simulatedPolicyImpact struct {
	ImportedIntentChanges    *simulatedImportedIntentChanges `json:"imported_intent_changes,omitempty"`
	ImpactHash               string                          `json:"impact_hash"`
	AddedRelationshipCount   int                             `json:"added_relationship_count"`
	AddedRelationships       []simulatedRelationship         `json:"added_relationships"`
	RemovedRelationshipCount int                             `json:"removed_relationship_count"`
	RemovedRelationships     []simulatedRelationship         `json:"removed_relationships"`
	AddedExplanationCount    int                             `json:"added_explanation_count"`
	AddedExplanations        []simulatedExplanation          `json:"added_explanations"`
	RemovedExplanationCount  int                             `json:"removed_explanation_count"`
	RemovedExplanations      []simulatedExplanation          `json:"removed_explanations"`
	AffectedDeviceCount      int                             `json:"affected_device_count"`
	AffectedDeviceIDs        []string                        `json:"affected_device_ids"`
	AffectedResourceCount    int                             `json:"affected_resource_count"`
	AffectedResourceIDs      []string                        `json:"affected_resource_ids"`
	AffectedGroupCount       int                             `json:"affected_resource_group_count"`
	AffectedGroupIDs         []string                        `json:"affected_resource_group_ids"`
	UnsupportedCapabilities  []string                        `json:"unsupported_capabilities"`
	Truncated                bool                            `json:"truncated"`
	StaleInputs              bool                            `json:"stale_inputs"`
	Uncertain                bool                            `json:"uncertain"`
}

type simulatedImportedIntentChanges struct {
	AddedCount               int                       `json:"added_count"`
	Added                    []simulatedImportedIntent `json:"added"`
	RemovedCount             int                       `json:"removed_count"`
	Removed                  []simulatedImportedIntent `json:"removed"`
	PacketAuthorityEvaluated bool                      `json:"packet_authority_evaluated"`
}

type simulatedImportedIntent struct {
	AccessRuleID                string                          `json:"access_rule_id"`
	SourceDeviceID              string                          `json:"source_device_id"`
	ImportedResourceID          string                          `json:"imported_resource_id"`
	ImportedResourceVersion     int64                           `json:"imported_resource_version"`
	TrustContractID             string                          `json:"trust_contract_id"`
	ContractVersion             int64                           `json:"contract_version"`
	OfferID                     string                          `json:"offer_id"`
	ExportID                    string                          `json:"export_id"`
	ExportVersion               int64                           `json:"export_version"`
	ProviderWorkspaceID         string                          `json:"provider_workspace_id"`
	ProviderNetworkID           string                          `json:"provider_network_id"`
	ConsumerWorkspaceID         string                          `json:"consumer_workspace_id"`
	ConsumerNetworkID           string                          `json:"consumer_network_id"`
	Resource                    simulatedResourceEvidence       `json:"resource"`
	ProviderSharingRevision     int64                           `json:"provider_sharing_revision"`
	ConsumerSharingRevision     int64                           `json:"consumer_sharing_revision"`
	ProviderAuthorityGeneration int64                           `json:"provider_authority_generation"`
	ConsumerAuthorityGeneration int64                           `json:"consumer_authority_generation"`
	RecoveryEpoch               int64                           `json:"recovery_epoch"`
	ExpiresAt                   string                          `json:"expires_at"`
	MaximumTraffic              []sharingTrafficData            `json:"maximum_traffic"`
	Protocol                    string                          `json:"protocol"`
	DestinationPortRanges       []publishPolicyPortRangeRequest `json:"destination_port_ranges"`
}

type simulatedRelationship struct {
	SourceDeviceID       string                         `json:"source_device_id"`
	DestinationDeviceID  string                         `json:"destination_device_id"`
	Protocol             string                         `json:"protocol"`
	DestinationPortRange *publishPolicyPortRangeRequest `json:"destination_port_range,omitempty"`
}

type simulatedExplanation struct {
	AccessRuleID          string                          `json:"access_rule_id"`
	SourceDeviceID        string                          `json:"source_device_id"`
	DestinationDeviceID   string                          `json:"destination_device_id"`
	Protocol              string                          `json:"protocol"`
	DestinationPortRanges []publishPolicyPortRangeRequest `json:"destination_port_ranges"`
	SelectorKind          string                          `json:"selector_kind"`
	Resource              *simulatedResourceEvidence      `json:"resource,omitempty"`
	ResourceGroup         *simulatedGroupEvidence         `json:"resource_group,omitempty"`
}

type simulatedResourceEvidence struct {
	ResourceID        string `json:"resource_id"`
	ResourceVersion   int64  `json:"resource_version"`
	TargetGeneration  int64  `json:"target_generation"`
	InventoryRevision int64  `json:"inventory_revision"`
	SemanticHash      string `json:"semantic_hash"`
}

type simulatedGroupEvidence struct {
	ResourceGroupID   string `json:"resource_group_id"`
	GroupVersion      int64  `json:"group_version"`
	DefinitionVersion int64  `json:"definition_version"`
	GroupRevision     int64  `json:"group_revision"`
	SemanticHash      string `json:"semantic_hash"`
}

type policySimulationPath struct {
	workspaceID string
	networkID   string
}

func parsePolicySimulationPath(request *http.Request) (policySimulationPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawQuery != "" || request.URL.RawPath != "" {
		return policySimulationPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) != 9 || segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "workspaces" || segments[4] != "networks" ||
		segments[6] != "policy" || segments[7] != "actions" || segments[8] != "simulate" {
		return policySimulationPath{}, false
	}
	return policySimulationPath{workspaceID: segments[3], networkID: segments[5]}, true
}

type managementPolicySimulationRequest struct {
	response      http.ResponseWriter
	request       *http.Request
	correlationID publicid.ID
	path          policySimulationPath
	session       accountsession.Session
	browser       *browserManagementAdmission
}

func (handler *ManagementHandler) simulatePolicy(
	ctx context.Context,
	input managementPolicySimulationRequest,
) string {
	request, decodeErr := decodePolicySimulationRequest(input.response, input.request, input.path)
	if decodeErr != nil {
		writeManagementError(ctx, handler.logger, input.response, input.correlationID, *decodeErr)
		return decodeErr.Code
	}
	if err := input.browser.validate(ctx); err != nil {
		classified := classifyAuthenticationError(err)
		writeManagementError(ctx, handler.logger, input.response, input.correlationID, classified)
		return classified.Code
	}
	result, err := handler.policySimulator.Simulate(ctx, input.session, request)
	if err != nil {
		classified := classifyPolicySimulationError(err)
		writeManagementError(ctx, handler.logger, input.response, input.correlationID, classified)
		return classified.Code
	}
	if !result.IsValid() || result.Baseline().Scope() != request.Scope() ||
		result.ProposedCandidate().Snapshot().Revision() != request.Revision() {
		apiError := managementError{
			Status: http.StatusInternalServerError, Code: "internal_failure",
			Message: "the request could not be completed",
		}
		writeManagementError(ctx, handler.logger, input.response, input.correlationID, apiError)
		return apiError.Code
	}
	responseData := encodePolicySimulationResult(result)
	input.response.Header().Set(
		"ETag",
		strongVersionETag(result.Baseline().RevisionVector().PolicyRevision()),
	)
	input.response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, input.response, http.StatusOK, simulatePolicyResponse{
		Data: responseData, CorrelationID: input.correlationID.String(),
	})
	return "success"
}

func decodePolicySimulationRequest(
	response http.ResponseWriter,
	request *http.Request,
	path policySimulationPath,
) (compilation.Request, *managementError) {
	workspaceID, err := workspace.ParseID(path.workspaceID)
	if err != nil {
		return compilation.Request{}, invalidManagementRequest()
	}
	networkID, err := network.ParseID(path.networkID)
	if err != nil {
		return compilation.Request{}, invalidManagementRequest()
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return compilation.Request{}, invalidManagementRequest()
	}
	baseRevision, preconditionErr := parsePolicyIfMatch(request.Header.Values("If-Match"))
	if preconditionErr != nil {
		return compilation.Request{}, preconditionErr
	}
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return compilation.Request{}, invalidManagementRequest()
	}
	var body simulatePolicyRequest
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, maximumPolicyPublicationBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || ensureJSONEnd(decoder) != nil ||
		body.Rules == nil || len(body.Rules) > policy.MaximumRules {
		return compilation.Request{}, invalidManagementRequest()
	}
	rules := make([]compilation.RuleIntent, len(body.Rules))
	for index, input := range body.Rules {
		rule, ruleErr := decodePolicyRuleIntent(scope, input)
		if ruleErr != nil {
			return compilation.Request{}, invalidManagementRequest()
		}
		rules[index] = rule
	}
	compiled, err := compilation.NewRequest(compilation.RequestParams{
		Scope: scope, Revision: baseRevision + 1, Rules: rules,
	})
	if err != nil {
		return compilation.Request{}, invalidManagementRequest()
	}
	return compiled, nil
}

func encodePolicySimulationResult(result simulation.Result) simulatedPolicy {
	baseline := result.Baseline()
	baselineCandidate := baseline.Candidate()
	baselineHash := baselineCandidate.SemanticHash().Bytes()
	releaseID, _, hasActiveRelease := baseline.ActiveRelease()
	baselineEvidence := simulatedPolicyBaseline{
		RevisionVector:        encodePolicySimulationVector(baseline.RevisionVector()),
		HasActiveRelease:      hasActiveRelease,
		CompilerFormatVersion: baselineCandidate.CompilerFormatVersion(),
		SemanticHash:          hex.EncodeToString(baselineHash[:]),
	}
	if hasActiveRelease {
		baselineEvidence.ReleaseID = releaseID.String()
	}
	proposed := result.ProposedCandidate()
	proposedHash := proposed.SemanticHash().Bytes()
	impactHash := result.ImpactHash().Bytes()
	impact := simulatedPolicyImpact{
		ImpactHash:               hex.EncodeToString(impactHash[:]),
		AddedRelationshipCount:   result.AddedRelationshipCount(),
		AddedRelationships:       encodeSimulatedRelationships(result.AddedRelationships()),
		RemovedRelationshipCount: result.RemovedRelationshipCount(),
		RemovedRelationships:     encodeSimulatedRelationships(result.RemovedRelationships()),
		AddedExplanationCount:    result.AddedExplanationCount(),
		AddedExplanations:        encodeSimulatedExplanations(result.AddedExplanations()),
		RemovedExplanationCount:  result.RemovedExplanationCount(),
		RemovedExplanations:      encodeSimulatedExplanations(result.RemovedExplanations()),
		AffectedDeviceCount:      result.AffectedDeviceCount(),
		AffectedDeviceIDs:        make([]string, 0, len(result.AffectedDevices())),
		AffectedResourceCount:    result.AffectedResourceCount(),
		AffectedResourceIDs:      make([]string, 0, len(result.AffectedResources())),
		AffectedGroupCount:       result.AffectedGroupCount(),
		AffectedGroupIDs:         make([]string, 0, len(result.AffectedGroups())),
		UnsupportedCapabilities:  make([]string, 0, len(result.UnsupportedCapabilities())),
		Truncated:                result.Truncated(), StaleInputs: result.StaleInputs(), Uncertain: result.Uncertain(),
	}
	for _, id := range result.AffectedDevices() {
		impact.AffectedDeviceIDs = append(impact.AffectedDeviceIDs, id.String())
	}
	for _, id := range result.AffectedResources() {
		impact.AffectedResourceIDs = append(impact.AffectedResourceIDs, id.String())
	}
	for _, id := range result.AffectedGroups() {
		impact.AffectedGroupIDs = append(impact.AffectedGroupIDs, id.String())
	}
	for _, capability := range result.UnsupportedCapabilities() {
		impact.UnsupportedCapabilities = append(impact.UnsupportedCapabilities, capability.String())
	}
	if baselineCandidate.CompilerFormatVersion() == 4 || proposed.CompilerFormatVersion() == 4 {
		impact.ImportedIntentChanges = &simulatedImportedIntentChanges{
			AddedCount: result.AddedImportedIntentCount(), Added: encodeSimulatedImportedIntents(result.AddedImportedIntents()),
			RemovedCount: result.RemovedImportedIntentCount(), Removed: encodeSimulatedImportedIntents(result.RemovedImportedIntents()),
			PacketAuthorityEvaluated: false,
		}
	}
	return simulatedPolicy{
		Baseline: baselineEvidence,
		Proposed: simulatedPolicyProposed{
			RevisionVector:        encodePolicySimulationVector(result.ProposedRevisionVector()),
			CompilerFormatVersion: proposed.CompilerFormatVersion(),
			SemanticHash:          hex.EncodeToString(proposedHash[:]),
			RuleCount:             proposed.ProjectionCount(),
		},
		Impact:       impact,
		PeerEstimate: encodePeerEstimate(result.Peers()),
	}
}

func encodeSimulatedImportedIntents(values []publication.ImportedResourceDestination) []simulatedImportedIntent {
	encoded := make([]simulatedImportedIntent, len(values))
	for index, value := range values {
		resolution := value.Resolution()
		contract := resolution.Contract()
		resource := contract.Resource()
		hash := resource.SemanticHash().Bytes()
		ports := value.DestinationPortRanges()
		encodedPorts := make([]publishPolicyPortRangeRequest, len(ports))
		for portIndex, port := range ports {
			encodedPorts[portIndex] = publishPolicyPortRangeRequest{First: int(port.First()), Last: int(port.Last())}
		}
		encoded[index] = simulatedImportedIntent{
			AccessRuleID: value.RuleID().String(), SourceDeviceID: value.SourceNodeID().String(),
			ImportedResourceID: resolution.ImportedResourceID().String(), ImportedResourceVersion: resolution.ImportedResourceVersion(),
			TrustContractID: contract.ID().String(), ContractVersion: contract.Version(), OfferID: contract.OfferID().String(),
			ExportID: contract.ExportID().String(), ExportVersion: resolution.ExportVersion(),
			ProviderWorkspaceID: resolution.ProviderScope().WorkspaceID().String(), ProviderNetworkID: resolution.ProviderScope().NetworkID().String(),
			ConsumerWorkspaceID: resolution.ConsumerScope().WorkspaceID().String(), ConsumerNetworkID: resolution.ConsumerScope().NetworkID().String(),
			Resource: simulatedResourceEvidence{ResourceID: resource.ResourceID().String(), ResourceVersion: resource.ResourceVersion(),
				TargetGeneration: resource.TargetGeneration(), InventoryRevision: resolution.ProviderInventoryRevision(), SemanticHash: hex.EncodeToString(hash[:])},
			ProviderSharingRevision: resolution.ProviderSharingRevision(), ConsumerSharingRevision: resolution.ConsumerSharingRevision(),
			ProviderAuthorityGeneration: contract.ProviderAuthorityGeneration(), ConsumerAuthorityGeneration: contract.ConsumerAuthorityGeneration(),
			RecoveryEpoch: contract.RecoveryEpoch(), ExpiresAt: contract.ExpiresAt().UTC().Format(time.RFC3339Nano),
			MaximumTraffic: sharingTrafficDataFromSet(contract.MaximumTraffic()), Protocol: value.Protocol().String(), DestinationPortRanges: encodedPorts,
		}
	}
	return encoded
}

func encodePolicySimulationVector(vector accessgraph.RevisionVector) simulatedPolicyRevisionVector {
	return simulatedPolicyRevisionVector{
		NetworkRevision: vector.NetworkRevision(), InventoryRevision: vector.InventoryRevision(),
		GroupRevision: vector.GroupRevision(), PolicyRevision: vector.PolicyRevision(),
		DNSRevision: vector.DNSRevision(), RouteRevision: vector.RouteRevision(),
		SharingRevision: vector.SharingRevision(), IsolationGeneration: vector.IsolationGeneration(),
	}
}

func encodeSimulatedRelationships(values []simulation.Relationship) []simulatedRelationship {
	encoded := make([]simulatedRelationship, len(values))
	for index, value := range values {
		encoded[index] = simulatedRelationship{
			SourceDeviceID:      value.SourceNodeID().String(),
			DestinationDeviceID: value.DestinationNodeID().String(), Protocol: value.Protocol().String(),
		}
		if first, last, found := value.DestinationPortRange(); found {
			encoded[index].DestinationPortRange = &publishPolicyPortRangeRequest{
				First: int(first), Last: int(last),
			}
		}
	}
	return encoded
}

func encodeSimulatedExplanations(values []simulation.Explanation) []simulatedExplanation {
	encoded := make([]simulatedExplanation, len(values))
	for index, value := range values {
		ranges := value.DestinationPortRanges()
		ports := make([]publishPolicyPortRangeRequest, len(ranges))
		for rangeIndex, portRange := range ranges {
			ports[rangeIndex] = publishPolicyPortRangeRequest{
				First: int(portRange.First()), Last: int(portRange.Last()),
			}
		}
		encoded[index] = simulatedExplanation{
			AccessRuleID: value.RuleID().String(), SourceDeviceID: value.SourceNodeID().String(),
			DestinationDeviceID: value.DestinationNodeID().String(), Protocol: value.Protocol().String(),
			DestinationPortRanges: ports, SelectorKind: value.SelectorKind().String(),
		}
		resourceID, version, generation, inventoryRevision, semanticHash, found := value.ResourceEvidence()
		if found {
			hash := semanticHash.Bytes()
			encoded[index].Resource = &simulatedResourceEvidence{
				ResourceID: resourceID.String(), ResourceVersion: version,
				TargetGeneration: generation, InventoryRevision: inventoryRevision,
				SemanticHash: hex.EncodeToString(hash[:]),
			}
		}
		groupID, version, definitionVersion, groupRevision, semanticHash, found := value.GroupEvidence()
		if found {
			hash := semanticHash.Bytes()
			encoded[index].ResourceGroup = &simulatedGroupEvidence{
				ResourceGroupID: groupID.String(), GroupVersion: version,
				DefinitionVersion: definitionVersion, GroupRevision: groupRevision,
				SemanticHash: hex.EncodeToString(hash[:]),
			}
		}
	}
	return encoded
}

func classifyPolicySimulationError(err error) managementError {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return managementError{
			Status: http.StatusGatewayTimeout, Code: "request_timeout",
			Message: "the request deadline expired", Retryable: true,
		}
	case errors.Is(err, simulation.ErrForbidden), errors.Is(err, compilation.ErrForbidden):
		return managementError{
			Status: http.StatusForbidden, Code: "forbidden",
			Message: "the request is not authorized",
		}
	case errors.Is(err, simulation.ErrTooLarge):
		tooLarge := managementError{
			Status: http.StatusUnprocessableEntity, Code: "simulation_too_large",
			Message: "the Device Groups or group rules are too large to preview Device by Device",
		}
		if peers, found := simulation.PeerEstimateOf(err); found {
			estimate := encodePeerEstimate(peers)
			tooLarge.PeerEstimate = &estimate
		}
		return tooLarge
	case errors.Is(err, simulation.ErrStaleInputs):
		return managementError{
			Status: http.StatusPreconditionFailed, Code: "precondition_failed",
			Message: "the Policy revision or simulation inputs changed",
		}
	case errors.Is(err, compilation.ErrResourceConflict):
		return managementError{
			Status: http.StatusConflict, Code: "resource_conflict",
			Message: "a Resource destination is not active or changed",
		}
	case errors.Is(err, simulation.ErrInvalidRequest), errors.Is(err, compilation.ErrInvalidRequest):
		return *invalidManagementRequest()
	case errors.Is(err, simulation.ErrInvalidBaseline), errors.Is(err, simulation.ErrInvalidResult):
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
