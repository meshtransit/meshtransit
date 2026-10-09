package httpapi

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy/catalog"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

type activePolicyResponse struct {
	Data          activePolicyData `json:"data"`
	CorrelationID string           `json:"correlation_id"`
}

type activePolicyData struct {
	WorkspaceID     string             `json:"workspace_id"`
	NetworkID       string             `json:"network_id"`
	PolicyRevision  int64              `json:"policy_revision"`
	SemanticHash    string             `json:"semantic_hash"`
	RuleCount       int                `json:"rule_count"`
	Complete        bool               `json:"complete"`
	DeviceRulesOnly bool               `json:"device_rules_only"`
	Rules           []activePolicyRule `json:"rules"`
}

type activePolicyRule struct {
	ID                    string                          `json:"id"`
	SourceDeviceID        string                          `json:"source_device_id"`
	SourceKind            string                          `json:"source_kind"`
	SourceSelectorID      string                          `json:"source_selector_id"`
	DestinationDeviceID   string                          `json:"destination_device_id"`
	Protocol              string                          `json:"protocol"`
	DestinationPortRanges []publishPolicyPortRangeRequest `json:"destination_port_ranges"`
	SelectorKind          string                          `json:"selector_kind"`
	DestinationSelectorID string                          `json:"destination_selector_id"`
}

func parseActivePolicyPath(request *http.Request) (policySimulationPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawQuery != "" || request.URL.RawPath != "" {
		return policySimulationPath{}, false
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(parts) != 7 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "workspaces" || parts[4] != "networks" || parts[6] != "policy" {
		return policySimulationPath{}, false
	}
	return policySimulationPath{workspaceID: parts[3], networkID: parts[5]}, true
}

func (handler *ManagementHandler) readActivePolicy(
	ctx context.Context,
	response http.ResponseWriter,
	correlationID publicid.ID,
	path policySimulationPath,
	session accountsession.Session,
) string {
	workspaceID, err := workspace.ParseID(path.workspaceID)
	networkID, networkErr := network.ParseID(path.networkID)
	scope, scopeErr := network.NewScope(workspaceID, networkID)
	if err != nil || networkErr != nil || scopeErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	if nilContinuationDependency(handler.activePolicies) {
		classified := classifyPolicySimulationError(simulation.ErrUnavailable)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	baseline, err := handler.activePolicies.ReadActivePolicy(ctx, session, scope, time.Now().UTC())
	if err == nil && (!baseline.IsValid() || baseline.Scope() != scope) {
		err = simulation.ErrInvalidBaseline
	}
	if err != nil {
		classified := classifyPolicySimulationError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	data := activePolicyProjection(baseline)
	response.Header().Set("ETag", strongVersionETag(data.PolicyRevision))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, activePolicyResponse{Data: data, CorrelationID: correlationID.String()})
	return "success"
}

// Resource provenance is projected as typed local selectors. It must never be
// flattened into Device intent when a Console appends a rule.
func activePolicyProjection(snapshot catalog.Snapshot) activePolicyData {
	hash := snapshot.SemanticHash().Bytes()
	data := activePolicyData{
		WorkspaceID: snapshot.Scope().WorkspaceID().String(), NetworkID: snapshot.Scope().NetworkID().String(),
		PolicyRevision: snapshot.Revision(), SemanticHash: hex.EncodeToString(hash[:]), RuleCount: snapshot.RuleCount(),
		Complete: snapshot.Complete(), DeviceRulesOnly: snapshot.DeviceRulesOnly(), Rules: make([]activePolicyRule, 0),
	}
	for _, item := range snapshot.Rows() {
		rule := item.Intent
		kind, selector := "device", rule.DestinationNodeID().String()
		if rule.DestinationDeviceGroupID().IsValid() {
			kind, selector = "device_group", rule.DestinationDeviceGroupID().String()
		}
		if rule.DestinationTagID().IsValid() {
			kind, selector = "device_tag", rule.DestinationTagID().String()
		}
		if rule.DestinationResourceID().IsValid() {
			kind, selector = "resource", rule.DestinationResourceID().String()
		}
		if rule.DestinationGroupID().IsValid() {
			kind, selector = "resource_group", rule.DestinationGroupID().String()
		}
		if rule.DestinationImportedResourceID().IsValid() {
			kind, selector = "imported_resource", rule.DestinationImportedResourceID().String()
		}
		destination := ""
		if item.DestinationNodeID.IsValid() {
			destination = item.DestinationNodeID.String()
		}
		sourceKind, sourceSelector, sourceDevice := "device", rule.SourceNodeID().String(), rule.SourceNodeID().String()
		switch {
		case rule.SourceGroupID().IsValid():
			sourceKind, sourceSelector, sourceDevice = "device_group", rule.SourceGroupID().String(), ""
		case rule.SourceIdentityGroupID().IsValid():
			sourceKind, sourceSelector, sourceDevice = "identity_group", rule.SourceIdentityGroupID().String(), ""
		case rule.SourceTagID().IsValid():
			sourceKind, sourceSelector, sourceDevice = "device_tag", rule.SourceTagID().String(), ""
		}
		data.Rules = append(data.Rules, activePolicyRule{ID: rule.ID().String(), SourceDeviceID: sourceDevice, SourceKind: sourceKind, SourceSelectorID: sourceSelector, DestinationDeviceID: destination, Protocol: rule.Protocol().String(), DestinationPortRanges: activePolicyPorts(rule.DestinationPortRanges()), SelectorKind: kind, DestinationSelectorID: selector})
	}
	return data
}

func activePolicyPorts(ports []policy.PortRange) []publishPolicyPortRangeRequest {
	result := make([]publishPolicyPortRangeRequest, 0, len(ports))
	for _, port := range ports {
		result = append(result, publishPolicyPortRangeRequest{First: int(port.First()), Last: int(port.Last())})
	}
	return result
}
