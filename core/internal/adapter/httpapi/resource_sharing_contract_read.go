package httpapi

import (
	"context"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
	"net/http"
	"time"
)

type shareContractDetailData struct {
	shareContractData
	ImportedDisplayName string               `json:"imported_display_name"`
	ScopeRelation       string               `json:"scope_relation"`
	ProviderWorkspaceID string               `json:"provider_workspace_id"`
	ProviderNetworkID   string               `json:"provider_network_id"`
	ConsumerWorkspaceID string               `json:"consumer_workspace_id"`
	ConsumerNetworkID   string               `json:"consumer_network_id"`
	ResourceID          string               `json:"resource_id"`
	ResourceVersion     int64                `json:"resource_version"`
	TargetGeneration    int64                `json:"target_generation"`
	MaximumTraffic      []sharingTrafficData `json:"maximum_traffic"`
	ExpiresAt           time.Time            `json:"expires_at"`
}

type shareContractDetailEnvelope struct {
	Data          shareContractDetailData `json:"data"`
	CorrelationID string                  `json:"correlation_id"`
}

func (handler *ManagementHandler) getTrustContract(ctx context.Context, response http.ResponseWriter, request *http.Request, correlationID publicid.ID, path resourceSharingPath, session accountsession.Session) string {
	if request.URL.RawQuery != "" || request.Body != nil && request.Body != http.NoBody ||
		len(request.Header.Values("If-Match")) != 0 || len(request.Header.Values("Idempotency-Key")) != 0 ||
		len(request.Header.Values("Content-Type")) != 0 {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	scope, err := path.scope()
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	id, err := sharing.ParseContractID(path.publicID)
	if err != nil {
		return handler.writeSharingRequestError(ctx, response, correlationID)
	}
	snapshot, err := handler.resourceSharing.GetContract(ctx, session, scope, id)
	if err != nil {
		return handler.writeSharingError(ctx, response, correlationID, err)
	}
	contract := snapshot.Contract()
	if !snapshot.IsValid() || contract.ID() != id || contract.ConsumerScope() != scope {
		return handler.writeSharingInternalError(ctx, response, correlationID)
	}
	data := shareContractDetailData{
		shareContractData:   shareContractDataFromResult(contract, snapshot.ImportedResourceVersion(), snapshot.AccessName()),
		ImportedDisplayName: snapshot.ImportedDisplayName().String(),
		ScopeRelation:       contract.ScopeRelation().String(),
		ProviderWorkspaceID: contract.ProviderScope().WorkspaceID().String(), ProviderNetworkID: contract.ProviderScope().NetworkID().String(),
		ConsumerWorkspaceID: scope.WorkspaceID().String(), ConsumerNetworkID: scope.NetworkID().String(),
		ResourceID: contract.Resource().ResourceID().String(), ResourceVersion: contract.Resource().ResourceVersion(),
		TargetGeneration: contract.Resource().TargetGeneration(), MaximumTraffic: sharingTrafficDataFromSet(contract.MaximumTraffic()), ExpiresAt: contract.ExpiresAt(),
	}
	response.Header().Set("ETag", strongVersionETag(contract.Version()))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, shareContractDetailEnvelope{Data: data, CorrelationID: correlationID.String()})
	return "success"
}
