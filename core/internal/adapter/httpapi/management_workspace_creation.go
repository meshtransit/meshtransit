package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace/creation"
)

// WorkspaceCollectionPath is the Account-scoped Workspace collection.
const WorkspaceCollectionPath = "/api/v1/workspaces"

// WorkspaceCreator creates Account-owned Workspaces within entitlement quotas.
type WorkspaceCreator interface {
	Create(context.Context, creation.Command) (creation.Result, error)
}

func isWorkspaceCollectionPath(request *http.Request) bool {
	return request != nil && request.URL != nil && request.URL.Path == WorkspaceCollectionPath &&
		request.URL.RawQuery == "" && request.URL.RawPath == ""
}

type workspaceCreationResponse struct {
	Data struct {
		ID          string    `json:"id"`
		DisplayName string    `json:"display_name"`
		DisplayCode string    `json:"display_code"`
		Version     int64     `json:"version"`
		CreatedAt   time.Time `json:"created_at"`
	} `json:"data"`
	CorrelationID string `json:"correlation_id"`
}

func (handler *ManagementHandler) createWorkspace(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, session accountsession.Session) string {
	if nilContinuationDependency(handler.workspaceCreations) {
		failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Workspace creation is temporarily unavailable"}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	var body struct {
		WorkspaceID string `json:"workspace_id"`
		DisplayName string `json:"display_name"`
	}
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || ensureJSONEnd(decoder) != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	workspaceID, err := workspace.ParseID(body.WorkspaceID)
	command := creation.Command{Session: session, WorkspaceID: workspaceID, DisplayName: body.DisplayName,
		CorrelationID: correlationID}
	if err != nil || !command.IsValid() {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	result, err := handler.workspaceCreations.Create(ctx, command)
	if err != nil {
		failure := classifyWorkspaceCreationError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	var output workspaceCreationResponse
	output.Data.ID = result.WorkspaceID.String()
	output.Data.DisplayName = result.DisplayName
	output.Data.DisplayCode = result.DisplayCode.String()
	output.Data.Version = result.Version
	output.Data.CreatedAt = result.CreatedAt
	output.CorrelationID = correlationID.String()
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	response.Header().Set("ETag", strongVersionETag(result.Version))
	writeManagementJSON(ctx, handler.logger, response, status, output)
	return "success"
}

func classifyWorkspaceCreationError(err error) managementError {
	switch {
	case errors.Is(err, creation.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "Your Session cannot create Workspaces. Sign in again."}
	case errors.Is(err, creation.ErrEntitlementMissing), errors.Is(err, creation.ErrEntitlementExpired):
		return managementError{Status: http.StatusForbidden, Code: "deployment_entitlement_expired",
			Message: "This MeshTransit installation cannot create Workspaces until its entitlement is renewed."}
	case errors.Is(err, creation.ErrDeploymentLimit):
		return managementError{Status: http.StatusConflict, Code: "deployment_workspace_limit",
			Message: "This installation has reached its Workspace limit."}
	case errors.Is(err, creation.ErrAccountLimit):
		return managementError{Status: http.StatusConflict, Code: "account_workspace_limit",
			Message: "You already own the maximum number of Workspaces."}
	case errors.Is(err, creation.ErrConflict):
		return managementError{Status: http.StatusConflict, Code: "resource_conflict",
			Message: "You already own a Workspace with this name, or this request ID was used for another Workspace."}
	case errors.Is(err, creation.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Refresh your Workspaces before trying again."}
	}
}
