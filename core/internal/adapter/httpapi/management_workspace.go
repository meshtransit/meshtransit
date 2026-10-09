package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace/settings"
)

// WorkspaceRenamer commits names through the current owner authority.
type WorkspaceRenamer interface {
	Rename(context.Context, settings.Command) (settings.Result, error)
}

func parseWorkspaceRenamePath(request *http.Request) (string, bool) {
	if request == nil || request.URL == nil || request.URL.RawQuery != "" || request.URL.RawPath != "" {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(parts) != 6 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "workspaces" || parts[4] != "actions" || parts[5] != "rename" {
		return "", false
	}
	return parts[3], true
}

type workspaceRenameResponse struct {
	Data struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
		DisplayCode string `json:"display_code"`
		Version     int64  `json:"version"`
	} `json:"data"`
	CorrelationID string `json:"correlation_id"`
}

func (handler *ManagementHandler) renameWorkspace(ctx context.Context, response http.ResponseWriter, request *http.Request,
	correlationID publicid.ID, path string, session accountsession.Session) string {
	expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *precondition)
		return precondition.Code
	}
	workspaceID, err := workspace.ParseID(path)
	var body struct {
		DisplayName string `json:"display_name"`
	}
	if err != nil || request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || ensureJSONEnd(decoder) != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	command := settings.Command{Session: session, WorkspaceID: workspaceID, DisplayName: body.DisplayName, ExpectedVersion: expectedVersion, CorrelationID: correlationID}
	if !command.IsValid() {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	if nilContinuationDependency(handler.workspaceRenames) {
		failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable", Message: "Workspace settings are temporarily unavailable", Retryable: false}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	result, err := handler.workspaceRenames.Rename(ctx, command)
	if err == nil && (!result.IsValid() || result.WorkspaceID != workspaceID || result.DisplayName != body.DisplayName || result.Version != expectedVersion+1) {
		err = settings.ErrInvalid
	}
	if err != nil {
		failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable", Message: "The result is uncertain. Refresh Workspace details before trying again.", Retryable: false}
		switch {
		case errors.Is(err, settings.ErrForbidden):
			failure = managementError{Status: http.StatusForbidden, Code: "permission_denied", Message: "Only the current Workspace owner can rename this Workspace"}
		case errors.Is(err, settings.ErrConflict):
			failure = managementError{Status: http.StatusConflict, Code: "version_conflict", Message: "Workspace details changed or this name is already in use. Refresh and choose a name."}
		case errors.Is(err, settings.ErrInvalid):
			failure = *invalidManagementRequest()
		}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	var output workspaceRenameResponse
	output.Data.ID = result.WorkspaceID.String()
	output.Data.DisplayName = result.DisplayName
	output.Data.DisplayCode = result.DisplayCode.String()
	output.Data.Version = result.Version
	output.CorrelationID = correlationID.String()
	response.Header().Set("ETag", strongVersionETag(result.Version))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}
