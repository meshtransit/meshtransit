package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/domain/workspace/selection"
)

const (
	// SessionWorkspacesPath lists the Workspaces the current Session may switch to.
	SessionWorkspacesPath = "/auth/v1/session/workspaces"
	// SessionWorkspacePath moves the current Session to another Workspace.
	SessionWorkspacePath = "/auth/v1/session/workspace"
)

// SessionWorkspaceSelector lists and switches the Session's Workspace.
type SessionWorkspaceSelector interface {
	List(context.Context, accountsession.Session) ([]selection.Candidate, error)
	Switch(context.Context, selection.SwitchCommand) (selection.SwitchResult, error)
}

// sessionWorkspaceRoute reports a list or switch path and its one method.
func sessionWorkspaceRoute(request *http.Request) (allowedMethod string, matched bool) {
	if request == nil || request.URL == nil || request.URL.RawQuery != "" || request.URL.RawPath != "" {
		return "", false
	}
	switch request.URL.Path {
	case SessionWorkspacesPath:
		return http.MethodGet, true
	case SessionWorkspacePath:
		return http.MethodPost, true
	}
	return "", false
}

func isSessionWorkspaceOperation(request *http.Request) bool {
	method, matched := sessionWorkspaceRoute(request)
	return matched && request.Method == method
}

type sessionWorkspaceItem struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	DisplayCode string `json:"display_code"`
	Owner       bool   `json:"owner"`
	Current     bool   `json:"current"`
}

type sessionWorkspaceListResponse struct {
	Data          []sessionWorkspaceItem `json:"data"`
	CorrelationID string                 `json:"correlation_id"`
}

type sessionWorkspaceSwitchResponse struct {
	Data struct {
		WorkspaceID string `json:"workspace_id"`
		Replayed    bool   `json:"replayed"`
	} `json:"data"`
	CorrelationID string `json:"correlation_id"`
}

func (handler *ManagementHandler) handleSessionWorkspace(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, session accountsession.Session) string {
	if nilContinuationDependency(handler.sessionWorkspaces) {
		failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Workspace switching is temporarily unavailable"}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	if request.Method == http.MethodGet {
		return handler.listSessionWorkspaces(ctx, response, correlationID, session)
	}
	return handler.switchSessionWorkspace(ctx, response, request, correlationID, session)
}

func (handler *ManagementHandler) listSessionWorkspaces(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, session accountsession.Session) string {
	candidates, err := handler.sessionWorkspaces.List(ctx, session)
	if err != nil {
		failure := classifySessionWorkspaceError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	output := sessionWorkspaceListResponse{Data: make([]sessionWorkspaceItem, 0, len(candidates)),
		CorrelationID: correlationID.String()}
	for _, candidate := range candidates {
		output.Data = append(output.Data, sessionWorkspaceItem{ID: candidate.WorkspaceID.String(),
			DisplayName: candidate.DisplayName, DisplayCode: candidate.DisplayCode.String(),
			Owner: candidate.Owner, Current: candidate.Current})
	}
	response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

func (handler *ManagementHandler) switchSessionWorkspace(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, session accountsession.Session) string {
	var body struct {
		WorkspaceID string `json:"workspace_id"`
	}
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || ensureJSONEnd(decoder) != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	workspaceID, err := workspace.ParseID(body.WorkspaceID)
	command := selection.SwitchCommand{Session: session, WorkspaceID: workspaceID, CorrelationID: correlationID}
	if err != nil || !command.IsValid() {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	result, err := handler.sessionWorkspaces.Switch(ctx, command)
	if err != nil {
		failure := classifySessionWorkspaceError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	var output sessionWorkspaceSwitchResponse
	output.Data.WorkspaceID = result.WorkspaceID.String()
	output.Data.Replayed = result.Replayed
	output.CorrelationID = correlationID.String()
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

func classifySessionWorkspaceError(err error) managementError {
	switch {
	case errors.Is(err, selection.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "Your Session has ended. Sign in again."}
	case errors.Is(err, selection.ErrNotAvailable):
		return managementError{Status: http.StatusNotFound, Code: "workspace_unavailable",
			Message: "This Workspace is not available to your Account."}
	case errors.Is(err, selection.ErrSessionChanged):
		return managementError{Status: http.StatusConflict, Code: "session_changed",
			Message: "Your Session changed in another tab. Refresh and try again."}
	case errors.Is(err, selection.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Refresh to see which Workspace is active."}
	}
}
