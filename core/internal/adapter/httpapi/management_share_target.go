package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/sharing/target"
	"meshtransit.net/core/internal/domain/workspace"
)

// ShareTargetResolver resolves a share consumer Network by display code.
type ShareTargetResolver interface {
	Resolve(context.Context, target.Query) (target.Target, error)
}

type shareTargetPath struct {
	workspace, network, code string
}

// parseShareTargetPath matches
// /api/v1/workspaces/{workspace}/networks/{network}/share-targets/{code}.
func parseShareTargetPath(request *http.Request) (shareTargetPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawQuery != "" || request.URL.RawPath != "" {
		return shareTargetPath{}, false
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(parts) != 8 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "workspaces" || parts[3] == "" ||
		parts[4] != "networks" || parts[5] == "" || parts[6] != "share-targets" || parts[7] == "" {
		return shareTargetPath{}, false
	}
	return shareTargetPath{workspace: parts[3], network: parts[5], code: parts[7]}, true
}

func isShareTargetRead(request *http.Request) bool {
	_, ok := parseShareTargetPath(request)
	return ok && request.Method == http.MethodGet
}

type shareTargetResponse struct {
	Data struct {
		WorkspaceID          string `json:"workspace_id"`
		NetworkID            string `json:"network_id"`
		WorkspaceDisplayCode string `json:"workspace_display_code"`
		NetworkDisplayCode   string `json:"network_display_code"`
		CrossWorkspace       bool   `json:"cross_workspace"`
	} `json:"data"`
	CorrelationID string `json:"correlation_id"`
}

func (handler *ManagementHandler) resolveShareTarget(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path shareTargetPath, session accountsession.Session) string {
	if nilContinuationDependency(handler.shareTargets) {
		failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Share targets are temporarily unavailable"}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	workspaceID, workspaceErr := workspace.ParseID(path.workspace)
	networkID, networkErr := network.ParseID(path.network)
	code, codeErr := identity.ParseDisplayCode(path.code)
	var provider network.Scope
	scopeErr := errors.Join(workspaceErr, networkErr)
	if scopeErr == nil {
		provider, scopeErr = network.NewScope(workspaceID, networkID)
	}
	query := target.Query{Session: session, Provider: provider, NetworkCode: code}
	if errors.Join(scopeErr, codeErr) != nil || !query.IsValid() {
		failure := *invalidManagementRequest()
		failure.Message = "Enter the 12-digit ID of the Network that should receive the share."
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	resolved, err := handler.shareTargets.Resolve(ctx, query)
	if err != nil {
		failure := classifyShareTargetError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	var output shareTargetResponse
	output.Data.WorkspaceID = resolved.Scope.WorkspaceID().String()
	output.Data.NetworkID = resolved.Scope.NetworkID().String()
	output.Data.WorkspaceDisplayCode = resolved.WorkspaceCode.String()
	output.Data.NetworkDisplayCode = resolved.NetworkCode.String()
	output.Data.CrossWorkspace = resolved.CrossWorkspace(provider)
	output.CorrelationID = correlationID.String()
	response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

func classifyShareTargetError(err error) managementError {
	switch {
	case errors.Is(err, target.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You need permission to share from this Network."}
	case errors.Is(err, target.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "share_target_not_found",
			Message: "No active Network has this ID. Check it with the receiving Workspace."}
	case errors.Is(err, target.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The Network could not be checked. Try again."}
	}
}
