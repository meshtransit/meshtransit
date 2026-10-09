package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/sessioncontext"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
	"github.com/meshtransit/meshtransit/core/internal/platform/ratelimit"
)

const defaultManagementScopePageSize = 50

func (browser *BrowserManagement) readManagementScopes(
	ctx context.Context,
	response *browserManagementResponse,
	request *http.Request,
	admission *browserManagementAdmission,
) error {
	correlationID, err := browser.management.correlationIDs.NewID()
	if err != nil || !correlationID.IsValid() {
		return ErrBrowserManagementUnavailable
	}
	setManagementSecurityHeaders(response.header, correlationID)
	address, err := browser.management.clientIPs.Resolve(request)
	if err != nil {
		writeManagementError(ctx, browser.management.logger, response, correlationID, *invalidManagementRequest())
		return nil
	}
	if limitErr := browser.management.enforceAdmittedRateLimit(ctx, admission, continuationBudget{
		response: response,
		kind:     ratelimit.SubjectSource,
		raw:      address.String(),
		policy:   browser.management.sourcePolicy,
	}); limitErr != nil {
		writeManagementError(ctx, browser.management.logger, response, correlationID, *limitErr)
		return nil
	}
	session, err := admission.authenticate(ctx, request)
	if err != nil {
		writeManagementError(
			ctx, browser.management.logger, response, correlationID, classifyAuthenticationError(err),
		)
		return nil
	}
	if limitErr := browser.management.enforceAdmittedRateLimit(ctx, admission, continuationBudget{
		response: response,
		kind:     ratelimit.SubjectAccountSession,
		raw:      session.ID().String(),
		policy:   browser.management.sessionPolicy,
	}); limitErr != nil {
		writeManagementError(ctx, browser.management.logger, response, correlationID, *limitErr)
		return nil
	}
	workspaceID, hasWorkspace := session.LoginWorkspaceID()
	if !hasWorkspace {
		writeManagementError(
			ctx, browser.management.logger, response, correlationID,
			classifyAuthenticationError(accountsession.ErrUnauthenticated),
		)
		return nil
	}
	limit, after, requestErr := parseManagementScopeQuery(request.URL.RawQuery, workspaceID)
	if requestErr != nil {
		writeManagementError(ctx, browser.management.logger, response, correlationID, *requestErr)
		return nil
	}
	page, err := browser.scopes.List(ctx, session, limit, after)
	if err != nil {
		writeManagementError(
			ctx, browser.management.logger, response, correlationID, classifyManagementScopeError(err),
		)
		return nil
	}
	items := page.Items()
	networks := make([]managementScopeNetwork, len(items))
	for index, item := range items {
		permissions := item.Permissions()
		encodedPermissions := make([]string, len(permissions))
		for permissionIndex, permission := range permissions {
			encodedPermissions[permissionIndex] = string(permission)
		}
		networks[index] = managementScopeNetwork{
			ID: item.NetworkID().String(), DisplayName: item.DisplayName(), Permissions: encodedPermissions,
			DisplayCode: item.DisplayCode().String(),
		}
	}
	next := ""
	if cursor, ok := page.Next(); ok {
		next, err = encodeManagementScopePageToken(page.WorkspaceID(), cursor)
		if err != nil {
			writeManagementError(ctx, browser.management.logger, response, correlationID, internalManagementError())
			return nil
		}
	}
	writeManagementJSON(ctx, browser.management.logger, response, http.StatusOK, managementScopeEnvelope{
		Data: managementScopeData{
			PrincipalID: session.PrincipalID().String(),
			Workspace: managementScopeWorkspace{
				ID: page.WorkspaceID().String(), DisplayName: page.WorkspaceDisplayName(),
				DisplayCode: page.WorkspaceDisplayCode().String(),
				Version:     page.WorkspaceVersion(), CanRename: page.WorkspaceCanRename(),
				Permissions: workspacePermissionStrings(page),
			},
			Networks: networks,
		},
		NextPageToken: next,
		CorrelationID: correlationID.String(),
	})
	return nil
}

func workspacePermissionStrings(page sessioncontext.Page) []string {
	permissions := make([]string, 0, len(page.WorkspacePermissions()))
	for _, permission := range page.WorkspacePermissions() {
		permissions = append(permissions, string(permission))
	}
	return permissions
}

func classifyManagementScopeError(err error) managementError {
	switch {
	case errors.Is(err, sessioncontext.ErrInvalidRequest):
		return *invalidManagementRequest()
	case errors.Is(err, sessioncontext.ErrUnauthenticated):
		return classifyAuthenticationError(accountsession.ErrUnauthenticated)
	case errors.Is(err, sessioncontext.ErrUnavailable),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return managementError{
			Status: http.StatusServiceUnavailable, Code: "management_scopes_unavailable",
			Message: "management scopes are temporarily unavailable", Retryable: true,
		}
	default:
		return internalManagementError()
	}
}

type managementScopePageToken struct {
	Version     int    `json:"v"`
	WorkspaceID string `json:"workspace_id"`
	After       string `json:"after"`
}

func parseManagementScopeQuery(
	rawQuery string,
	workspaceID workspace.ID,
) (int, network.ID, *managementError) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return 0, network.ID{}, invalidManagementRequest()
	}
	for key, entries := range values {
		if (key != "page_size" && key != "page_token") || len(entries) != 1 || entries[0] == "" {
			return 0, network.ID{}, invalidManagementRequest()
		}
	}
	limit := defaultManagementScopePageSize
	if rawLimit := values.Get("page_size"); rawLimit != "" {
		limit, err = strconv.Atoi(rawLimit)
		if err != nil || limit < 1 || limit > sessioncontext.MaximumPageSize || strconv.Itoa(limit) != rawLimit {
			return 0, network.ID{}, invalidManagementRequest()
		}
	}
	after := network.ID{}
	if encoded := values.Get("page_token"); encoded != "" {
		after, err = decodeManagementScopePageToken(encoded, workspaceID)
		if err != nil {
			return 0, network.ID{}, invalidManagementRequest()
		}
	}
	return limit, after, nil
}

func encodeManagementScopePageToken(workspaceID workspace.ID, after network.ID) (string, error) {
	if !workspaceID.IsValid() || !after.IsValid() {
		return "", sessioncontext.ErrInvalidRequest
	}
	payload, err := json.Marshal(managementScopePageToken{
		Version: 1, WorkspaceID: workspaceID.String(), After: after.String(),
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeManagementScopePageToken(encoded string, workspaceID workspace.ID) (network.ID, error) {
	if len(encoded) > 512 || !workspaceID.IsValid() {
		return network.ID{}, sessioncontext.ErrInvalidRequest
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return network.ID{}, sessioncontext.ErrInvalidRequest
	}
	var wire managementScopePageToken
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || ensureJSONEnd(decoder) != nil ||
		wire.Version != 1 || wire.WorkspaceID != workspaceID.String() {
		return network.ID{}, sessioncontext.ErrInvalidRequest
	}
	return network.ParseID(wire.After)
}

type managementScopeWorkspace struct {
	Version     int64    `json:"version,omitempty"`
	CanRename   bool     `json:"can_rename,omitempty"`
	Permissions []string `json:"permissions"`
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	DisplayCode string   `json:"display_code,omitempty"`
}

type managementScopeNetwork struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	DisplayCode string   `json:"display_code,omitempty"`
	Permissions []string `json:"permissions"`
}

type managementScopeData struct {
	PrincipalID string                   `json:"principal_id"`
	Workspace   managementScopeWorkspace `json:"workspace"`
	Networks    []managementScopeNetwork `json:"networks"`
}

type managementScopeEnvelope struct {
	Data          managementScopeData `json:"data"`
	NextPageToken string              `json:"next_page_token,omitempty"`
	CorrelationID string              `json:"correlation_id"`
}
