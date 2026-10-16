package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/domain/workspace/roles"
)

// WorkspaceRoleManager lists members and changes built-in role assignments.
type WorkspaceRoleManager interface {
	ListMembers(context.Context, roles.ListCommand) (roles.Directory, error)
	Assign(context.Context, roles.AssignCommand) (roles.AssignResult, error)
	Revoke(context.Context, roles.RevokeCommand) (roles.RevokeResult, error)
}

type workspaceRolePathKind uint8

const (
	workspaceRolePathMembers workspaceRolePathKind = iota + 1
	workspaceRolePathAssign
	workspaceRolePathRevoke
)

type workspaceRolePath struct {
	kind         workspaceRolePathKind
	workspaceID  string
	assignmentID string
}

// parseWorkspaceRolePath matches:
//
//	GET    /api/v1/workspaces/{workspace}/members
//	POST   /api/v1/workspaces/{workspace}/role-assignments
//	DELETE /api/v1/workspaces/{workspace}/role-assignments/{assignment}
func parseWorkspaceRolePath(request *http.Request) (workspaceRolePath, bool) {
	if request == nil || request.URL == nil || request.URL.RawQuery != "" || request.URL.RawPath != "" {
		return workspaceRolePath{}, false
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(parts) < 5 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "workspaces" || parts[3] == "" {
		return workspaceRolePath{}, false
	}
	switch {
	case len(parts) == 5 && parts[4] == "members":
		return workspaceRolePath{kind: workspaceRolePathMembers, workspaceID: parts[3]}, true
	case len(parts) == 5 && parts[4] == "role-assignments":
		return workspaceRolePath{kind: workspaceRolePathAssign, workspaceID: parts[3]}, true
	case len(parts) == 6 && parts[4] == "role-assignments" && parts[5] != "":
		return workspaceRolePath{kind: workspaceRolePathRevoke, workspaceID: parts[3], assignmentID: parts[5]}, true
	}
	return workspaceRolePath{}, false
}

func (path workspaceRolePath) allowedMethod() string {
	switch path.kind {
	case workspaceRolePathMembers:
		return http.MethodGet
	case workspaceRolePathRevoke:
		return http.MethodDelete
	default:
		return http.MethodPost
	}
}

func (path workspaceRolePath) operation() string {
	switch path.kind {
	case workspaceRolePathMembers:
		return workspaceMembersReadOperation
	case workspaceRolePathAssign:
		return workspaceRoleAssignOperation
	default:
		return workspaceRoleRevokeOperation
	}
}

type workspaceRoleAssignmentData struct {
	ID        string     `json:"id"`
	Role      string     `json:"role"`
	NetworkID string     `json:"network_id,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Version   int64      `json:"version"`
	CreatedAt time.Time  `json:"created_at"`
}

type workspaceMemberData struct {
	PrincipalID         string                        `json:"principal_id"`
	DisplayName         string                        `json:"display_name"`
	MembershipState     string                        `json:"membership_state"`
	MembershipExpiresAt *time.Time                    `json:"membership_expires_at,omitempty"`
	Owner               bool                          `json:"owner"`
	RoleAssignments     []workspaceRoleAssignmentData `json:"role_assignments"`
}

type workspaceMembersResponse struct {
	Data struct {
		WorkspaceID string                `json:"workspace_id"`
		Members     []workspaceMemberData `json:"members"`
		Truncated   bool                  `json:"truncated"`
	} `json:"data"`
	CorrelationID string `json:"correlation_id"`
}

type workspaceRoleAssignmentResponse struct {
	Data          workspaceRoleAssignmentData `json:"data"`
	CorrelationID string                      `json:"correlation_id"`
}

type workspaceRoleRevocationResponse struct {
	Data struct {
		ID      string `json:"id"`
		State   string `json:"state"`
		Version int64  `json:"version"`
	} `json:"data"`
	CorrelationID string `json:"correlation_id"`
}

func assignmentData(assignment roles.Assignment) workspaceRoleAssignmentData {
	data := workspaceRoleAssignmentData{ID: assignment.ID.String(), Role: string(assignment.Role),
		Version: assignment.Version, CreatedAt: assignment.CreatedAt}
	if (assignment.NetworkID != network.ID{}) {
		data.NetworkID = assignment.NetworkID.String()
	}
	if !assignment.ExpiresAt.IsZero() {
		expires := assignment.ExpiresAt
		data.ExpiresAt = &expires
	}
	return data
}

func (handler *ManagementHandler) handleWorkspaceRoles(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path workspaceRolePath, session accountsession.Session) string {
	if nilContinuationDependency(handler.workspaceRoles) {
		failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Workspace members are temporarily unavailable"}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	workspaceID, err := workspace.ParseID(path.workspaceID)
	if err != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	switch path.kind {
	case workspaceRolePathMembers:
		return handler.listWorkspaceMembers(ctx, response, correlationID, workspaceID, session)
	case workspaceRolePathAssign:
		return handler.assignWorkspaceRole(ctx, response, request, correlationID, workspaceID, session)
	default:
		return handler.revokeWorkspaceRole(ctx, response, request, correlationID, workspaceID, path.assignmentID, session)
	}
}

func (handler *ManagementHandler) listWorkspaceMembers(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, workspaceID workspace.ID, session accountsession.Session) string {
	directory, err := handler.workspaceRoles.ListMembers(ctx, roles.ListCommand{Session: session, WorkspaceID: workspaceID})
	if err != nil {
		return handler.writeWorkspaceRoleError(ctx, response, correlationID, err)
	}
	var output workspaceMembersResponse
	output.Data.WorkspaceID = directory.WorkspaceID.String()
	output.Data.Truncated = directory.Truncated
	output.Data.Members = make([]workspaceMemberData, 0, len(directory.Members))
	for _, member := range directory.Members {
		data := workspaceMemberData{PrincipalID: member.PrincipalID.String(), DisplayName: member.DisplayName,
			MembershipState: member.MembershipState, Owner: member.Owner,
			RoleAssignments: make([]workspaceRoleAssignmentData, 0, len(member.Assignments))}
		if !member.MembershipExpiresAt.IsZero() {
			expires := member.MembershipExpiresAt
			data.MembershipExpiresAt = &expires
		}
		for _, assignment := range member.Assignments {
			data.RoleAssignments = append(data.RoleAssignments, assignmentData(assignment))
		}
		output.Data.Members = append(output.Data.Members, data)
	}
	output.CorrelationID = correlationID.String()
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

func (handler *ManagementHandler) assignWorkspaceRole(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, workspaceID workspace.ID, session accountsession.Session) string {
	var body struct {
		AssignmentID string `json:"assignment_id"`
		PrincipalID  string `json:"principal_id"`
		Role         string `json:"role"`
		NetworkID    string `json:"network_id,omitempty"`
		ExpiresAt    string `json:"expires_at,omitempty"`
	}
	if !decodeWorkspaceRoleBody(response, request, &body) {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	command := roles.AssignCommand{Session: session, WorkspaceID: workspaceID, CorrelationID: correlationID}
	var err error
	command.AssignmentID, err = publicid.Parse(body.AssignmentID)
	valid := err == nil
	if command.PrincipalID, err = publicid.Parse(body.PrincipalID); err != nil {
		valid = false
	}
	if command.Role, err = authorization.ParseBuiltinRole(body.Role); err != nil {
		valid = false
	}
	if body.NetworkID != "" {
		if command.NetworkID, err = network.ParseID(body.NetworkID); err != nil {
			valid = false
		}
	}
	if body.ExpiresAt != "" {
		if command.ExpiresAt, err = time.Parse(time.RFC3339Nano, body.ExpiresAt); err != nil {
			valid = false
		}
		command.ExpiresAt = command.ExpiresAt.UTC().Truncate(time.Microsecond)
	}
	if !valid || !command.IsValid() {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	result, err := handler.workspaceRoles.Assign(ctx, command)
	if err != nil {
		return handler.writeWorkspaceRoleError(ctx, response, correlationID, err)
	}
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	response.Header().Set("ETag", strongVersionETag(result.Assignment.Version))
	writeManagementJSON(ctx, handler.logger, response, status, workspaceRoleAssignmentResponse{
		Data: assignmentData(result.Assignment), CorrelationID: correlationID.String(),
	})
	return "success"
}

func (handler *ManagementHandler) revokeWorkspaceRole(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, workspaceID workspace.ID, assignmentPath string,
	session accountsession.Session) string {
	expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *precondition)
		return precondition.Code
	}
	assignmentID, err := publicid.Parse(assignmentPath)
	if err != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	command := roles.RevokeCommand{Session: session, WorkspaceID: workspaceID, AssignmentID: assignmentID,
		ExpectedVersion: expectedVersion, CorrelationID: correlationID}
	if !command.IsValid() {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	result, err := handler.workspaceRoles.Revoke(ctx, command)
	if err != nil {
		return handler.writeWorkspaceRoleError(ctx, response, correlationID, err)
	}
	var output workspaceRoleRevocationResponse
	output.Data.ID = result.AssignmentID.String()
	output.Data.State = "revoked"
	output.Data.Version = result.Version
	output.CorrelationID = correlationID.String()
	response.Header().Set("ETag", strongVersionETag(result.Version))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

func decodeWorkspaceRoleBody(response http.ResponseWriter, request *http.Request, target any) bool {
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 4096))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && ensureJSONEnd(decoder) == nil
}

func (handler *ManagementHandler) writeWorkspaceRoleError(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, err error) string {
	failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
		Message: "The result is uncertain. Refresh Workspace members before trying again."}
	switch {
	case errors.Is(err, roles.ErrForbidden):
		failure = managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "Your role cannot make this change. Nobody can change their own roles."}
	case errors.Is(err, roles.ErrNotFound):
		failure = managementError{Status: http.StatusNotFound, Code: "not_found",
			Message: "The member, Network or role assignment is unavailable"}
	case errors.Is(err, roles.ErrConflict):
		failure = managementError{Status: http.StatusConflict, Code: "resource_conflict",
			Message: "This member already has that role, or the assignment changed. Refresh members."}
	case errors.Is(err, roles.ErrInvalid):
		failure = *invalidManagementRequest()
	}
	writeManagementError(ctx, handler.logger, response, correlationID, failure)
	return failure.Code
}

// isWorkspaceRoleOperation reports a role-management path with its allowed method.
func isWorkspaceRoleOperation(request *http.Request) bool {
	path, ok := parseWorkspaceRolePath(request)
	return ok && request.Method == path.allowedMethod()
}
