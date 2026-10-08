package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/memberlifecycle"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

// MemberLifecycleManager suspends, resumes and removes Workspace members.
type MemberLifecycleManager interface {
	Change(context.Context, accountsession.Session, memberlifecycle.Request) (memberlifecycle.Result, error)
	Remove(context.Context, accountsession.Session, memberlifecycle.RemovalRequest) (
		memberlifecycle.RemovalResult, error)
}

type memberLifecyclePath struct {
	workspaceID workspace.ID
	memberID    publicid.ID
	action      memberlifecycle.Action
}

// parseMemberLifecyclePath matches, with no query,
//
//	POST /api/v1/workspaces/{ws}/members/{principal}/actions/{suspend|resume|remove}
func parseMemberLifecyclePath(request *http.Request) (memberLifecyclePath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		return memberLifecyclePath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) != 8 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" ||
		segments[4] != "members" || segments[6] != "actions" {
		return memberLifecyclePath{}, false
	}
	action := memberlifecycle.Action(segments[7])
	if action != memberlifecycle.ActionSuspend && action != memberlifecycle.ActionResume &&
		action != memberlifecycle.ActionRemove {
		return memberLifecyclePath{}, false
	}
	workspaceID, workspaceOK := canonicalPublicID(segments[3])
	memberID, memberOK := canonicalPublicID(segments[5])
	if !workspaceOK || !memberOK {
		return memberLifecyclePath{}, false
	}
	return memberLifecyclePath{workspaceID: workspace.ID(workspaceID), memberID: memberID, action: action}, true
}

// isMemberLifecycleOperation admits only POST to a member action.
func isMemberLifecycleOperation(request *http.Request) bool {
	_, ok := parseMemberLifecyclePath(request)
	return ok && request.Method == http.MethodPost
}

func (path memberLifecyclePath) operation() string { return "workspace_member_" + string(path.action) }

func (handler *ManagementHandler) handleMemberLifecycle(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path memberLifecyclePath, session accountsession.Session) string {
	fail := func(failure managementError) string {
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	response.Header().Set("Cache-Control", "no-store")
	if nilContinuationDependency(handler.memberLifecycle) {
		return fail(managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Member changes are temporarily unavailable", Retryable: true})
	}
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		return fail(managementError{Status: http.StatusMethodNotAllowed, Code: "method_not_allowed",
			Message: "the method is not allowed"})
	}
	if path.action == memberlifecycle.ActionRemove {
		return handler.handleMemberRemoval(ctx, response, request, correlationID, path, session)
	}
	var body struct {
		Reason *string `json:"reason"`
	}
	if !readDeviceGroupBody(response, request, &body) || body.Reason == nil {
		return fail(*invalidManagementRequest())
	}
	result, err := handler.memberLifecycle.Change(ctx, session, memberlifecycle.Request{
		WorkspaceID: path.workspaceID, MemberID: path.memberID, Action: path.action, Reason: *body.Reason,
		CorrelationID: correlationID,
	})
	if err != nil {
		return fail(classifyMemberLifecycleError(err))
	}
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, struct {
		Data          memberLifecycleResultBody `json:"data"`
		CorrelationID string                    `json:"correlation_id"`
	}{newMemberLifecycleResultBody(result), correlationID.String()})
	return "success"
}

type memberLifecycleMemberBody struct {
	PrincipalID string  `json:"principal_id"`
	State       string  `json:"membership_state"`
	ExpiresAt   *string `json:"membership_expires_at"`
	Version     int64   `json:"version"`
}

type memberLifecycleDeviceBody struct {
	DeviceID  string `json:"device_id"`
	NetworkID string `json:"network_id"`
	Hostname  string `json:"hostname"`
	State     string `json:"state"`
}

type memberLifecycleResultBody struct {
	Member        memberLifecycleMemberBody   `json:"member"`
	Devices       []memberLifecycleDeviceBody `json:"devices"`
	SessionsEnded int                         `json:"sessions_ended"`
	NetworkCount  int                         `json:"network_count"`
}

func newMemberLifecycleResultBody(result memberlifecycle.Result) memberLifecycleResultBody {
	member := memberLifecycleMemberBody{
		PrincipalID: result.After.PrincipalID.String(), State: result.After.State, Version: result.After.Version,
	}
	if result.After.ExpiresAt != nil {
		expires := result.After.ExpiresAt.UTC().Format(time.RFC3339)
		member.ExpiresAt = &expires
	}
	devices := make([]memberLifecycleDeviceBody, len(result.Devices))
	for index, device := range result.Devices {
		devices[index] = memberLifecycleDeviceBody{
			DeviceID: device.DeviceID.String(), NetworkID: device.NetworkID.String(), Hostname: device.Hostname,
			State: device.State,
		}
	}
	return memberLifecycleResultBody{
		Member: member, Devices: devices, SessionsEnded: result.SessionsEnded, NetworkCount: len(result.Networks),
	}
}

func classifyMemberLifecycleError(err error) managementError {
	switch {
	case errors.Is(err, memberlifecycle.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot make this change to the member"}
	case errors.Is(err, memberlifecycle.ErrProtected):
		return managementError{Status: http.StatusForbidden, Code: "member_protected",
			Message: "Nobody can suspend or remove the owner or themselves"}
	case errors.Is(err, memberlifecycle.ErrPlan):
		return managementError{Status: http.StatusConflict, Code: "device_plan_conflict",
			Message: "A Device in the plan is not the member's, or cannot take that action. Reload the Devices."}
	case errors.Is(err, memberlifecycle.ErrNewOwner):
		return managementError{Status: http.StatusConflict, Code: "new_owner_unavailable",
			Message: "The new owner is not an active member of the Device's Network"}
	case errors.Is(err, memberlifecycle.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "member_not_found",
			Message: "The member is no longer in this Workspace"}
	case errors.Is(err, memberlifecycle.ErrWrongState):
		return managementError{Status: http.StatusConflict, Code: "member_state_conflict",
			Message: "The member's state does not allow this change"}
	case errors.Is(err, memberlifecycle.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload before trying again.", Retryable: true}
	}
}
