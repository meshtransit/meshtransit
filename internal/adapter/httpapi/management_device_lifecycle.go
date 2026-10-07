package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/devicelifecycle"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

// DeviceLifecycleManager suspends, resumes, transfers and renames Devices.
type DeviceLifecycleManager interface {
	Change(context.Context, accountsession.Session, devicelifecycle.Request) (devicelifecycle.Result, error)
}

type deviceLifecyclePath struct {
	scope    network.Scope
	deviceID node.ID
	action   string
}

// deviceLifecycleActions are the actions a path may name.
var deviceLifecycleActions = map[string]bool{"suspend": true, "resume": true, "transfer": true, "rename": true}

// parseDeviceLifecyclePath matches, with no query,
//
//	POST /api/v1/workspaces/{ws}/networks/{net}/devices/{device}/actions/{suspend|resume|transfer|rename}
func parseDeviceLifecyclePath(request *http.Request) (deviceLifecyclePath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		return deviceLifecyclePath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) != 10 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" ||
		segments[4] != "networks" || segments[6] != "devices" || segments[8] != "actions" ||
		!deviceLifecycleActions[segments[9]] {
		return deviceLifecyclePath{}, false
	}
	workspaceID, workspaceOK := canonicalPublicID(segments[3])
	networkID, networkOK := canonicalPublicID(segments[5])
	deviceID, deviceOK := canonicalPublicID(segments[7])
	if !workspaceOK || !networkOK || !deviceOK {
		return deviceLifecyclePath{}, false
	}
	scope, err := network.NewScope(workspace.ID(workspaceID), network.ID(networkID))
	if err != nil {
		return deviceLifecyclePath{}, false
	}
	return deviceLifecyclePath{scope: scope, deviceID: node.ID(deviceID), action: segments[9]}, true
}

// isDeviceLifecycleOperation admits only POST to a lifecycle action.
func isDeviceLifecycleOperation(request *http.Request) bool {
	_, ok := parseDeviceLifecyclePath(request)
	return ok && request.Method == http.MethodPost
}

func (path deviceLifecyclePath) operation() string { return "device_" + path.action }

func (handler *ManagementHandler) handleDeviceLifecycle(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path deviceLifecyclePath, session accountsession.Session) string {
	fail := func(failure managementError) string {
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	response.Header().Set("Cache-Control", "no-store")
	if nilContinuationDependency(handler.deviceLifecycle) {
		return fail(managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Device changes are temporarily unavailable", Retryable: true})
	}
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		return fail(managementError{Status: http.StatusMethodNotAllowed, Code: "method_not_allowed",
			Message: "the method is not allowed"})
	}
	expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		return fail(*precondition)
	}
	lifecycle, ok := parseDeviceLifecycleBody(response, request, path)
	if !ok {
		return fail(*invalidManagementRequest())
	}
	lifecycle.Scope, lifecycle.DeviceID, lifecycle.ExpectedVersion, lifecycle.CorrelationID =
		path.scope, path.deviceID, expectedVersion, correlationID
	result, err := handler.deviceLifecycle.Change(ctx, session, lifecycle)
	if err != nil {
		return fail(classifyDeviceLifecycleError(err))
	}
	response.Header().Set("ETag", strongVersionETag(result.After.Version))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, struct {
		Data struct {
			Device          deviceLifecycleBody `json:"device"`
			NetworkRevision int64               `json:"network_revision"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}{Data: struct {
		Device          deviceLifecycleBody `json:"device"`
		NetworkRevision int64               `json:"network_revision"`
	}{newDeviceLifecycleBody(result.After), result.NetworkRevision}, CorrelationID: correlationID.String()})
	return "success"
}

// parseDeviceLifecycleBody reads the action's exact body:
//
//	suspend, resume  {"reason"}
//	transfer         {"to": "workspace"|"member", "principal_id" (member only), "reason"}
//	rename           {"hostname", "reason" (optional)}
func parseDeviceLifecycleBody(response http.ResponseWriter, request *http.Request,
	path deviceLifecyclePath) (devicelifecycle.Request, bool) {
	var body struct {
		Reason      *string `json:"reason"`
		To          *string `json:"to"`
		PrincipalID *string `json:"principal_id"`
		Hostname    *string `json:"hostname"`
	}
	if !readDeviceGroupBody(response, request, &body) {
		return devicelifecycle.Request{}, false
	}
	var lifecycle devicelifecycle.Request
	if body.Reason != nil {
		lifecycle.Reason = *body.Reason
	}
	switch path.action {
	case "suspend", "resume":
		lifecycle.Action = devicelifecycle.ActionSuspend
		if path.action == "resume" {
			lifecycle.Action = devicelifecycle.ActionResume
		}
		return lifecycle, body.Reason != nil && body.To == nil && body.PrincipalID == nil && body.Hostname == nil
	case "transfer":
		if body.Reason == nil || body.To == nil || body.Hostname != nil {
			return devicelifecycle.Request{}, false
		}
		switch *body.To {
		case "workspace":
			lifecycle.Action = devicelifecycle.ActionTransferWorkspace
			return lifecycle, body.PrincipalID == nil
		case "member":
			if body.PrincipalID == nil {
				return devicelifecycle.Request{}, false
			}
			owner, ok := canonicalPublicID(*body.PrincipalID)
			lifecycle.Action, lifecycle.NewOwner = devicelifecycle.ActionTransferMember, owner
			return lifecycle, ok
		default:
			return devicelifecycle.Request{}, false
		}
	default:
		if body.Hostname == nil || body.To != nil || body.PrincipalID != nil {
			return devicelifecycle.Request{}, false
		}
		hostname, err := node.ParseHostname(*body.Hostname)
		lifecycle.Action, lifecycle.Hostname = devicelifecycle.ActionRename, hostname
		return lifecycle, err == nil
	}
}

type deviceLifecycleBody struct {
	DeviceID        string  `json:"device_id"`
	Hostname        string  `json:"hostname"`
	State           string  `json:"state"`
	Ownership       string  `json:"ownership"`
	OwnerID         *string `json:"owner_principal_id"`
	SuspendedReason *string `json:"suspended_reason"`
	HandoverTo      *string `json:"handover_principal_id"`
	ExpiresAt       string  `json:"expires_at"`
	Version         int64   `json:"version"`
}

func newDeviceLifecycleBody(state devicelifecycle.State) deviceLifecycleBody {
	body := deviceLifecycleBody{
		DeviceID: state.DeviceID.String(), Hostname: state.Hostname, State: state.State,
		Ownership: string(state.Ownership), ExpiresAt: state.ExpiresAt.UTC().Format(time.RFC3339),
		Version: state.Version,
	}
	if state.Owner.IsValid() {
		owner := state.Owner.String()
		body.OwnerID = &owner
	}
	if state.SuspendedReason != "" {
		reason := string(state.SuspendedReason)
		body.SuspendedReason = &reason
	}
	if state.HandoverTo.IsValid() {
		handover := state.HandoverTo.String()
		body.HandoverTo = &handover
	}
	return body
}

func classifyDeviceLifecycleError(err error) managementError {
	switch {
	case errors.Is(err, devicelifecycle.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot make this change to the Device"}
	case errors.Is(err, devicelifecycle.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "device_not_found",
			Message: "The Device no longer exists"}
	case errors.Is(err, devicelifecycle.ErrVersionConflict):
		return managementError{Status: http.StatusPreconditionFailed, Code: "version_conflict",
			Message: "The Device changed. Reload and review it again."}
	case errors.Is(err, devicelifecycle.ErrWrongState):
		return managementError{Status: http.StatusConflict, Code: "device_state_conflict",
			Message: "The Device's state does not allow this change"}
	case errors.Is(err, devicelifecycle.ErrIneligibleOwner):
		return managementError{Status: http.StatusUnprocessableEntity, Code: "owner_not_eligible",
			Message: "The new owner must be an active member of this Workspace and Network"}
	case errors.Is(err, devicelifecycle.ErrHostnameTaken):
		return managementError{Status: http.StatusConflict, Code: "hostname_taken",
			Message: "Another Device in this Network has that name"}
	case errors.Is(err, devicelifecycle.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload before trying again.", Retryable: true}
	}
}
