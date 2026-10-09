package httpapi

import (
	"context"
	"net/http"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/memberlifecycle"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

type memberRemovalDeviceRequest struct {
	DeviceID   *string `json:"device_id"`
	Action     *string `json:"action"`
	NewOwnerID *string `json:"new_owner_id"`
}

// parseMemberRemovalPlan reads each Device choice; the service checks the
// plan as a whole.
func parseMemberRemovalPlan(items []memberRemovalDeviceRequest) ([]memberlifecycle.DevicePlan, bool) {
	if len(items) > memberlifecycle.MaximumPlanDevices {
		return nil, false
	}
	plans := make([]memberlifecycle.DevicePlan, len(items))
	for index, item := range items {
		if item.DeviceID == nil || item.Action == nil {
			return nil, false
		}
		deviceID, deviceOK := canonicalPublicID(*item.DeviceID)
		if !deviceOK {
			return nil, false
		}
		plans[index] = memberlifecycle.DevicePlan{
			DeviceID: node.ID(deviceID), Action: memberlifecycle.DeviceAction(*item.Action),
		}
		if item.NewOwnerID != nil {
			owner, ownerOK := canonicalPublicID(*item.NewOwnerID)
			if !ownerOK {
				return nil, false
			}
			plans[index].NewOwnerID = owner
		}
		if !plans[index].IsValid() {
			return nil, false
		}
	}
	return plans, true
}

func (handler *ManagementHandler) handleMemberRemoval(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path memberLifecyclePath, session accountsession.Session) string {
	fail := func(failure managementError) string {
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	var body struct {
		Reason  *string                       `json:"reason"`
		Devices *[]memberRemovalDeviceRequest `json:"devices"`
	}
	if !readDeviceGroupBody(response, request, &body) || body.Reason == nil || body.Devices == nil {
		return fail(*invalidManagementRequest())
	}
	plans, ok := parseMemberRemovalPlan(*body.Devices)
	if !ok {
		return fail(*invalidManagementRequest())
	}
	result, err := handler.memberLifecycle.Remove(ctx, session, memberlifecycle.RemovalRequest{
		WorkspaceID: path.workspaceID, MemberID: path.memberID, Reason: *body.Reason, Devices: plans,
		CorrelationID: correlationID,
	})
	if err != nil {
		return fail(classifyMemberLifecycleError(err))
	}
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, struct {
		Data          memberRemovalResultBody `json:"data"`
		CorrelationID string                  `json:"correlation_id"`
	}{newMemberRemovalResultBody(result), correlationID.String()})
	return "success"
}

type memberRemovalDeviceBody struct {
	DeviceID  string `json:"device_id"`
	NetworkID string `json:"network_id"`
	Hostname  string `json:"hostname"`
	Action    string `json:"action"`
	State     string `json:"state"`
}

type memberRemovalResultBody struct {
	Member             memberLifecycleMemberBody `json:"member"`
	Devices            []memberRemovalDeviceBody `json:"devices"`
	HandoversCancelled int                       `json:"handovers_cancelled"`
	KeysRevoked        int                       `json:"enrollment_keys_revoked"`
	GroupsLeft         int                       `json:"identity_groups_left"`
	RolesRevoked       int                       `json:"roles_revoked"`
	SessionsEnded      int                       `json:"sessions_ended"`
	NetworkCount       int                       `json:"network_count"`
}

func newMemberRemovalResultBody(result memberlifecycle.RemovalResult) memberRemovalResultBody {
	devices := make([]memberRemovalDeviceBody, len(result.Devices))
	for index, device := range result.Devices {
		devices[index] = memberRemovalDeviceBody{
			DeviceID: device.DeviceID.String(), NetworkID: device.NetworkID.String(), Hostname: device.Hostname,
			Action: string(device.Action), State: device.State,
		}
	}
	return memberRemovalResultBody{
		Member: memberLifecycleMemberBody{
			PrincipalID: result.After.PrincipalID.String(), State: result.After.State, Version: result.After.Version,
		},
		Devices: devices, HandoversCancelled: result.HandoversCancelled, KeysRevoked: result.KeysRevoked,
		GroupsLeft: result.GroupsLeft, RolesRevoked: result.RolesRevoked, SessionsEnded: result.SessionsEnded,
		NetworkCount: len(result.Networks),
	}
}
