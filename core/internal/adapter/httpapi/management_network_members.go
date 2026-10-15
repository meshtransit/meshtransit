package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/memberlifecycle"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	networkMemberListOperation   = "network_member_list"
	networkMemberAddOperation    = "network_member_add"
	networkMemberRemoveOperation = "network_member_remove"
)

// NetworkMemberManager lists, adds and removes the members of one Network.
type NetworkMemberManager interface {
	List(context.Context, accountsession.Session, network.Scope, publicid.ID, int) (
		memberlifecycle.NetworkMemberPage, error)
	Add(context.Context, accountsession.Session, network.Scope, []publicid.ID, publicid.ID) (
		memberlifecycle.NetworkAdditionResult, error)
	Remove(context.Context, accountsession.Session, memberlifecycle.NetworkRemovalRequest) (
		memberlifecycle.NetworkRemovalResult, error)
}

type networkMemberPath struct {
	scope network.Scope
	// kind is "list", "add" or "remove".
	kind     string
	memberID publicid.ID
	after    publicid.ID
	limit    int
}

// parseNetworkMemberPath matches, under /api/v1/workspaces/{ws}/networks/{net}:
// GET members[?after=&limit=], POST members/actions/add and
// POST members/{principal}/actions/remove. Only the list takes a query, and
// only those two keys once each.
func parseNetworkMemberPath(request *http.Request) (networkMemberPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" {
		return networkMemberPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) < 7 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" ||
		segments[4] != "networks" || segments[6] != "members" {
		return networkMemberPath{}, false
	}
	workspaceID, workspaceOK := canonicalPublicID(segments[3])
	networkID, networkOK := canonicalPublicID(segments[5])
	if !workspaceOK || !networkOK {
		return networkMemberPath{}, false
	}
	scope, err := network.NewScope(workspace.ID(workspaceID), network.ID(networkID))
	if err != nil {
		return networkMemberPath{}, false
	}
	path := networkMemberPath{scope: scope}
	rest := segments[7:]
	switch {
	case len(rest) == 0:
		path.kind = "list"
		return path.withPage(request.URL.RawQuery)
	case len(rest) == 2 && rest[0] == "actions" && rest[1] == "add":
		path.kind = "add"
	case len(rest) == 3 && rest[1] == "actions" && rest[2] == "remove":
		member, ok := canonicalPublicID(rest[0])
		if !ok {
			return networkMemberPath{}, false
		}
		path.kind, path.memberID = "remove", member
	default:
		return networkMemberPath{}, false
	}
	return path, request.URL.RawQuery == ""
}

func (path networkMemberPath) withPage(rawQuery string) (networkMemberPath, bool) {
	path.limit = memberlifecycle.DefaultNetworkMemberPage
	if rawQuery == "" {
		return path, true
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return networkMemberPath{}, false
	}
	for key, items := range values {
		if (key != "after" && key != "limit") || len(items) != 1 || items[0] == "" {
			return networkMemberPath{}, false
		}
	}
	if value := values.Get("after"); value != "" {
		after, ok := canonicalPublicID(value)
		if !ok {
			return networkMemberPath{}, false
		}
		path.after = after
	}
	if value := values.Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || strconv.Itoa(limit) != value || limit < 1 || limit > memberlifecycle.MaximumNetworkMemberPage {
			return networkMemberPath{}, false
		}
		path.limit = limit
	}
	return path, true
}

func (path networkMemberPath) allowedMethod() string {
	if path.kind == "list" {
		return http.MethodGet
	}
	return http.MethodPost
}

func (path networkMemberPath) operation() string {
	switch path.kind {
	case "list":
		return networkMemberListOperation
	case "add":
		return networkMemberAddOperation
	default:
		return networkMemberRemoveOperation
	}
}

// isNetworkMemberOperation admits only the method each path allows.
func isNetworkMemberOperation(request *http.Request) bool {
	path, ok := parseNetworkMemberPath(request)
	return ok && request.Method == path.allowedMethod()
}

// isNetworkMemberRead admits the bounded member page.
func isNetworkMemberRead(request *http.Request) bool {
	path, ok := parseNetworkMemberPath(request)
	return ok && request.Method == http.MethodGet && path.kind == "list"
}

// parseNetworkMemberIDs reads a bounded list of canonical principal IDs,
// each named once.
func parseNetworkMemberIDs(texts []string) ([]publicid.ID, bool) {
	if len(texts) == 0 || len(texts) > memberlifecycle.MaximumNetworkAdditions {
		return nil, false
	}
	ids := make([]publicid.ID, len(texts))
	seen := make(map[publicid.ID]bool, len(texts))
	for index, text := range texts {
		id, ok := canonicalPublicID(text)
		if !ok || seen[id] {
			return nil, false
		}
		seen[id] = true
		ids[index] = id
	}
	return ids, true
}

func (handler *ManagementHandler) handleNetworkMembers(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path networkMemberPath, session accountsession.Session) string {
	fail := func(failure managementError) string {
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	response.Header().Set("Cache-Control", "no-store")
	if nilContinuationDependency(handler.networkMembers) {
		return fail(managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Network members are temporarily unavailable", Retryable: true})
	}
	switch path.kind {
	case "list":
		page, err := handler.networkMembers.List(ctx, session, path.scope, path.after, path.limit)
		if err != nil {
			return fail(classifyNetworkMemberError(err))
		}
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, struct {
			Data          networkMemberPageBody `json:"data"`
			CorrelationID string                `json:"correlation_id"`
		}{newNetworkMemberPageBody(path.scope, page), correlationID.String()})
	case "add":
		var body struct {
			PrincipalIDs *[]string `json:"principal_ids"`
		}
		if !readDeviceGroupBody(response, request, &body) || body.PrincipalIDs == nil {
			return fail(*invalidManagementRequest())
		}
		members, ok := parseNetworkMemberIDs(*body.PrincipalIDs)
		if !ok {
			return fail(*invalidManagementRequest())
		}
		result, err := handler.networkMembers.Add(ctx, session, path.scope, members, correlationID)
		if err != nil {
			return fail(classifyNetworkMemberError(err))
		}
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, struct {
			Data          networkMemberAdditionBody `json:"data"`
			CorrelationID string                    `json:"correlation_id"`
		}{newNetworkMemberAdditionBody(path.scope, result), correlationID.String()})
	default:
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
		result, err := handler.networkMembers.Remove(ctx, session, memberlifecycle.NetworkRemovalRequest{
			Scope: path.scope, MemberID: path.memberID, Reason: *body.Reason, Devices: plans,
			CorrelationID: correlationID,
		})
		if err != nil {
			return fail(classifyNetworkMemberError(err))
		}
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, struct {
			Data          networkMemberRemovalBody `json:"data"`
			CorrelationID string                   `json:"correlation_id"`
		}{newNetworkMemberRemovalBody(result), correlationID.String()})
	}
	return "success"
}

type networkMembershipBody struct {
	MembershipID string `json:"membership_id"`
	PrincipalID  string `json:"principal_id"`
	State        string `json:"state"`
	Version      int64  `json:"version"`
	AddedAt      string `json:"added_at"`
}

func newNetworkMembershipBody(membership memberlifecycle.NetworkMembership) networkMembershipBody {
	return networkMembershipBody{
		MembershipID: membership.MembershipID.String(), PrincipalID: membership.PrincipalID.String(),
		State: membership.State, Version: membership.Version, AddedAt: managementTime(membership.AddedAt),
	}
}

type networkMemberBody struct {
	PrincipalID    string                 `json:"principal_id"`
	DisplayName    string                 `json:"display_name"`
	WorkspaceState string                 `json:"workspace_membership_state"`
	Owner          bool                   `json:"owner"`
	Membership     *networkMembershipBody `json:"network_membership"`
}

type networkMemberPageBody struct {
	NetworkID string              `json:"network_id"`
	CanManage bool                `json:"can_manage"`
	Members   []networkMemberBody `json:"members"`
	Next      string              `json:"next_after,omitempty"`
}

func newNetworkMemberPageBody(scope network.Scope, page memberlifecycle.NetworkMemberPage) networkMemberPageBody {
	members := make([]networkMemberBody, len(page.Members))
	for index, member := range page.Members {
		members[index] = networkMemberBody{
			PrincipalID: member.PrincipalID.String(), DisplayName: member.DisplayName,
			WorkspaceState: member.WorkspaceState, Owner: member.Owner,
		}
		if member.Membership != nil {
			body := newNetworkMembershipBody(*member.Membership)
			members[index].Membership = &body
		}
	}
	body := networkMemberPageBody{NetworkID: scope.NetworkID().String(), CanManage: page.CanManage, Members: members}
	if page.HasMore && len(page.Members) > 0 {
		body.Next = page.Members[len(page.Members)-1].PrincipalID.String()
	}
	return body
}

type networkMemberAdditionBody struct {
	NetworkID string                  `json:"network_id"`
	Added     []networkMembershipBody `json:"added"`
	Unchanged []string                `json:"unchanged"`
}

func newNetworkMemberAdditionBody(scope network.Scope,
	result memberlifecycle.NetworkAdditionResult) networkMemberAdditionBody {
	added := make([]networkMembershipBody, len(result.Added))
	for index, membership := range result.Added {
		added[index] = newNetworkMembershipBody(membership)
	}
	unchanged := make([]string, len(result.Unchanged))
	for index, member := range result.Unchanged {
		unchanged[index] = member.String()
	}
	return networkMemberAdditionBody{NetworkID: scope.NetworkID().String(), Added: added, Unchanged: unchanged}
}

type networkRemovedDeviceBody struct {
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
	Action   string `json:"action"`
	State    string `json:"state"`
}

type networkMemberRemovalBody struct {
	Member             networkRemovedMemberBody   `json:"member"`
	Devices            []networkRemovedDeviceBody `json:"devices"`
	HandoversCancelled int                        `json:"handovers_cancelled"`
	KeysRevoked        int                        `json:"enrollment_keys_revoked"`
	RolesRevoked       int                        `json:"roles_revoked"`
	NetworkRevision    int64                      `json:"network_revision"`
}

type networkRemovedMemberBody struct {
	MembershipID string `json:"membership_id"`
	PrincipalID  string `json:"principal_id"`
	State        string `json:"state"`
	Version      int64  `json:"version"`
}

func newNetworkMemberRemovalBody(result memberlifecycle.NetworkRemovalResult) networkMemberRemovalBody {
	devices := make([]networkRemovedDeviceBody, len(result.Devices))
	for index, device := range result.Devices {
		devices[index] = networkRemovedDeviceBody{
			DeviceID: device.DeviceID.String(), Hostname: device.Hostname, Action: string(device.Action),
			State: device.State,
		}
	}
	return networkMemberRemovalBody{
		Member: networkRemovedMemberBody{
			MembershipID: result.After.MembershipID.String(), PrincipalID: result.After.PrincipalID.String(),
			State: result.After.State, Version: result.After.Version,
		},
		Devices: devices, HandoversCancelled: result.HandoversCancelled, KeysRevoked: result.KeysRevoked,
		RolesRevoked: result.RolesRevoked, NetworkRevision: result.Network.NetworkRevision,
	}
}

func classifyNetworkMemberError(err error) managementError {
	switch {
	case errors.Is(err, memberlifecycle.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot change the members of this Network"}
	case errors.Is(err, memberlifecycle.ErrProtected):
		return managementError{Status: http.StatusForbidden, Code: "member_protected",
			Message: "Nobody can remove the owner or themselves from a Network"}
	case errors.Is(err, memberlifecycle.ErrPlan):
		return managementError{Status: http.StatusConflict, Code: "device_plan_conflict",
			Message: "A Device in the plan is not the member's in this Network, or cannot take that action. " +
				"Reload the Devices."}
	case errors.Is(err, memberlifecycle.ErrNewOwner):
		return managementError{Status: http.StatusConflict, Code: "new_owner_unavailable",
			Message: "The new owner is not an active member of this Network"}
	case errors.Is(err, memberlifecycle.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "member_not_found",
			Message: "The person is not a member of this Workspace or Network"}
	case errors.Is(err, memberlifecycle.ErrWrongState):
		return managementError{Status: http.StatusConflict, Code: "member_state_conflict",
			Message: "A suspended Workspace member cannot join a Network"}
	case errors.Is(err, memberlifecycle.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload before trying again.", Retryable: true}
	}
}
