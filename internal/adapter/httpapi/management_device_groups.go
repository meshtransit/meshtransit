package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/devicegroup"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const (
	deviceGroupListOperation    = "device_group_list"
	deviceGroupMembersOperation = "device_group_members"
	deviceGroupCreateOperation  = "device_group_create"
	deviceGroupUpdateOperation  = "device_group_update"
	deviceGroupDeleteOperation  = "device_group_delete"
	deviceGroupChangeOperation  = "device_group_change_members"
	maximumDeviceGroupBodyBytes = 64 << 10
	defaultDeviceGroupPage      = 100
)

// DeviceGroupManager lists and changes Network Device Groups.
type DeviceGroupManager interface {
	List(context.Context, accountsession.Session, network.Scope) (devicegroup.Listing, error)
	Members(context.Context, accountsession.Session, network.Scope, devicegroup.ID, node.ID,
		int) (devicegroup.MemberPage, error)
	Create(context.Context, accountsession.Session, network.Scope, devicegroup.Definition,
		publicid.ID) (devicegroup.Result, error)
	Update(context.Context, accountsession.Session, network.Scope, devicegroup.ID, int64, devicegroup.Definition,
		publicid.ID) (devicegroup.Result, error)
	Delete(context.Context, accountsession.Session, network.Scope, devicegroup.ID, int64,
		publicid.ID) (devicegroup.Result, error)
	ChangeMembers(context.Context, accountsession.Session, network.Scope, devicegroup.ID, int64, []node.ID,
		[]node.ID, publicid.ID) (devicegroup.MembershipResult, error)
}

type deviceGroupPath struct {
	scope   network.Scope
	groupID devicegroup.ID
	// action is "" to list, "members", "create", "update", "delete" or "change-members".
	action string
	after  node.ID
	limit  int
}

// parseDeviceGroupPath matches, under /api/v1/workspaces/{ws}/networks/{net}:
// GET device-groups, POST device-groups/actions/create,
// GET device-groups/{id}/members[?after=&limit=] and
// POST device-groups/{id}/actions/{update|delete|change-members}.
// Only the member page takes a query, and only those two keys once each.
func parseDeviceGroupPath(request *http.Request) (deviceGroupPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" {
		return deviceGroupPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) < 7 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" ||
		segments[4] != "networks" || segments[6] != "device-groups" {
		return deviceGroupPath{}, false
	}
	workspaceID, err := workspace.ParseID(segments[3])
	if err != nil || workspaceID.String() != segments[3] {
		return deviceGroupPath{}, false
	}
	networkID, err := network.ParseID(segments[5])
	if err != nil || networkID.String() != segments[5] {
		return deviceGroupPath{}, false
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return deviceGroupPath{}, false
	}
	path := deviceGroupPath{scope: scope}
	rest := segments[7:]
	switch {
	case len(rest) == 0:
	case len(rest) == 2 && rest[0] == "actions" && rest[1] == "create":
		path.action = "create"
	case len(rest) == 2 && rest[1] == "members":
		path.action = "members"
	case len(rest) == 3 && rest[1] == "actions" &&
		(rest[2] == "update" || rest[2] == "delete" || rest[2] == "change-members"):
		path.action = rest[2]
	default:
		return deviceGroupPath{}, false
	}
	if path.action != "" && path.action != "create" {
		id, err := devicegroup.ParseID(rest[0])
		if err != nil || id.String() != rest[0] {
			return deviceGroupPath{}, false
		}
		path.groupID = id
	}
	if path.action != "members" {
		return path, request.URL.RawQuery == ""
	}
	return path.withPage(request.URL.RawQuery)
}

func (path deviceGroupPath) withPage(rawQuery string) (deviceGroupPath, bool) {
	path.limit = defaultDeviceGroupPage
	if rawQuery == "" {
		return path, true
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return deviceGroupPath{}, false
	}
	for key, items := range values {
		if (key != "after" && key != "limit") || len(items) != 1 || items[0] == "" {
			return deviceGroupPath{}, false
		}
	}
	if value := values.Get("after"); value != "" {
		after, err := node.ParseID(value)
		if err != nil || after.String() != value {
			return deviceGroupPath{}, false
		}
		path.after = after
	}
	if value := values.Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || strconv.Itoa(limit) != value || limit < 1 || limit > devicegroup.MaximumMemberPage {
			return deviceGroupPath{}, false
		}
		path.limit = limit
	}
	return path, true
}

func (path deviceGroupPath) allowedMethod() string {
	if path.action == "" || path.action == "members" {
		return http.MethodGet
	}
	return http.MethodPost
}

func (path deviceGroupPath) operation() string {
	switch path.action {
	case "":
		return deviceGroupListOperation
	case "members":
		return deviceGroupMembersOperation
	case "create":
		return deviceGroupCreateOperation
	case "update":
		return deviceGroupUpdateOperation
	case "delete":
		return deviceGroupDeleteOperation
	default:
		return deviceGroupChangeOperation
	}
}

// isDeviceGroupOperation admits only the method each path allows.
func isDeviceGroupOperation(request *http.Request) bool {
	path, ok := parseDeviceGroupPath(request)
	return ok && request.Method == path.allowedMethod()
}

// isDeviceGroupRead admits the list and the bounded member page.
func isDeviceGroupRead(request *http.Request) bool {
	path, ok := parseDeviceGroupPath(request)
	return ok && request.Method == http.MethodGet && path.allowedMethod() == http.MethodGet
}

type deviceGroupBody struct {
	GroupID     string `json:"group_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MemberCount int    `json:"member_count"`
	RuleCount   int    `json:"rule_count"`
	Version     int64  `json:"version"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func newDeviceGroupBody(group devicegroup.Group) deviceGroupBody {
	return deviceGroupBody{
		GroupID: group.ID.String(), Name: group.Name, Description: group.Description,
		MemberCount: group.MemberCount, RuleCount: group.RuleCount, Version: group.Version,
		CreatedAt: managementTime(group.CreatedAt), UpdatedAt: managementTime(group.UpdatedAt),
	}
}

func readDeviceGroupBody(response http.ResponseWriter, request *http.Request, target any) bool {
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maximumDeviceGroupBodyBytes))
	if err != nil {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && ensureJSONEnd(decoder) == nil
}

func parseDeviceGroupDefinition(response http.ResponseWriter, request *http.Request) (devicegroup.Definition, bool) {
	var body struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if !readDeviceGroupBody(response, request, &body) || body.Name == nil || body.Description == nil {
		return devicegroup.Definition{}, false
	}
	definition := devicegroup.Definition{Name: *body.Name, Description: *body.Description}
	return definition, definition.IsValid()
}

func parseDeviceIDs(texts []string) ([]node.ID, bool) {
	if len(texts) > devicegroup.MaximumMembersPerChange {
		return nil, false
	}
	ids := make([]node.ID, len(texts))
	for index, text := range texts {
		id, err := node.ParseID(text)
		if err != nil || id.String() != text {
			return nil, false
		}
		ids[index] = id
	}
	return ids, true
}

func parseDeviceGroupMembership(response http.ResponseWriter, request *http.Request) ([]node.ID, []node.ID, bool) {
	var body struct {
		Add    *[]string `json:"add"`
		Remove *[]string `json:"remove"`
	}
	if !readDeviceGroupBody(response, request, &body) || body.Add == nil || body.Remove == nil {
		return nil, nil, false
	}
	add, addOK := parseDeviceIDs(*body.Add)
	remove, removeOK := parseDeviceIDs(*body.Remove)
	return add, remove, addOK && removeOK && len(add)+len(remove) > 0
}

func (handler *ManagementHandler) handleDeviceGroups(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path deviceGroupPath, session accountsession.Session) string {
	fail := func(failure managementError) string {
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	if nilContinuationDependency(handler.deviceGroups) {
		return fail(managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Device Groups are temporarily unavailable", Retryable: true})
	}
	response.Header().Set("Cache-Control", "no-store")
	switch path.action {
	case "":
		listing, err := handler.deviceGroups.List(ctx, session, path.scope)
		if err != nil {
			return fail(classifyDeviceGroupError(err))
		}
		bodies := make([]deviceGroupBody, 0, len(listing.Groups))
		for _, group := range listing.Groups {
			bodies = append(bodies, newDeviceGroupBody(group))
		}
		var output struct {
			Data struct {
				Groups           []deviceGroupBody `json:"groups"`
				CanManage        bool              `json:"can_manage"`
				CanManageMembers bool              `json:"can_manage_members"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}
		output.Data.Groups, output.CorrelationID = bodies, correlationID.String()
		output.Data.CanManage, output.Data.CanManageMembers = listing.CanManage, listing.CanManageMembers
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
		return "success"
	case "members":
		page, err := handler.deviceGroups.Members(ctx, session, path.scope, path.groupID, path.after, path.limit)
		if err != nil {
			return fail(classifyDeviceGroupError(err))
		}
		type memberBody struct {
			DeviceID string `json:"device_id"`
			Name     string `json:"name"`
			Active   bool   `json:"active"`
			AddedAt  string `json:"added_at"`
		}
		members := make([]memberBody, 0, len(page.Members))
		for _, member := range page.Members {
			members = append(members, memberBody{
				DeviceID: member.DeviceID.String(), Name: member.Name, Active: member.Active,
				AddedAt: managementTime(member.AddedAt),
			})
		}
		var output struct {
			Data struct {
				Group   deviceGroupBody `json:"group"`
				Members []memberBody    `json:"members"`
				Next    string          `json:"next_after,omitempty"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}
		output.Data.Group, output.Data.Members = newDeviceGroupBody(page.Group), members
		if page.HasMore && len(page.Members) > 0 {
			output.Data.Next = page.Members[len(page.Members)-1].DeviceID.String()
		}
		output.CorrelationID = correlationID.String()
		response.Header().Set("ETag", strongVersionETag(page.Group.Version))
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
		return "success"
	case "change-members":
		return handler.changeDeviceGroupMembers(ctx, response, request, correlationID, path, session, fail)
	}

	var result devicegroup.Result
	var err error
	if path.action == "create" {
		definition, valid := parseDeviceGroupDefinition(response, request)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		result, err = handler.deviceGroups.Create(ctx, session, path.scope, definition, correlationID)
	} else {
		expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
		if precondition != nil {
			return fail(*precondition)
		}
		if path.action == "update" {
			definition, valid := parseDeviceGroupDefinition(response, request)
			if !valid {
				return fail(*invalidManagementRequest())
			}
			result, err = handler.deviceGroups.Update(ctx, session, path.scope, path.groupID, expectedVersion,
				definition, correlationID)
		} else {
			result, err = handler.deviceGroups.Delete(ctx, session, path.scope, path.groupID, expectedVersion,
				correlationID)
		}
	}
	if err != nil {
		return fail(classifyDeviceGroupError(err))
	}
	var output struct {
		Data struct {
			Group   deviceGroupBody `json:"group"`
			Deleted bool            `json:"deleted"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Group, output.Data.Deleted = newDeviceGroupBody(result.Group), result.Deleted
	output.CorrelationID = correlationID.String()
	status := http.StatusOK
	if path.action == "create" {
		status = http.StatusCreated
	}
	response.Header().Set("ETag", strongVersionETag(result.Group.Version))
	writeManagementJSON(ctx, handler.logger, response, status, output)
	return "success"
}

func (handler *ManagementHandler) changeDeviceGroupMembers(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path deviceGroupPath, session accountsession.Session,
	fail func(managementError) string) string {
	expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		return fail(*precondition)
	}
	add, remove, valid := parseDeviceGroupMembership(response, request)
	if !valid {
		return fail(*invalidManagementRequest())
	}
	result, err := handler.deviceGroups.ChangeMembers(ctx, session, path.scope, path.groupID, expectedVersion,
		add, remove, correlationID)
	if err != nil {
		return fail(classifyDeviceGroupError(err))
	}
	var output struct {
		Data struct {
			Group           deviceGroupBody `json:"group"`
			Added           int             `json:"added"`
			Removed         int             `json:"removed"`
			AccessAffecting bool            `json:"access_affecting"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Group, output.Data.Added, output.Data.Removed = newDeviceGroupBody(result.Group), result.Added,
		result.Removed
	output.Data.AccessAffecting, output.CorrelationID = result.AccessAffecting, correlationID.String()
	response.Header().Set("ETag", strongVersionETag(result.Group.Version))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

func classifyDeviceGroupError(err error) managementError {
	switch {
	case errors.Is(err, devicegroup.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot view or change Device Groups in this Network"}
	case errors.Is(err, devicegroup.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "device_group_not_found",
			Message: "The Device Group no longer exists"}
	case errors.Is(err, devicegroup.ErrVersionConflict):
		return managementError{Status: http.StatusPreconditionFailed, Code: "version_conflict",
			Message: "The Device Group changed. Reload and review it again."}
	case errors.Is(err, devicegroup.ErrIneligibleDevice):
		return managementError{Status: http.StatusUnprocessableEntity, Code: "device_not_eligible",
			Message: "A chosen Device is not an active Device of this Network"}
	case errors.Is(err, devicegroup.ErrGroupLimit):
		return managementError{Status: http.StatusConflict, Code: "device_group_limit",
			Message: "This Network already has the maximum number of Device Groups"}
	case errors.Is(err, devicegroup.ErrMemberLimit):
		return managementError{Status: http.StatusConflict, Code: "device_group_member_limit",
			Message: "The Device Group would exceed the maximum number of members"}
	case errors.Is(err, devicegroup.ErrNameTaken):
		return managementError{Status: http.StatusConflict, Code: "device_group_name_taken",
			Message: "Another Device Group in this Network has that name"}
	case errors.Is(err, devicegroup.ErrInUse):
		return managementError{Status: http.StatusConflict, Code: "device_group_in_use",
			Message: "Active rules still select this Device Group. Change those rules first."}
	case errors.Is(err, devicegroup.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload Device Groups before trying again.", Retryable: true}
	}
}

func managementTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
