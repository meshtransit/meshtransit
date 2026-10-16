package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// IdentityGroupManager lists and changes Workspace Identity Groups.
type IdentityGroupManager interface {
	List(context.Context, accountsession.Session, workspace.ID) (identitygroup.Listing, error)
	Members(context.Context, accountsession.Session, workspace.ID, identitygroup.ID, publicid.ID,
		int) (identitygroup.MemberPage, error)
	Create(context.Context, accountsession.Session, workspace.ID, identitygroup.Definition,
		publicid.ID) (identitygroup.Result, error)
	Update(context.Context, accountsession.Session, workspace.ID, identitygroup.ID, int64, identitygroup.Definition,
		publicid.ID) (identitygroup.Result, error)
	Delete(context.Context, accountsession.Session, workspace.ID, identitygroup.ID, int64,
		publicid.ID) (identitygroup.Result, error)
	ChangeMembers(context.Context, accountsession.Session, workspace.ID, identitygroup.ID, int64, []publicid.ID,
		[]publicid.ID, publicid.ID) (identitygroup.MembershipResult, error)
}

// DeviceTagManager lists and changes the device tag catalog and Device tags.
type DeviceTagManager interface {
	List(context.Context, accountsession.Session, workspace.ID) (devicetag.Listing, error)
	Create(context.Context, accountsession.Session, workspace.ID, devicetag.Definition,
		publicid.ID) (devicetag.Result, error)
	Update(context.Context, accountsession.Session, workspace.ID, devicetag.ID, int64, devicetag.Definition,
		publicid.ID) (devicetag.Result, error)
	Delete(context.Context, accountsession.Session, workspace.ID, devicetag.ID, int64,
		publicid.ID) (devicetag.Result, error)
	NetworkTags(context.Context, accountsession.Session, network.Scope) ([]devicetag.DeviceTags, error)
	NetworkOptions(context.Context, accountsession.Session, network.Scope) (devicetag.NetworkOptions, error)
	ChangeAssignments(context.Context, accountsession.Session, network.Scope, node.ID, []devicetag.ID,
		[]devicetag.ID, publicid.ID) (devicetag.AssignmentResult, error)
}

// identityCatalogKind names which resource a path addresses.
type identityCatalogKind int

const (
	identityCatalogUnknown identityCatalogKind = iota
	identityCatalogGroups
	identityCatalogTags
	identityCatalogNetworkTags
	identityCatalogDeviceTags
	identityCatalogTagOptions
)

type identityCatalogPath struct {
	kind        identityCatalogKind
	workspaceID workspace.ID
	scope       network.Scope
	groupID     identitygroup.ID
	tagID       devicetag.ID
	deviceID    node.ID
	// methods are the methods the path accepts; action is what the request's
	// method does there: "" to list, "members", "create", "update",
	// "delete", "change-members" or "change-tags", and "" when the path does
	// not accept the method.
	methods restMethods
	action  string
	after   publicid.ID
	limit   int
}

func canonicalPublicID(text string) (publicid.ID, bool) {
	id, err := publicid.Parse(text)
	return id, err == nil && id.String() == text
}

// parseIdentityCatalogPath matches, under /api/v1/workspaces/{ws}:
//
//	GET|POST     identity-groups               list, create
//	PATCH|DELETE identity-groups/{id}          update, delete
//	GET|PATCH    identity-groups/{id}/members  page[?after=&limit=], change
//	GET|POST     device-tags                   list, create
//	PATCH|DELETE device-tags/{id}              update, delete
//	GET          networks/{net}/device-tags    the Network's Device tags
//	GET          networks/{net}/assignable-device-tags
//	PATCH        networks/{net}/devices/{device}/tags
//
// A path matched with a method it does not accept carries no action, for a
// 405. Only the member page takes a query, and only after and limit once each.
func parseIdentityCatalogPath(request *http.Request) (identityCatalogPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" {
		return identityCatalogPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) < 5 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" {
		return identityCatalogPath{}, false
	}
	workspaceText, ok := canonicalPublicID(segments[3])
	if !ok {
		return identityCatalogPath{}, false
	}
	path := identityCatalogPath{workspaceID: workspace.ID(workspaceText)}
	rest := segments[4:]
	switch rest[0] {
	case "identity-groups":
		path.kind = identityCatalogGroups
		if !path.matchCatalog(rest[1:], request.Method, true) {
			return identityCatalogPath{}, false
		}
	case "device-tags":
		path.kind = identityCatalogTags
		if !path.matchCatalog(rest[1:], request.Method, false) {
			return identityCatalogPath{}, false
		}
	case "networks":
		if !path.matchNetwork(rest[1:], request.Method) {
			return identityCatalogPath{}, false
		}
	default:
		return identityCatalogPath{}, false
	}
	if path.action != "members" {
		return path, request.URL.RawQuery == ""
	}
	return path.withPage(request.URL.RawQuery)
}

// matchCatalog reads a groups or tags path; the method picks the action.
func (path *identityCatalogPath) matchCatalog(rest []string, method string, groups bool) bool {
	var actions map[string]string
	switch {
	case len(rest) == 0:
		path.methods, actions = collectionMethods, map[string]string{http.MethodPost: "create"}
	case len(rest) == 1:
		path.methods = itemMethods
		actions = map[string]string{http.MethodPatch: "update", http.MethodDelete: "delete"}
	case groups && len(rest) == 2 && rest[1] == "members":
		path.methods = restMethods{http.MethodGet, http.MethodPatch}
		actions = map[string]string{http.MethodGet: "members", http.MethodPatch: "change-members"}
	default:
		return false
	}
	if path.methods.allows(method) {
		path.action = actions[method]
	}
	if len(rest) == 0 {
		return true
	}
	id, ok := canonicalPublicID(rest[0])
	if !ok {
		return false
	}
	if groups {
		path.groupID = identitygroup.ID(id)
	} else {
		path.tagID = devicetag.ID(id)
	}
	return true
}

func (path *identityCatalogPath) matchNetwork(rest []string, method string) bool {
	if len(rest) < 2 {
		return false
	}
	networkText, ok := canonicalPublicID(rest[0])
	if !ok {
		return false
	}
	scope, err := network.NewScope(path.workspaceID, network.ID(networkText))
	if err != nil {
		return false
	}
	path.scope = scope
	switch {
	case len(rest) == 2 && rest[1] == "device-tags":
		path.kind, path.methods = identityCatalogNetworkTags, readMethods
		return true
	case len(rest) == 2 && rest[1] == "assignable-device-tags":
		path.kind, path.methods = identityCatalogTagOptions, readMethods
		return true
	case len(rest) == 4 && rest[1] == "devices" && rest[3] == "tags":
		device, ok := canonicalPublicID(rest[2])
		if !ok {
			return false
		}
		path.kind, path.deviceID, path.methods = identityCatalogDeviceTags, node.ID(device), restMethods{http.MethodPatch}
		if path.methods.allows(method) {
			path.action = "change-tags"
		}
		return true
	default:
		return false
	}
}

func (path identityCatalogPath) withPage(rawQuery string) (identityCatalogPath, bool) {
	path.limit = defaultDeviceGroupPage
	if rawQuery == "" {
		return path, true
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return identityCatalogPath{}, false
	}
	for key, items := range values {
		if (key != "after" && key != "limit") || len(items) != 1 || items[0] == "" {
			return identityCatalogPath{}, false
		}
	}
	if value := values.Get("after"); value != "" {
		after, ok := canonicalPublicID(value)
		if !ok {
			return identityCatalogPath{}, false
		}
		path.after = after
	}
	if value := values.Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || strconv.Itoa(limit) != value || limit < 1 || limit > identitygroup.MaximumMemberPage {
			return identityCatalogPath{}, false
		}
		path.limit = limit
	}
	return path, true
}

func (path identityCatalogPath) operation() string {
	switch path.kind {
	case identityCatalogGroups:
		switch path.action {
		case "":
			return "identity_group_list"
		case "members":
			return "identity_group_members"
		case "change-members":
			return "identity_group_change_members"
		default:
			return "identity_group_" + path.action
		}
	case identityCatalogTags:
		if path.action == "" {
			return "device_tag_list"
		}
		return "device_tag_" + path.action
	case identityCatalogNetworkTags:
		return "network_device_tags_read"
	case identityCatalogTagOptions:
		return "network_tag_options_read"
	default:
		return "device_tags_change"
	}
}

// isIdentityCatalogOperation admits only the methods each path accepts.
func isIdentityCatalogOperation(request *http.Request) bool {
	path, ok := parseIdentityCatalogPath(request)
	return ok && path.methods.allows(request.Method)
}

// isIdentityCatalogRead admits the catalog reads and the bounded member page.
func isIdentityCatalogRead(request *http.Request) bool {
	return request != nil && request.Method == http.MethodGet && isIdentityCatalogOperation(request)
}

func (handler *ManagementHandler) handleIdentityCatalog(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path identityCatalogPath, session accountsession.Session) string {
	fail := func(failure managementError) string {
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	response.Header().Set("Cache-Control", "no-store")
	switch path.kind {
	case identityCatalogGroups:
		if nilContinuationDependency(handler.identityGroups) {
			return fail(identityCatalogUnavailable())
		}
		return handler.handleIdentityGroups(ctx, response, request, correlationID, path, session, fail)
	default:
		if nilContinuationDependency(handler.deviceTags) {
			return fail(identityCatalogUnavailable())
		}
		return handler.handleDeviceTags(ctx, response, request, correlationID, path, session, fail)
	}
}

func identityCatalogUnavailable() managementError {
	return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
		Message: "Groups and tags are temporarily unavailable", Retryable: true}
}

func identityCatalogUncertain() managementError {
	return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
		Message: "The result is uncertain. Reload before trying again.", Retryable: true}
}

func classifyIdentityGroupError(err error) managementError {
	switch {
	case errors.Is(err, identitygroup.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot view or change user groups in this Workspace"}
	case errors.Is(err, identitygroup.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "identity_group_not_found",
			Message: "The user group no longer exists"}
	case errors.Is(err, identitygroup.ErrVersionConflict):
		return managementError{Status: http.StatusPreconditionFailed, Code: "version_conflict",
			Message: "The user group changed. Reload and review it again."}
	case errors.Is(err, identitygroup.ErrIneligibleMember):
		return managementError{Status: http.StatusUnprocessableEntity, Code: "member_not_eligible",
			Message: "A chosen person is not an active member of this Workspace"}
	case errors.Is(err, identitygroup.ErrGroupLimit):
		return managementError{Status: http.StatusConflict, Code: "identity_group_limit",
			Message: "This Workspace already has the maximum number of user groups"}
	case errors.Is(err, identitygroup.ErrMemberLimit):
		return managementError{Status: http.StatusConflict, Code: "identity_group_member_limit",
			Message: "The user group would exceed the maximum number of members"}
	case errors.Is(err, identitygroup.ErrNameTaken):
		return managementError{Status: http.StatusConflict, Code: "identity_group_name_taken",
			Message: "Another user group in this Workspace has that name"}
	case errors.Is(err, identitygroup.ErrInUse):
		return managementError{Status: http.StatusConflict, Code: "identity_group_in_use",
			Message: "Active rules select this user group or it owns tags. Change those first."}
	case errors.Is(err, identitygroup.ErrEdgeBudget):
		return managementError{Status: http.StatusConflict, Code: "device_policy_edge_limit",
			Message: "A Device would reach more than 10,000 rule edges. Narrow the rules or split the group."}
	case errors.Is(err, identitygroup.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return identityCatalogUncertain()
	}
}

func classifyDeviceTagError(err error) managementError {
	switch {
	case errors.Is(err, devicetag.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot view or change these tags"}
	case errors.Is(err, devicetag.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "device_tag_not_found",
			Message: "The tag or Device no longer exists"}
	case errors.Is(err, devicetag.ErrVersionConflict):
		return managementError{Status: http.StatusPreconditionFailed, Code: "version_conflict",
			Message: "The tag changed. Reload and review it again."}
	case errors.Is(err, devicetag.ErrTagLimit):
		return managementError{Status: http.StatusConflict, Code: "device_tag_limit",
			Message: "This Workspace already has the maximum number of tags"}
	case errors.Is(err, devicetag.ErrUnknownOwner):
		return managementError{Status: http.StatusUnprocessableEntity, Code: "device_tag_owner_unknown",
			Message: "A chosen tag owner is not in this Workspace"}
	case errors.Is(err, devicetag.ErrNameTaken):
		return managementError{Status: http.StatusConflict, Code: "device_tag_name_taken",
			Message: "Another tag in this Workspace has that name"}
	case errors.Is(err, devicetag.ErrInUse):
		return managementError{Status: http.StatusConflict, Code: "device_tag_in_use",
			Message: "Active rules select this tag. Change those rules first."}
	case errors.Is(err, devicetag.ErrEdgeBudget):
		return managementError{Status: http.StatusConflict, Code: "device_policy_edge_limit",
			Message: "A Device would reach more than 10,000 rule edges. Narrow the rules first."}
	case errors.Is(err, devicetag.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return identityCatalogUncertain()
	}
}
