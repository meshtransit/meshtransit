package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/idempotency"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
	authority "github.com/meshtransit/meshtransit/internal/resource/authority"
	"github.com/meshtransit/meshtransit/internal/resource/catalog"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const defaultResourcePageSize = 50

type resourceManagementKind uint8

const (
	resourceManagementUnknown resourceManagementKind = iota
	resourceManagementCollection
	resourceManagementItem
	resourceGroupManagementCollection
	resourceGroupManagementItem
)

type resourceManagementPath struct {
	kind        resourceManagementKind
	workspaceID string
	networkID   string
	publicID    string
	action      string
}

func parseResourceManagementPath(request *http.Request) (resourceManagementPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" {
		return resourceManagementPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if (len(segments) != 7 && len(segments) != 8 && len(segments) != 10) ||
		segments[0] != "api" ||
		segments[1] != "v1" || segments[2] != "workspaces" || segments[4] != "networks" {
		return resourceManagementPath{}, false
	}
	path := resourceManagementPath{workspaceID: segments[3], networkID: segments[5]}
	switch segments[6] {
	case "resources":
		path.kind = resourceManagementCollection
		if len(segments) >= 8 {
			path.kind = resourceManagementItem
			path.publicID = segments[7]
		}
	case "resource-groups":
		path.kind = resourceGroupManagementCollection
		if len(segments) >= 8 {
			path.kind = resourceGroupManagementItem
			path.publicID = segments[7]
		}
	default:
		return resourceManagementPath{}, false
	}
	if len(segments) == 10 {
		if segments[8] != "actions" ||
			(segments[9] != "suspend" && segments[9] != "resume" && segments[9] != "delete") {
			return resourceManagementPath{}, false
		}
		path.action = segments[9]
	}
	return path, true
}

func (path resourceManagementPath) isCollection() bool {
	return path.kind == resourceManagementCollection || path.kind == resourceGroupManagementCollection
}

func (path resourceManagementPath) isAction() bool { return path.action != "" }

func (path resourceManagementPath) allowedMethod(method string) string {
	if path.isCollection() && (method == http.MethodGet || method == http.MethodPost) {
		return method
	}
	if path.isAction() && method == http.MethodPost {
		return method
	}
	if !path.isCollection() && method == http.MethodGet {
		return method
	}
	return ""
}

func allowedMethodOrGet(resourceMatched bool, allowed string) string {
	if resourceMatched {
		return http.MethodGet
	}
	if allowed != "" {
		return allowed
	}
	return http.MethodPost
}

func (path resourceManagementPath) operation(method string) string {
	if path.isAction() && method == http.MethodPost {
		group := path.kind == resourceGroupManagementItem
		switch path.action {
		case "suspend":
			if group {
				return resourceGroupSuspendOperation
			}
			return resourceSuspendOperation
		case "resume":
			if group {
				return resourceGroupResumeOperation
			}
			return resourceResumeOperation
		case "delete":
			if group {
				return resourceGroupDeleteOperation
			}
			return resourceDeleteOperation
		}
	}
	switch path.kind {
	case resourceManagementCollection:
		switch method {
		case http.MethodPost:
			return resourceCreateOperation
		case http.MethodGet:
			return resourceListOperation
		}
	case resourceManagementItem:
		if method == http.MethodGet {
			return resourceGetOperation
		}
	case resourceGroupManagementCollection:
		switch method {
		case http.MethodPost:
			return resourceGroupCreateOperation
		case http.MethodGet:
			return resourceGroupListOperation
		}
	case resourceGroupManagementItem:
		if method == http.MethodGet {
			return resourceGroupGetOperation
		}
	}
	return unknownManagementOperation
}

func (path resourceManagementPath) scope() (network.Scope, error) {
	workspaceID, err := workspace.ParseID(path.workspaceID)
	if err != nil {
		return network.Scope{}, err
	}
	networkID, err := network.ParseID(path.networkID)
	if err != nil {
		return network.Scope{}, err
	}
	return network.NewScope(workspaceID, networkID)
}

func (handler *ManagementHandler) handleResourceManagement(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path resourceManagementPath,
	session accountsession.Session,
) string {
	if path.isAction() {
		if handler.resourceLifecycles == nil {
			writeManagementError(ctx, handler.logger, response, correlationID, resourceUnavailableError())
			return "operation_unavailable"
		}
		return handler.transitionResourceLifecycle(
			ctx, response, request, correlationID, path, session,
		)
	}
	if path.isCollection() && request.Method == http.MethodPost {
		if handler.resourceCreations == nil {
			writeManagementError(ctx, handler.logger, response, correlationID, resourceUnavailableError())
			return "operation_unavailable"
		}
		if path.kind == resourceManagementCollection {
			return handler.createResource(ctx, response, request, correlationID, path, session)
		}
		return handler.createResourceGroup(ctx, response, request, correlationID, path, session)
	}
	if handler.resourceCatalog == nil {
		writeManagementError(ctx, handler.logger, response, correlationID, resourceUnavailableError())
		return "operation_unavailable"
	}
	if path.kind == resourceManagementCollection || path.kind == resourceGroupManagementCollection {
		return handler.listResourceAuthority(ctx, response, request, correlationID, path, session)
	}
	return handler.getResourceAuthority(ctx, response, request, correlationID, path, session)
}

type resourceLifecycleRequest struct {
	Reason string `json:"reason"`
}

func (handler *ManagementHandler) transitionResourceLifecycle(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path resourceManagementPath,
	session accountsession.Session,
) string {
	if request.URL.RawQuery != "" {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	scope, expectedVersion, proof, requestErr := handler.resourceMutationEnvelope(request, path)
	if requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	var body resourceLifecycleRequest
	if requestErr = decodeResourceBody(response, request, &body); requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	reason, err := authority.NewAuditReason(body.Reason)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	operation := lifecycleOperation(path)
	var command authority.LifecycleCommand
	if path.kind == resourceManagementItem {
		id, err := resource.ParseID(path.publicID)
		if err != nil {
			return handler.writeResourceRequestError(ctx, response, correlationID)
		}
		command, err = authority.NewResourceLifecycleCommand(
			operation, scope, id, expectedVersion, session, reason, proof,
		)
		if err != nil {
			return handler.writeResourceRequestError(ctx, response, correlationID)
		}
	} else {
		id, err := resource.ParseGroupID(path.publicID)
		if err != nil {
			return handler.writeResourceRequestError(ctx, response, correlationID)
		}
		command, err = authority.NewGroupLifecycleCommand(
			operation, scope, id, expectedVersion, session, reason, proof,
		)
		if err != nil {
			return handler.writeResourceRequestError(ctx, response, correlationID)
		}
	}
	result, err := handler.resourceLifecycles.Transition(ctx, command)
	if err != nil {
		classified := classifyResourceLifecycleError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	if !resourceLifecycleMatches(result, command) {
		writeManagementError(ctx, handler.logger, response, correlationID, internalManagementError())
		return "internal_failure"
	}
	response.Header().Set("ETag", strongVersionETag(result.Version()))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, resourceLifecycleEnvelope{
		Data: resourceLifecycleData{
			ResourceID: lifecycleResourceID(result), ResourceGroupID: lifecycleGroupID(result),
			State: catalog.StateString(result.State()), Version: result.Version(),
			NetworkRevision:   result.NetworkRevision(),
			InventoryRevision: lifecycleInventoryRevision(result),
			GroupRevision:     lifecycleGroupRevision(result),
		},
		CorrelationID: correlationID.String(),
	})
	return "success"
}

func lifecycleOperation(path resourceManagementPath) authority.LifecycleOperation {
	group := path.kind == resourceGroupManagementItem
	switch path.action {
	case "suspend":
		if group {
			return authority.LifecycleSuspendGroup
		}
		return authority.LifecycleSuspendResource
	case "resume":
		if group {
			return authority.LifecycleResumeGroup
		}
		return authority.LifecycleResumeResource
	case "delete":
		if group {
			return authority.LifecycleDeleteGroup
		}
		return authority.LifecycleDeleteResource
	default:
		return authority.LifecycleOperationUnknown
	}
}

type createResourceRequest struct {
	DisplayName string `json:"display_name"`
	DeviceID    string `json:"device_id"`
	Reason      string `json:"reason"`
}

type createResourceGroupRequest struct {
	DisplayName string                      `json:"display_name"`
	Members     []createResourceGroupMember `json:"members"`
	Reason      string                      `json:"reason"`
}

type createResourceGroupMember struct {
	ResourceID       string `json:"resource_id"`
	ResourceVersion  int64  `json:"resource_version"`
	TargetGeneration int64  `json:"target_generation"`
}

func (handler *ManagementHandler) createResource(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path resourceManagementPath,
	session accountsession.Session,
) string {
	if request.URL.RawQuery != "" {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	scope, expectedRevision, proof, requestErr := handler.resourceMutationEnvelope(request, path)
	if requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	var body createResourceRequest
	if requestErr = decodeResourceBody(response, request, &body); requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	name, err := resource.ParseDisplayName(body.DisplayName)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	deviceID, err := node.ParseID(body.DeviceID)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	reason, err := authority.NewAuditReason(body.Reason)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	definition, err := resource.NewDeviceDefinition(resource.DeviceDefinitionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: session.PrincipalID(),
		CustodianPrincipalID: session.PrincipalID(), DeviceID: deviceID,
	})
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	command, err := authority.NewCreateDeviceCommand(
		definition, expectedRevision, session, reason, proof,
	)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	result, err := handler.resourceCreations.Create(ctx, command)
	if err != nil {
		classified := classifyResourceAuthorityError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	if !resourceCreationMatches(result, command) {
		writeManagementError(ctx, handler.logger, response, correlationID, internalManagementError())
		return "internal_failure"
	}
	data := resourceCreatedData(command, result)
	response.Header().Set("Location", request.URL.Path+"/"+result.ResourceID().String())
	response.Header().Set("ETag", strongVersionETag(result.Version()))
	writeManagementJSON(ctx, handler.logger, response, http.StatusCreated, resourceItemEnvelope{
		Data: data, CorrelationID: correlationID.String(),
	})
	return "success"
}

func (handler *ManagementHandler) createResourceGroup(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path resourceManagementPath,
	session accountsession.Session,
) string {
	if request.URL.RawQuery != "" {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	scope, expectedRevision, proof, requestErr := handler.resourceMutationEnvelope(request, path)
	if requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	var body createResourceGroupRequest
	if requestErr = decodeResourceBody(response, request, &body); requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	name, err := resource.ParseDisplayName(body.DisplayName)
	if err != nil || len(body.Members) == 0 || len(body.Members) > resource.MaximumGroupMembers {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	members := make([]resource.Reference, len(body.Members))
	for index, member := range body.Members {
		resourceID, err := resource.ParseID(member.ResourceID)
		if err != nil {
			return handler.writeResourceRequestError(ctx, response, correlationID)
		}
		reference, err := resource.NewReference(
			scope, resourceID, member.ResourceVersion, member.TargetGeneration,
		)
		if err != nil {
			return handler.writeResourceRequestError(ctx, response, correlationID)
		}
		members[index] = reference
	}
	reason, err := authority.NewAuditReason(body.Reason)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	definition, err := resource.NewGroupDefinition(resource.GroupDefinitionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: session.PrincipalID(),
		CustodianPrincipalID: session.PrincipalID(), Members: members,
	})
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	command, err := authority.NewCreateGroupCommand(
		definition, expectedRevision, session, reason, proof,
	)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	result, err := handler.resourceCreations.Create(ctx, command)
	if err != nil {
		classified := classifyResourceAuthorityError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	if !resourceCreationMatches(result, command) {
		writeManagementError(ctx, handler.logger, response, correlationID, internalManagementError())
		return "internal_failure"
	}
	data := resourceGroupCreatedData(command, result)
	response.Header().Set("Location", request.URL.Path+"/"+result.GroupID().String())
	response.Header().Set("ETag", strongVersionETag(result.Version()))
	writeManagementJSON(ctx, handler.logger, response, http.StatusCreated, resourceGroupItemEnvelope{
		Data: data, CorrelationID: correlationID.String(),
	})
	return "success"
}

func (handler *ManagementHandler) resourceMutationEnvelope(
	request *http.Request,
	path resourceManagementPath,
) (network.Scope, int64, idempotency.Proof, *managementError) {
	scope, err := path.scope()
	if err != nil {
		return network.Scope{}, 0, idempotency.Proof{}, invalidManagementRequest()
	}
	expectedRevision, requestErr := parseIfMatch(request.Header.Values("If-Match"))
	if requestErr != nil {
		return network.Scope{}, 0, idempotency.Proof{}, requestErr
	}
	rawKey := singleHeader(request.Header, "Idempotency-Key")
	if rawKey == "" {
		return network.Scope{}, 0, idempotency.Proof{}, invalidManagementRequest()
	}
	proof, err := handler.idempotency.Proof(rawKey)
	if err != nil || !proof.IsValid() {
		return network.Scope{}, 0, idempotency.Proof{}, invalidManagementRequest()
	}
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return network.Scope{}, 0, idempotency.Proof{}, invalidManagementRequest()
	}
	return scope, expectedRevision, proof, nil
}

func decodeResourceBody(
	response http.ResponseWriter,
	request *http.Request,
	destination any,
) *managementError {
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, maximumManagementBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return invalidManagementRequest()
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return invalidManagementRequest()
	}
	return nil
}

func (handler *ManagementHandler) getResourceAuthority(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path resourceManagementPath,
	session accountsession.Session,
) string {
	if request.URL.RawQuery != "" || !validResourceReadHeaders(request) {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	scope, err := path.scope()
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	if path.kind == resourceManagementItem {
		id, err := resource.ParseID(path.publicID)
		if err != nil {
			return handler.writeResourceRequestError(ctx, response, correlationID)
		}
		value, err := handler.resourceCatalog.GetResource(ctx, session, scope, id)
		if err != nil {
			classified := classifyResourceCatalogError(err)
			writeManagementError(ctx, handler.logger, response, correlationID, classified)
			return classified.Code
		}
		response.Header().Set("ETag", strongVersionETag(value.Version()))
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, resourceItemEnvelope{
			Data: resourceCatalogData(value), CorrelationID: correlationID.String(),
		})
		return "success"
	}
	id, err := resource.ParseGroupID(path.publicID)
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	value, err := handler.resourceCatalog.GetGroup(ctx, session, scope, id)
	if err != nil {
		classified := classifyResourceCatalogError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	response.Header().Set("ETag", strongVersionETag(value.Version()))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, resourceGroupItemEnvelope{
		Data: resourceGroupCatalogData(value), CorrelationID: correlationID.String(),
	})
	return "success"
}

func (handler *ManagementHandler) listResourceAuthority(
	ctx context.Context,
	response http.ResponseWriter,
	request *http.Request,
	correlationID publicid.ID,
	path resourceManagementPath,
	session accountsession.Session,
) string {
	if !validResourceReadHeaders(request) {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	scope, err := path.scope()
	if err != nil {
		return handler.writeResourceRequestError(ctx, response, correlationID)
	}
	kind := "resources"
	if path.kind == resourceGroupManagementCollection {
		kind = "resource-groups"
	}
	state, limit, cursor, requestErr := parseResourceListQuery(request.URL.RawQuery, kind)
	if requestErr != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
		return requestErr.Code
	}
	if path.kind == resourceManagementCollection {
		page, err := handler.resourceCatalog.ListResources(ctx, session, scope, state, limit, cursor)
		if err != nil {
			classified := classifyResourceCatalogError(err)
			writeManagementError(ctx, handler.logger, response, correlationID, classified)
			return classified.Code
		}
		items := make([]resourceData, len(page.Items))
		for index, item := range page.Items {
			items[index] = resourceCatalogData(item)
		}
		next, err := encodeResourcePageCursor(kind, catalog.StateString(state), page.Next)
		if err != nil {
			writeManagementError(ctx, handler.logger, response, correlationID, internalManagementError())
			return "internal_failure"
		}
		response.Header().Set("ETag", strongVersionETag(page.Revision))
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, resourceListEnvelope{
			Data: items, NextPageToken: next, CorrelationID: correlationID.String(),
		})
		return "success"
	}
	page, err := handler.resourceCatalog.ListGroups(ctx, session, scope, state, limit, cursor)
	if err != nil {
		classified := classifyResourceCatalogError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, classified)
		return classified.Code
	}
	items := make([]resourceGroupData, len(page.Items))
	for index, item := range page.Items {
		items[index] = resourceGroupCatalogData(item)
	}
	next, err := encodeResourcePageCursor(kind, catalog.StateString(state), page.Next)
	if err != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, internalManagementError())
		return "internal_failure"
	}
	response.Header().Set("ETag", strongVersionETag(page.Revision))
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, resourceGroupListEnvelope{
		Data: items, NextPageToken: next, CorrelationID: correlationID.String(),
	})
	return "success"
}

func validResourceReadHeaders(request *http.Request) bool {
	if request == nil || request.ContentLength != 0 ||
		(request.Body != nil && request.Body != http.NoBody) ||
		len(request.TransferEncoding) != 0 || len(request.Trailer) != 0 {
		return false
	}
	for _, name := range []string{"Content-Encoding", "Expect", "Upgrade"} {
		if _, present := request.Header[name]; present {
			return false
		}
	}
	return len(request.Header.Values("If-Match")) == 0 &&
		len(request.Header.Values("Idempotency-Key")) == 0 &&
		len(request.Header.Values("Content-Type")) == 0
}

type managementPageCursor struct {
	Version  int    `json:"v"`
	Kind     string `json:"kind"`
	State    string `json:"state"`
	Revision int64  `json:"revision"`
	After    string `json:"after"`
}

func parseResourceListQuery(
	rawQuery string,
	kind string,
) (resource.State, int, catalog.PageCursor, *managementError) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return resource.StateUnknown, 0, catalog.PageCursor{}, invalidManagementRequest()
	}
	for key, entries := range values {
		if (key != "state" && key != "page_size" && key != "page_token") ||
			len(entries) != 1 || entries[0] == "" {
			return resource.StateUnknown, 0, catalog.PageCursor{}, invalidManagementRequest()
		}
	}
	state, err := catalog.ParseState(values.Get("state"))
	if err != nil {
		return resource.StateUnknown, 0, catalog.PageCursor{}, invalidManagementRequest()
	}
	limit := defaultResourcePageSize
	if rawLimit := values.Get("page_size"); rawLimit != "" {
		limit, err = strconv.Atoi(rawLimit)
		if err != nil || limit < 1 || limit > catalog.MaximumPageSize || strconv.Itoa(limit) != rawLimit {
			return resource.StateUnknown, 0, catalog.PageCursor{}, invalidManagementRequest()
		}
	}
	cursor := catalog.PageCursor{}
	if encoded := values.Get("page_token"); encoded != "" {
		cursor, err = decodeResourcePageCursor(encoded, kind, catalog.StateString(state))
		if err != nil {
			return resource.StateUnknown, 0, catalog.PageCursor{}, invalidManagementRequest()
		}
	}
	return state, limit, cursor, nil
}

func encodeResourcePageCursor(kind, state string, cursor catalog.PageCursor) (string, error) {
	if !cursor.IsValid() {
		return "", nil
	}
	payload, err := json.Marshal(managementPageCursor{
		Version: 1, Kind: kind, State: state,
		Revision: cursor.Revision(), After: cursor.After().String(),
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeResourcePageCursor(encoded, kind, state string) (catalog.PageCursor, error) {
	if len(encoded) > 512 {
		return catalog.PageCursor{}, catalog.ErrInvalidRequest
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return catalog.PageCursor{}, catalog.ErrInvalidRequest
	}
	var wire managementPageCursor
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || ensureJSONEnd(decoder) != nil ||
		wire.Version != 1 || wire.Kind != kind || wire.State != state {
		return catalog.PageCursor{}, catalog.ErrInvalidRequest
	}
	after, err := publicid.Parse(wire.After)
	if err != nil {
		return catalog.PageCursor{}, catalog.ErrInvalidRequest
	}
	return catalog.NewPageCursor(wire.Revision, after)
}

type resourceData struct {
	ResourceID               string     `json:"resource_id"`
	DisplayName              string     `json:"display_name"`
	OwnerPrincipalID         string     `json:"owner_principal_id"`
	CustodianPrincipalID     string     `json:"custodian_principal_id"`
	DeviceID                 string     `json:"device_id"`
	Kind                     string     `json:"kind"`
	State                    string     `json:"state"`
	Provenance               string     `json:"provenance"`
	Version                  int64      `json:"version"`
	TargetGeneration         int64      `json:"target_generation"`
	SemanticHash             string     `json:"semantic_hash"`
	ActivatedNetworkRevision int64      `json:"activated_network_revision"`
	InventoryRevision        int64      `json:"inventory_revision"`
	CreatedAt                *time.Time `json:"created_at,omitempty"`
	UpdatedAt                *time.Time `json:"updated_at,omitempty"`
}

type resourceGroupData struct {
	ResourceGroupID          string                `json:"resource_group_id"`
	DisplayName              string                `json:"display_name"`
	OwnerPrincipalID         string                `json:"owner_principal_id"`
	CustodianPrincipalID     string                `json:"custodian_principal_id"`
	State                    string                `json:"state"`
	Version                  int64                 `json:"version"`
	DefinitionVersion        int64                 `json:"definition_version"`
	SemanticHash             string                `json:"semantic_hash"`
	ActivatedNetworkRevision int64                 `json:"activated_network_revision"`
	GroupRevision            int64                 `json:"group_revision"`
	Members                  []resourceGroupMember `json:"members"`
	CreatedAt                *time.Time            `json:"created_at,omitempty"`
	UpdatedAt                *time.Time            `json:"updated_at,omitempty"`
}

type resourceGroupMember struct {
	ResourceID       string `json:"resource_id"`
	ResourceVersion  int64  `json:"resource_version"`
	TargetGeneration int64  `json:"target_generation"`
}

type resourceItemEnvelope struct {
	Data          resourceData `json:"data"`
	CorrelationID string       `json:"correlation_id"`
}

type resourceGroupItemEnvelope struct {
	Data          resourceGroupData `json:"data"`
	CorrelationID string            `json:"correlation_id"`
}

type resourceLifecycleData struct {
	ResourceID        string `json:"resource_id,omitempty"`
	ResourceGroupID   string `json:"resource_group_id,omitempty"`
	State             string `json:"state"`
	Version           int64  `json:"version"`
	NetworkRevision   int64  `json:"network_revision"`
	InventoryRevision int64  `json:"inventory_revision,omitempty"`
	GroupRevision     int64  `json:"group_revision,omitempty"`
}

type resourceLifecycleEnvelope struct {
	Data          resourceLifecycleData `json:"data"`
	CorrelationID string                `json:"correlation_id"`
}

type resourceListEnvelope struct {
	Data          []resourceData `json:"data"`
	NextPageToken string         `json:"next_page_token,omitempty"`
	CorrelationID string         `json:"correlation_id"`
}

type resourceGroupListEnvelope struct {
	Data          []resourceGroupData `json:"data"`
	NextPageToken string              `json:"next_page_token,omitempty"`
	CorrelationID string              `json:"correlation_id"`
}

func resourceCreatedData(command authority.Command, result authority.Result) resourceData {
	definition := command.Device()
	hash := command.SemanticHash().Bytes()
	return resourceData{
		ResourceID: result.ResourceID().String(), DisplayName: definition.DisplayName().String(),
		OwnerPrincipalID:     definition.OwnerPrincipalID().String(),
		CustodianPrincipalID: definition.CustodianPrincipalID().String(),
		DeviceID:             definition.DeviceID().String(), Kind: "device", State: "active", Provenance: "manual",
		Version: result.Version(), TargetGeneration: definition.TargetGeneration(),
		SemanticHash: hex.EncodeToString(hash[:]), ActivatedNetworkRevision: result.NetworkRevision(),
		InventoryRevision: result.SubsystemRevision(),
	}
}

func resourceGroupCreatedData(command authority.Command, result authority.Result) resourceGroupData {
	definition := command.Group()
	hash := command.SemanticHash().Bytes()
	members := resourceGroupMembers(definition.Members())
	return resourceGroupData{
		ResourceGroupID: result.GroupID().String(), DisplayName: definition.DisplayName().String(),
		OwnerPrincipalID:     definition.OwnerPrincipalID().String(),
		CustodianPrincipalID: definition.CustodianPrincipalID().String(), State: "active",
		Version: result.Version(), DefinitionVersion: definition.DefinitionVersion(),
		SemanticHash: hex.EncodeToString(hash[:]), ActivatedNetworkRevision: result.NetworkRevision(),
		GroupRevision: result.SubsystemRevision(), Members: members,
	}
}

func resourceCatalogData(value catalog.Resource) resourceData {
	hash := value.SemanticHash().Bytes()
	createdAt, updatedAt := value.CreatedAt(), value.UpdatedAt()
	return resourceData{
		ResourceID: value.ID().String(), DisplayName: value.DisplayName().String(),
		OwnerPrincipalID:     value.OwnerPrincipalID().String(),
		CustodianPrincipalID: value.CustodianPrincipalID().String(), DeviceID: value.DeviceID().String(),
		Kind: "device", State: catalog.StateString(value.State()), Provenance: "manual",
		Version: value.Version(), TargetGeneration: value.TargetGeneration(),
		SemanticHash:             hex.EncodeToString(hash[:]),
		ActivatedNetworkRevision: value.ActivatedNetworkRevision(), InventoryRevision: value.InventoryRevision(),
		CreatedAt: &createdAt, UpdatedAt: &updatedAt,
	}
}

func resourceGroupCatalogData(value catalog.Group) resourceGroupData {
	hash := value.SemanticHash().Bytes()
	createdAt, updatedAt := value.CreatedAt(), value.UpdatedAt()
	return resourceGroupData{
		ResourceGroupID: value.ID().String(), DisplayName: value.DisplayName().String(),
		OwnerPrincipalID:     value.OwnerPrincipalID().String(),
		CustodianPrincipalID: value.CustodianPrincipalID().String(), State: catalog.StateString(value.State()),
		Version: value.Version(), DefinitionVersion: value.DefinitionVersion(),
		SemanticHash:             hex.EncodeToString(hash[:]),
		ActivatedNetworkRevision: value.ActivatedNetworkRevision(), GroupRevision: value.GroupRevision(),
		Members: resourceGroupMembers(value.Members()), CreatedAt: &createdAt, UpdatedAt: &updatedAt,
	}
}

func resourceGroupMembers(references []resource.Reference) []resourceGroupMember {
	members := make([]resourceGroupMember, len(references))
	for index, reference := range references {
		members[index] = resourceGroupMember{
			ResourceID: reference.ResourceID().String(), ResourceVersion: reference.ResourceVersion(),
			TargetGeneration: reference.TargetGeneration(),
		}
	}
	return members
}

func resourceCreationMatches(result authority.Result, command authority.Command) bool {
	if !result.IsValid() || result.Operation() != command.Operation() || result.Scope() != command.Scope() ||
		result.SemanticHash() != command.SemanticHash() || result.Version() != 1 ||
		result.SubsystemRevision() != command.ExpectedSubsystemRevision()+1 {
		return false
	}
	if command.Operation() == authority.OperationCreateDevice {
		return result.ResourceID().IsValid() && !result.GroupID().IsValid()
	}
	return result.GroupID().IsValid() && !result.ResourceID().IsValid()
}

func resourceLifecycleMatches(
	result authority.LifecycleResult,
	command authority.LifecycleCommand,
) bool {
	if !result.IsValid() || result.Operation() != command.Operation() ||
		result.Scope() != command.Scope() || result.State() != command.Operation().TargetState() ||
		result.Version() != command.ExpectedVersion()+1 {
		return false
	}
	if command.Operation().IsGroup() {
		return result.GroupID() == command.GroupID() && !result.ResourceID().IsValid()
	}
	return result.ResourceID() == command.ResourceID() && !result.GroupID().IsValid()
}

func lifecycleInventoryRevision(result authority.LifecycleResult) int64 {
	if result.Operation().IsGroup() {
		return 0
	}
	return result.SubsystemRevision()
}

func lifecycleGroupRevision(result authority.LifecycleResult) int64 {
	if !result.Operation().IsGroup() {
		return 0
	}
	return result.SubsystemRevision()
}

func lifecycleResourceID(result authority.LifecycleResult) string {
	if !result.ResourceID().IsValid() {
		return ""
	}
	return result.ResourceID().String()
}

func lifecycleGroupID(result authority.LifecycleResult) string {
	if !result.GroupID().IsValid() {
		return ""
	}
	return result.GroupID().String()
}

func classifyResourceAuthorityError(err error) managementError {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return managementError{Status: http.StatusGatewayTimeout, Code: "request_timeout", Message: "the request deadline expired", Retryable: true}
	case errors.Is(err, authority.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "forbidden", Message: "the request is not authorized"}
	case errors.Is(err, authority.ErrConflict):
		return managementError{Status: http.StatusPreconditionFailed, Code: "precondition_failed", Message: "the collection revision precondition is stale"}
	case errors.Is(err, authority.ErrIntentConflict):
		return managementError{Status: http.StatusConflict, Code: "idempotency_conflict", Message: "the idempotency key is bound to different request semantics"}
	case errors.Is(err, authority.ErrIdempotencyExpired):
		return managementError{Status: http.StatusConflict, Code: "idempotency_expired", Message: "the idempotency replay window expired"}
	case errors.Is(err, context.Canceled), errors.Is(err, authority.ErrRetryableTransaction),
		errors.Is(err, authority.ErrCommitOutcomeUnknown), errors.Is(err, authority.ErrRetryExhausted):
		return resourceUnavailableError()
	default:
		return internalManagementError()
	}
}

func classifyResourceLifecycleError(err error) managementError {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return managementError{Status: http.StatusGatewayTimeout, Code: "request_timeout", Message: "the request deadline expired", Retryable: true}
	case errors.Is(err, authority.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "forbidden", Message: "the request is not authorized"}
	case errors.Is(err, authority.ErrLifecycleNotFound):
		return managementError{Status: http.StatusNotFound, Code: "not_found", Message: "the requested resource is unavailable"}
	case errors.Is(err, authority.ErrLifecycleVersionConflict):
		return managementError{Status: http.StatusPreconditionFailed, Code: "precondition_failed", Message: "the aggregate version precondition is stale"}
	case errors.Is(err, authority.ErrInvalidLifecycleTransition):
		return managementError{Status: http.StatusConflict, Code: "invalid_state_transition", Message: "the requested lifecycle transition is not valid"}
	case errors.Is(err, authority.ErrIntentConflict):
		return managementError{Status: http.StatusConflict, Code: "idempotency_conflict", Message: "the idempotency key is bound to different request semantics"}
	case errors.Is(err, authority.ErrIdempotencyExpired):
		return managementError{Status: http.StatusConflict, Code: "idempotency_expired", Message: "the idempotency replay window expired"}
	case errors.Is(err, context.Canceled), errors.Is(err, authority.ErrRetryableTransaction),
		errors.Is(err, authority.ErrCommitOutcomeUnknown), errors.Is(err, authority.ErrRetryExhausted):
		return resourceUnavailableError()
	default:
		return internalManagementError()
	}
}

func classifyResourceCatalogError(err error) managementError {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return managementError{Status: http.StatusGatewayTimeout, Code: "request_timeout", Message: "the request deadline expired", Retryable: true}
	case errors.Is(err, catalog.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "forbidden", Message: "the request is not authorized"}
	case errors.Is(err, catalog.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "not_found", Message: "the requested resource is unavailable"}
	case errors.Is(err, catalog.ErrConflict):
		return managementError{Status: http.StatusConflict, Code: "collection_changed", Message: "the collection changed during pagination"}
	case errors.Is(err, context.Canceled), errors.Is(err, catalog.ErrUnavailable):
		return resourceUnavailableError()
	default:
		return internalManagementError()
	}
}

func resourceUnavailableError() managementError {
	return managementError{Status: http.StatusServiceUnavailable, Code: "operation_unavailable", Message: "the operation is temporarily unavailable", Retryable: true}
}

func internalManagementError() managementError {
	return managementError{Status: http.StatusInternalServerError, Code: "internal_failure", Message: "the request could not be completed"}
}

func (handler *ManagementHandler) writeResourceRequestError(
	ctx context.Context,
	response http.ResponseWriter,
	correlationID publicid.ID,
) string {
	requestErr := invalidManagementRequest()
	writeManagementError(ctx, handler.logger, response, correlationID, *requestErr)
	return requestErr.Code
}
