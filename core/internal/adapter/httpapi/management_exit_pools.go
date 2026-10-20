package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	exitPoolListOperation       = "exit_pool_list"
	exitPoolReadOperation       = "exit_pool_read"
	exitPoolCreateOperation     = "exit_pool_create"
	exitPoolUpdateOperation     = "exit_pool_update"
	exitPoolDeleteOperation     = "exit_pool_delete"
	exitPoolNodePutOperation    = "exit_pool_node_put"
	exitPoolNodeDeleteOperation = "exit_pool_node_delete"
)

// ExitPoolManager lists and changes the Exit Pools of a Network and their
// exit nodes.
type ExitPoolManager interface {
	List(context.Context, accountsession.Session, network.Scope, exitpool.ID, int) (exitpool.Listing, error)
	Read(context.Context, accountsession.Session, network.Scope, exitpool.ID) (exitpool.Reading, error)
	Create(context.Context, accountsession.Session, network.Scope, exitpool.Definition,
		publicid.ID) (exitpool.Result, error)
	Update(context.Context, accountsession.Session, network.Scope, exitpool.ID, int64, exitpool.Definition,
		publicid.ID) (exitpool.Result, error)
	Delete(context.Context, accountsession.Session, network.Scope, exitpool.ID, int64,
		publicid.ID) (exitpool.Result, error)
	PutNode(context.Context, accountsession.Session, network.Scope, exitpool.ID, int64, exitpool.NodeAssignment,
		publicid.ID) (exitpool.Result, error)
	RemoveNode(context.Context, accountsession.Session, network.Scope, exitpool.ID, int64, node.ID,
		publicid.ID) (exitpool.Result, error)
}

type exitPoolPath struct {
	scope    network.Scope
	poolID   exitpool.ID
	deviceID node.ID
	methods  restMethods
	// operation is what the request's method does at the path; empty when
	// the path does not accept the method.
	operation string
	after     exitpool.ID
	limit     int
}

// parseExitPoolPath matches, under /api/v1/workspaces/{ws}/networks/{net}:
//
//	GET|POST         exit-pools                       list, create
//	GET|PATCH|DELETE exit-pools/{pool}                read, update, delete
//	PUT|DELETE       exit-pools/{pool}/nodes/{device} set, remove an exit node
//
// Only the list takes a query: after (a pool ID) and limit, once each.
func parseExitPoolPath(request *http.Request) (exitPoolPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" {
		return exitPoolPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) < 7 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" ||
		segments[4] != "networks" || segments[6] != "exit-pools" {
		return exitPoolPath{}, false
	}
	workspaceID, err := workspace.ParseID(segments[3])
	if err != nil || workspaceID.String() != segments[3] {
		return exitPoolPath{}, false
	}
	networkID, err := network.ParseID(segments[5])
	if err != nil || networkID.String() != segments[5] {
		return exitPoolPath{}, false
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return exitPoolPath{}, false
	}
	path := exitPoolPath{scope: scope}
	rest := segments[7:]
	var operations map[string]string
	switch {
	case len(rest) == 0:
		path.methods = collectionMethods
		operations = map[string]string{http.MethodGet: exitPoolListOperation, http.MethodPost: exitPoolCreateOperation}
	case len(rest) == 1:
		path.methods = restMethods{http.MethodGet, http.MethodPatch, http.MethodDelete}
		operations = map[string]string{http.MethodGet: exitPoolReadOperation, http.MethodPatch: exitPoolUpdateOperation,
			http.MethodDelete: exitPoolDeleteOperation}
	case len(rest) == 3 && rest[1] == "nodes":
		device, err := node.ParseID(rest[2])
		if err != nil || device.String() != rest[2] {
			return exitPoolPath{}, false
		}
		path.deviceID = device
		path.methods = restMethods{http.MethodPut, http.MethodDelete}
		operations = map[string]string{http.MethodPut: exitPoolNodePutOperation,
			http.MethodDelete: exitPoolNodeDeleteOperation}
	default:
		return exitPoolPath{}, false
	}
	if len(rest) > 0 {
		id, err := exitpool.ParseID(rest[0])
		if err != nil || id.String() != rest[0] {
			return exitPoolPath{}, false
		}
		path.poolID = id
	}
	if path.methods.allows(request.Method) {
		path.operation = operations[request.Method]
	}
	if path.operation == exitPoolListOperation {
		return path.withPage(request.URL.RawQuery)
	}
	return path, request.URL.RawQuery == ""
}

func (path exitPoolPath) withPage(rawQuery string) (exitPoolPath, bool) {
	path.limit = exitpool.DefaultPage
	if rawQuery == "" {
		return path, true
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return exitPoolPath{}, false
	}
	for key, items := range values {
		if (key != "after" && key != "limit") || len(items) != 1 || items[0] == "" {
			return exitPoolPath{}, false
		}
	}
	if value := values.Get("after"); value != "" {
		after, err := exitpool.ParseID(value)
		if err != nil || after.String() != value {
			return exitPoolPath{}, false
		}
		path.after = after
	}
	if value := values.Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || strconv.Itoa(limit) != value || limit < 1 || limit > exitpool.MaximumPage {
			return exitPoolPath{}, false
		}
		path.limit = limit
	}
	return path, true
}

// isExitPoolOperation admits only the methods each path accepts.
func isExitPoolOperation(request *http.Request) bool {
	path, ok := parseExitPoolPath(request)
	return ok && path.methods.allows(request.Method)
}

// isExitPoolRead admits the list and one pool.
func isExitPoolRead(request *http.Request) bool {
	return request != nil && request.Method == http.MethodGet && isExitPoolOperation(request)
}

type exitPoolProbeBody struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

type exitNodeBody struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Priority   int    `json:"priority"`
	State      string `json:"state"`
	Offered    bool   `json:"offered"`
	Eligible   bool   `json:"eligible"`
	AddedAt    string `json:"added_at"`
}

type exitPoolBody struct {
	PoolID               string              `json:"exit_pool_id"`
	Name                 string              `json:"name"`
	Failback             bool                `json:"failback"`
	SMTPAllowed          bool                `json:"smtp_allowed"`
	ConntrackPerConsumer int                 `json:"conntrack_per_consumer"`
	DNSUpstreams         []string            `json:"dns_upstreams"`
	Probes               []exitPoolProbeBody `json:"probes"`
	Nodes                []exitNodeBody      `json:"nodes"`
	Version              int64               `json:"version"`
	CreatedAt            string              `json:"created_at"`
	UpdatedAt            string              `json:"updated_at"`
}

var exitNodeStateNames = map[exitpool.NodeState]string{exitpool.NodeActive: "active", exitpool.NodeDraining: "draining"}

func newExitPoolBody(stored exitpool.Pool) exitPoolBody {
	body := exitPoolBody{
		PoolID: stored.ID.String(), Name: stored.Name, Failback: stored.Failback, SMTPAllowed: stored.SMTPAllowed,
		ConntrackPerConsumer: stored.ConntrackPerConsumer,
		DNSUpstreams:         make([]string, 0, len(stored.DNSUpstreams)),
		Probes:               make([]exitPoolProbeBody, 0, len(stored.Probes)),
		Nodes:                make([]exitNodeBody, 0, len(stored.Nodes)), Version: stored.Version,
		CreatedAt: managementTime(stored.CreatedAt), UpdatedAt: managementTime(stored.UpdatedAt),
	}
	for _, address := range stored.DNSUpstreams {
		body.DNSUpstreams = append(body.DNSUpstreams, address.String())
	}
	for _, probe := range stored.Probes {
		body.Probes = append(body.Probes, exitPoolProbeBody{Address: probe.Address.String(), Port: probe.Port})
	}
	for _, exitNode := range stored.Nodes {
		body.Nodes = append(body.Nodes, exitNodeBody{
			DeviceID: exitNode.DeviceID.String(), DeviceName: exitNode.DeviceName, Priority: exitNode.Priority,
			State: exitNodeStateNames[exitNode.State], Offered: exitNode.Offered, Eligible: exitNode.Eligible,
			AddedAt: managementTime(exitNode.AddedAt),
		})
	}
	return body
}

// parseExitPoolDefinition reads a whole definition; PATCH replaces it whole
// too. Addresses must be canonical text: the API never rewrites them.
func parseExitPoolDefinition(response http.ResponseWriter, request *http.Request) (exitpool.Definition, bool) {
	var body struct {
		Name                 *string              `json:"name"`
		Failback             *bool                `json:"failback"`
		SMTPAllowed          *bool                `json:"smtp_allowed"`
		ConntrackPerConsumer *int                 `json:"conntrack_per_consumer"`
		DNSUpstreams         *[]string            `json:"dns_upstreams"`
		Probes               *[]exitPoolProbeBody `json:"probes"`
	}
	if !readSiteBody(response, request, &body) || body.Name == nil || body.Failback == nil ||
		body.SMTPAllowed == nil || body.ConntrackPerConsumer == nil || body.DNSUpstreams == nil ||
		body.Probes == nil || len(*body.DNSUpstreams) > exitpool.MaximumDNSUpstreams ||
		len(*body.Probes) > exitpool.MaximumProbesPerPool {
		return exitpool.Definition{}, false
	}
	definition := exitpool.Definition{Name: *body.Name, Failback: *body.Failback, SMTPAllowed: *body.SMTPAllowed,
		ConntrackPerConsumer: *body.ConntrackPerConsumer}
	for _, text := range *body.DNSUpstreams {
		address, err := netip.ParseAddr(text)
		if err != nil || address.String() != text {
			return exitpool.Definition{}, false
		}
		definition.DNSUpstreams = append(definition.DNSUpstreams, address)
	}
	for _, item := range *body.Probes {
		address, err := netip.ParseAddr(item.Address)
		if err != nil || address.String() != item.Address {
			return exitpool.Definition{}, false
		}
		definition.Probes = append(definition.Probes, exitpool.Probe{Address: address, Port: item.Port})
	}
	return definition, true
}

func parseExitNodeAssignment(response http.ResponseWriter, request *http.Request,
	device node.ID) (exitpool.NodeAssignment, bool) {
	var body struct {
		Priority *int    `json:"priority"`
		State    *string `json:"state"`
	}
	if !readSiteBody(response, request, &body) || body.Priority == nil || body.State == nil {
		return exitpool.NodeAssignment{}, false
	}
	state := map[string]exitpool.NodeState{"active": exitpool.NodeActive, "draining": exitpool.NodeDraining}[*body.State]
	assignment := exitpool.NodeAssignment{DeviceID: device, Priority: *body.Priority, State: state}
	return assignment, assignment.Validate() == nil
}

func (handler *ManagementHandler) handleExitPools(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path exitPoolPath, session accountsession.Session) string {
	fail := func(failure managementError) string {
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	if nilContinuationDependency(handler.exitPools) {
		return fail(managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Exit Pools are temporarily unavailable", Retryable: true})
	}
	response.Header().Set("Cache-Control", "no-store")
	switch path.operation {
	case exitPoolListOperation, exitPoolReadOperation:
		return handler.readExitPools(ctx, response, correlationID, path, session, fail)
	case exitPoolCreateOperation:
		definition, valid := parseExitPoolDefinition(response, request)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		result, err := handler.exitPools.Create(ctx, session, path.scope, definition, correlationID)
		return handler.writeExitPoolResult(ctx, response, correlationID, http.StatusCreated, result, err, fail)
	}
	expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		return fail(*precondition)
	}
	var result exitpool.Result
	var err error
	switch path.operation {
	case exitPoolUpdateOperation:
		definition, valid := parseExitPoolDefinition(response, request)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		result, err = handler.exitPools.Update(ctx, session, path.scope, path.poolID, expectedVersion, definition,
			correlationID)
	case exitPoolDeleteOperation:
		result, err = handler.exitPools.Delete(ctx, session, path.scope, path.poolID, expectedVersion, correlationID)
	case exitPoolNodePutOperation:
		assignment, valid := parseExitNodeAssignment(response, request, path.deviceID)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		result, err = handler.exitPools.PutNode(ctx, session, path.scope, path.poolID, expectedVersion, assignment,
			correlationID)
	case exitPoolNodeDeleteOperation:
		result, err = handler.exitPools.RemoveNode(ctx, session, path.scope, path.poolID, expectedVersion,
			path.deviceID, correlationID)
	default:
		return fail(*invalidManagementRequest())
	}
	return handler.writeExitPoolResult(ctx, response, correlationID, http.StatusOK, result, err, fail)
}

func (handler *ManagementHandler) readExitPools(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path exitPoolPath, session accountsession.Session,
	fail func(managementError) string) string {
	if path.operation == exitPoolReadOperation {
		reading, err := handler.exitPools.Read(ctx, session, path.scope, path.poolID)
		if err != nil {
			return fail(classifyExitPoolError(err))
		}
		var output struct {
			Data struct {
				Pool      exitPoolBody `json:"exit_pool"`
				CanManage bool         `json:"can_manage"`
				CanDelete bool         `json:"can_delete"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}
		output.Data.Pool, output.Data.CanManage = newExitPoolBody(reading.Pool), reading.CanManage
		output.Data.CanDelete, output.CorrelationID = reading.CanDelete, correlationID.String()
		response.Header().Set("ETag", strongVersionETag(reading.Pool.Version))
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
		return "success"
	}
	listing, err := handler.exitPools.List(ctx, session, path.scope, path.after, path.limit)
	if err != nil {
		return fail(classifyExitPoolError(err))
	}
	bodies := make([]exitPoolBody, 0, len(listing.Pools))
	for _, stored := range listing.Pools {
		bodies = append(bodies, newExitPoolBody(stored))
	}
	var output struct {
		Data struct {
			Pools     []exitPoolBody `json:"exit_pools"`
			Next      string         `json:"next_after,omitempty"`
			CanManage bool           `json:"can_manage"`
			CanDelete bool           `json:"can_delete"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Pools, output.Data.CanManage, output.Data.CanDelete = bodies, listing.CanManage, listing.CanDelete
	if listing.HasMore && len(listing.Pools) > 0 {
		output.Data.Next = listing.Pools[len(listing.Pools)-1].ID.String()
	}
	output.CorrelationID = correlationID.String()
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

func (handler *ManagementHandler) writeExitPoolResult(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, status int, result exitpool.Result, err error, fail func(managementError) string) string {
	if err != nil {
		return fail(classifyExitPoolError(err))
	}
	var output struct {
		Data struct {
			Pool    exitPoolBody `json:"exit_pool"`
			Deleted bool         `json:"deleted"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Pool, output.Data.Deleted, output.CorrelationID = newExitPoolBody(result.Pool), result.Deleted,
		correlationID.String()
	response.Header().Set("ETag", strongVersionETag(result.Pool.Version))
	writeManagementJSON(ctx, handler.logger, response, status, output)
	return "success"
}

func classifyExitPoolError(err error) managementError {
	switch {
	case errors.Is(err, exitpool.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot view or change Exit Pools in this Network"}
	case errors.Is(err, exitpool.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "exit_pool_not_found",
			Message: "The Exit Pool or exit node no longer exists"}
	case errors.Is(err, exitpool.ErrVersionConflict):
		return managementError{Status: http.StatusPreconditionFailed, Code: "version_conflict",
			Message: "The Exit Pool changed. Reload and review it again."}
	case errors.Is(err, exitpool.ErrNameTaken):
		return managementError{Status: http.StatusConflict, Code: "exit_pool_name_taken",
			Message: "Another Exit Pool in this Network has that name"}
	case errors.Is(err, exitpool.ErrPoolLimit):
		return managementError{Status: http.StatusConflict, Code: "exit_pool_limit",
			Message: "This Network already has the most Exit Pools its plan allows"}
	case errors.Is(err, exitpool.ErrNodeLimit):
		return managementError{Status: http.StatusConflict, Code: "exit_node_limit",
			Message: "The Exit Pool already has the most exit nodes it can have"}
	case errors.Is(err, exitpool.ErrNodeNotEligible):
		return managementError{Status: http.StatusConflict, Code: "exit_node_not_eligible",
			Message: "Only an active Device owned by the Workspace in this Network can be an exit node"}
	case errors.Is(err, exitpool.ErrNodeInOtherPool):
		return managementError{Status: http.StatusConflict, Code: "exit_node_in_other_pool",
			Message: "The Device is already an exit node of another Exit Pool. Remove it there first."}
	case errors.Is(err, exitpool.ErrInUse):
		return managementError{Status: http.StatusConflict, Code: "exit_pool_in_use",
			Message: "Active rules name this Exit Pool. Change those rules first."}
	case errors.Is(err, exitpool.ErrNotInternet):
		return managementError{Status: http.StatusUnprocessableEntity, Code: "exit_pool_address_not_internet",
			Message: "A resolver or probe address is not on the Internet: private, local, the mesh or a special range"}
	case errors.Is(err, exitpool.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload Exit Pools before trying again.", Retryable: true}
	}
}
