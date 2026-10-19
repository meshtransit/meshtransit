package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/site"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	siteListOperation           = "site_list"
	siteReadOperation           = "site_read"
	siteCreateOperation         = "site_create"
	siteUpdateOperation         = "site_update"
	siteDeleteOperation         = "site_delete"
	siteRouterPutOperation      = "site_router_put"
	siteRouterDeleteOperation   = "site_router_delete"
	sitePrimaryHistoryOperation = "site_primary_history"
	maximumSiteBodyBytes        = 128 << 10
)

// SiteManager lists and changes the Sites of a Network and their routers.
type SiteManager interface {
	List(context.Context, accountsession.Session, network.Scope, site.ID, int) (site.Listing, error)
	Read(context.Context, accountsession.Session, network.Scope, site.ID) (site.Reading, error)
	Create(context.Context, accountsession.Session, network.Scope, site.Definition, publicid.ID) (site.Result, error)
	Update(context.Context, accountsession.Session, network.Scope, site.ID, int64, site.Definition,
		publicid.ID) (site.Result, error)
	Delete(context.Context, accountsession.Session, network.Scope, site.ID, int64, publicid.ID) (site.Result, error)
	PutRouter(context.Context, accountsession.Session, network.Scope, site.ID, int64, site.RouterAssignment,
		publicid.ID) (site.Result, error)
	RemoveRouter(context.Context, accountsession.Session, network.Scope, site.ID, int64, site.RouterAssignment,
		publicid.ID) (site.Result, error)
	PrimaryChanges(context.Context, accountsession.Session, network.Scope, site.ID, publicid.ID,
		int) (site.PrimaryHistory, error)
}

type sitePath struct {
	scope    network.Scope
	siteID   site.ID
	deviceID node.ID
	methods  restMethods
	// operation is what the request's method does at the path; empty when
	// the path does not accept the method.
	operation string
	after     site.ID
	limit     int
	// afterEvent pages the primary history.
	afterEvent publicid.ID
}

// parseSitePath matches, under /api/v1/workspaces/{ws}/networks/{net}:
//
//	GET|POST         sites                        list, create
//	GET|PATCH|DELETE sites/{site}                 read, update, delete
//	PUT|DELETE       sites/{site}/routers/{device} set, remove a router
//	GET              sites/{site}/primary-changes  the elected primary's history
//
// Only the lists take a query: after (a Site or change ID) and limit, once
// each.
func parseSitePath(request *http.Request) (sitePath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" {
		return sitePath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) < 7 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" ||
		segments[4] != "networks" || segments[6] != "sites" {
		return sitePath{}, false
	}
	workspaceID, err := workspace.ParseID(segments[3])
	if err != nil || workspaceID.String() != segments[3] {
		return sitePath{}, false
	}
	networkID, err := network.ParseID(segments[5])
	if err != nil || networkID.String() != segments[5] {
		return sitePath{}, false
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return sitePath{}, false
	}
	path := sitePath{scope: scope}
	rest := segments[7:]
	var operations map[string]string
	switch {
	case len(rest) == 0:
		path.methods = collectionMethods
		operations = map[string]string{http.MethodGet: siteListOperation, http.MethodPost: siteCreateOperation}
	case len(rest) == 1:
		path.methods = restMethods{http.MethodGet, http.MethodPatch, http.MethodDelete}
		operations = map[string]string{http.MethodGet: siteReadOperation, http.MethodPatch: siteUpdateOperation,
			http.MethodDelete: siteDeleteOperation}
	case len(rest) == 2 && rest[1] == "primary-changes":
		path.methods = restMethods{http.MethodGet}
		operations = map[string]string{http.MethodGet: sitePrimaryHistoryOperation}
	case len(rest) == 3 && rest[1] == "routers":
		device, err := node.ParseID(rest[2])
		if err != nil || device.String() != rest[2] {
			return sitePath{}, false
		}
		path.deviceID = device
		path.methods = restMethods{http.MethodPut, http.MethodDelete}
		operations = map[string]string{http.MethodPut: siteRouterPutOperation, http.MethodDelete: siteRouterDeleteOperation}
	default:
		return sitePath{}, false
	}
	if len(rest) > 0 {
		id, err := site.ParseID(rest[0])
		if err != nil || id.String() != rest[0] {
			return sitePath{}, false
		}
		path.siteID = id
	}
	if path.methods.allows(request.Method) {
		path.operation = operations[request.Method]
	}
	switch path.operation {
	case siteListOperation:
		return path.withPage(request.URL.RawQuery)
	case sitePrimaryHistoryOperation:
		return path.withHistoryPage(request.URL.RawQuery)
	default:
		return path, request.URL.RawQuery == ""
	}
}

func (path sitePath) withHistoryPage(rawQuery string) (sitePath, bool) {
	path.limit = site.DefaultHistoryPage
	if rawQuery == "" {
		return path, true
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return sitePath{}, false
	}
	for key, items := range values {
		if (key != "after" && key != "limit") || len(items) != 1 || items[0] == "" {
			return sitePath{}, false
		}
	}
	if value := values.Get("after"); value != "" {
		after, err := publicid.Parse(value)
		if err != nil || after.String() != value {
			return sitePath{}, false
		}
		path.afterEvent = after
	}
	if value := values.Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || strconv.Itoa(limit) != value || limit < 1 || limit > site.MaximumHistoryPage {
			return sitePath{}, false
		}
		path.limit = limit
	}
	return path, true
}

func (path sitePath) withPage(rawQuery string) (sitePath, bool) {
	path.limit = site.DefaultPage
	if rawQuery == "" {
		return path, true
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return sitePath{}, false
	}
	for key, items := range values {
		if (key != "after" && key != "limit") || len(items) != 1 || items[0] == "" {
			return sitePath{}, false
		}
	}
	if value := values.Get("after"); value != "" {
		after, err := site.ParseID(value)
		if err != nil || after.String() != value {
			return sitePath{}, false
		}
		path.after = after
	}
	if value := values.Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || strconv.Itoa(limit) != value || limit < 1 || limit > site.MaximumPage {
			return sitePath{}, false
		}
		path.limit = limit
	}
	return path, true
}

// isSiteOperation admits only the methods each path accepts.
func isSiteOperation(request *http.Request) bool {
	path, ok := parseSitePath(request)
	return ok && path.methods.allows(request.Method)
}

// isSiteRead admits the list and one Site.
func isSiteRead(request *http.Request) bool {
	return request != nil && request.Method == http.MethodGet && isSiteOperation(request)
}

type siteProbeBody struct {
	Address string `json:"address"`
	Kind    string `json:"kind"`
	Port    uint16 `json:"port"`
}

type siteRouterBody struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Priority   int    `json:"priority"`
	State      string `json:"state"`
	Eligible   bool   `json:"eligible"`
	AddedAt    string `json:"added_at"`
	// Health and RouteEnforcement come with one Site's read only: the
	// router's own measure of this Site, absent when it reported none in the
	// last 30 seconds, and whether it forwards into the routes it was sent.
	Health           *siteRouterHealthBody `json:"health,omitempty"`
	RouteEnforcement string                `json:"route_enforcement,omitempty"`
	// Clients and LocalFailoverClients, with one Site's read, count the
	// Devices that reported using the router in the last three minutes, and
	// those of them that chose it while the primary did not answer.
	Clients              *int `json:"clients,omitempty"`
	LocalFailoverClients *int `json:"local_failover_clients,omitempty"`
}

// SiteRouterUseCounter counts, per router of a Site, the Devices that report
// using it.
type SiteRouterUseCounter interface {
	CountSiteRouters(ctx context.Context, siteRef string, now time.Time) (map[string]distribution.RouterUse, error)
}

// sitePrimaryBody is the router Core elected; DeviceID is null when no
// router can serve.
type sitePrimaryBody struct {
	DeviceID   *string `json:"device_id"`
	Generation int64   `json:"generation"`
	Reason     string  `json:"reason"`
	ElectedAt  string  `json:"elected_at"`
}

type sitePrimaryChangeBody struct {
	EventID          string  `json:"event_id"`
	OccurredAt       string  `json:"occurred_at"`
	DeviceID         *string `json:"device_id"`
	PreviousDeviceID *string `json:"previous_device_id"`
	Reason           string  `json:"reason"`
	Generation       int64   `json:"generation"`
}

func optionalDeviceText(device node.ID) *string {
	if device == (node.ID{}) {
		return nil
	}
	text := device.String()
	return &text
}

type siteBody struct {
	SiteID     string           `json:"site_id"`
	Name       string           `json:"name"`
	Prefixes   []string         `json:"prefixes"`
	Masquerade bool             `json:"masquerade"`
	Failback   bool             `json:"failback"`
	Probes     []siteProbeBody  `json:"probes"`
	Routers    []siteRouterBody `json:"routers"`
	Version    int64            `json:"version"`
	CreatedAt  string           `json:"created_at"`
	UpdatedAt  string           `json:"updated_at"`
	// Primary comes with one Site's read only, absent before Core's first
	// election.
	Primary *sitePrimaryBody `json:"primary,omitempty"`
}

var routerStateNames = map[site.RouterState]string{site.RouterActive: "active", site.RouterDraining: "draining"}

func newSiteBody(stored site.Site) siteBody {
	body := siteBody{
		SiteID: stored.ID.String(), Name: stored.Name, Masquerade: stored.Masquerade, Failback: stored.Failback,
		Prefixes: make([]string, 0, len(stored.Prefixes)), Probes: make([]siteProbeBody, 0, len(stored.Probes)),
		Routers: make([]siteRouterBody, 0, len(stored.Routers)), Version: stored.Version,
		CreatedAt: managementTime(stored.CreatedAt), UpdatedAt: managementTime(stored.UpdatedAt),
	}
	for _, prefix := range stored.Prefixes {
		body.Prefixes = append(body.Prefixes, prefix.String())
	}
	for _, probe := range stored.Probes {
		kind := "icmp"
		if probe.Kind == site.ProbeTCP {
			kind = "tcp"
		}
		body.Probes = append(body.Probes, siteProbeBody{Address: probe.Address.String(), Kind: kind, Port: probe.Port})
	}
	for _, router := range stored.Routers {
		body.Routers = append(body.Routers, siteRouterBody{
			DeviceID: router.DeviceID.String(), DeviceName: router.DeviceName, Priority: router.Priority,
			State: routerStateNames[router.State], Eligible: router.Eligible, AddedAt: managementTime(router.AddedAt),
		})
	}
	return body
}

func readSiteBody(response http.ResponseWriter, request *http.Request, target any) bool {
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maximumSiteBodyBytes))
	if err != nil {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil && ensureJSONEnd(decoder) == nil
}

// parseSiteDefinition reads a whole definition; PATCH replaces it whole too.
// Prefixes and probes must be canonical text: the API never rewrites them.
func parseSiteDefinition(response http.ResponseWriter, request *http.Request) (site.Definition, bool) {
	var body struct {
		Name       *string          `json:"name"`
		Prefixes   *[]string        `json:"prefixes"`
		Masquerade *bool            `json:"masquerade"`
		Failback   *bool            `json:"failback"`
		Probes     *[]siteProbeBody `json:"probes"`
	}
	if !readSiteBody(response, request, &body) || body.Name == nil || body.Prefixes == nil ||
		body.Masquerade == nil || body.Failback == nil || body.Probes == nil ||
		len(*body.Prefixes) > site.MaximumPrefixesPerSite || len(*body.Probes) > site.MaximumProbesPerSite {
		return site.Definition{}, false
	}
	definition := site.Definition{Name: *body.Name, Masquerade: *body.Masquerade, Failback: *body.Failback}
	for _, text := range *body.Prefixes {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || prefix.String() != text {
			return site.Definition{}, false
		}
		definition.Prefixes = append(definition.Prefixes, prefix)
	}
	for _, item := range *body.Probes {
		address, err := netip.ParseAddr(item.Address)
		kind := map[string]site.ProbeKind{"icmp": site.ProbeICMP, "tcp": site.ProbeTCP}[item.Kind]
		if err != nil || address.String() != item.Address || kind == 0 {
			return site.Definition{}, false
		}
		definition.Probes = append(definition.Probes, site.Probe{Address: address, Kind: kind, Port: item.Port})
	}
	return definition, true
}

func parseRouterAssignment(response http.ResponseWriter, request *http.Request,
	device node.ID) (site.RouterAssignment, bool) {
	var body struct {
		Priority *int    `json:"priority"`
		State    *string `json:"state"`
	}
	if !readSiteBody(response, request, &body) || body.Priority == nil || body.State == nil {
		return site.RouterAssignment{}, false
	}
	state := map[string]site.RouterState{"active": site.RouterActive, "draining": site.RouterDraining}[*body.State]
	assignment := site.RouterAssignment{DeviceID: device, Priority: *body.Priority, State: state}
	return assignment, assignment.Validate() == nil
}

func (handler *ManagementHandler) handleSites(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path sitePath, session accountsession.Session) string {
	fail := func(failure managementError) string {
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	if nilContinuationDependency(handler.sites) {
		return fail(managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Sites are temporarily unavailable", Retryable: true})
	}
	response.Header().Set("Cache-Control", "no-store")
	switch path.operation {
	case siteListOperation, siteReadOperation:
		return handler.readSites(ctx, response, correlationID, path, session, fail)
	case sitePrimaryHistoryOperation:
		return handler.readSitePrimaryHistory(ctx, response, correlationID, path, session, fail)
	case siteCreateOperation:
		definition, valid := parseSiteDefinition(response, request)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		result, err := handler.sites.Create(ctx, session, path.scope, definition, correlationID)
		return handler.writeSiteResult(ctx, response, correlationID, http.StatusCreated, result, err, fail)
	}
	expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		return fail(*precondition)
	}
	var result site.Result
	var err error
	switch path.operation {
	case siteUpdateOperation:
		definition, valid := parseSiteDefinition(response, request)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		result, err = handler.sites.Update(ctx, session, path.scope, path.siteID, expectedVersion, definition, correlationID)
	case siteDeleteOperation:
		result, err = handler.sites.Delete(ctx, session, path.scope, path.siteID, expectedVersion, correlationID)
	case siteRouterPutOperation:
		assignment, valid := parseRouterAssignment(response, request, path.deviceID)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		result, err = handler.sites.PutRouter(ctx, session, path.scope, path.siteID, expectedVersion, assignment,
			correlationID)
	default:
		result, err = handler.sites.RemoveRouter(ctx, session, path.scope, path.siteID, expectedVersion,
			site.RouterAssignment{DeviceID: path.deviceID}, correlationID)
	}
	return handler.writeSiteResult(ctx, response, correlationID, http.StatusOK, result, err, fail)
}

func (handler *ManagementHandler) readSites(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path sitePath, session accountsession.Session, fail func(managementError) string) string {
	if path.operation == siteReadOperation {
		reading, err := handler.sites.Read(ctx, session, path.scope, path.siteID)
		if err != nil {
			return fail(classifySiteError(err))
		}
		var output struct {
			Data struct {
				Site      siteBody `json:"site"`
				CanManage bool     `json:"can_manage"`
				CanDelete bool     `json:"can_delete"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}
		output.Data.Site, output.Data.CanManage = newSiteBody(reading.Site), reading.CanManage
		if primary := reading.Primary; primary != nil {
			output.Data.Site.Primary = &sitePrimaryBody{DeviceID: optionalDeviceText(primary.Device),
				Generation: primary.Generation, Reason: primary.Reason, ElectedAt: managementTime(primary.ElectedAt)}
		}
		handler.addRouterHealth(ctx, &output.Data.Site, reading.Site)
		handler.addRouterUse(ctx, &output.Data.Site, reading.Site)
		output.Data.CanDelete, output.CorrelationID = reading.CanDelete, correlationID.String()
		response.Header().Set("ETag", strongVersionETag(reading.Site.Version))
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
		return "success"
	}
	listing, err := handler.sites.List(ctx, session, path.scope, path.after, path.limit)
	if err != nil {
		return fail(classifySiteError(err))
	}
	bodies := make([]siteBody, 0, len(listing.Sites))
	for _, stored := range listing.Sites {
		bodies = append(bodies, newSiteBody(stored))
	}
	var output struct {
		Data struct {
			Sites     []siteBody `json:"sites"`
			Next      string     `json:"next_after,omitempty"`
			CanManage bool       `json:"can_manage"`
			CanDelete bool       `json:"can_delete"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Sites, output.Data.CanManage, output.Data.CanDelete = bodies, listing.CanManage, listing.CanDelete
	if listing.HasMore && len(listing.Sites) > 0 {
		output.Data.Next = listing.Sites[len(listing.Sites)-1].ID.String()
	}
	output.CorrelationID = correlationID.String()
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

func (handler *ManagementHandler) writeSiteResult(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, status int, result site.Result, err error, fail func(managementError) string) string {
	if err != nil {
		return fail(classifySiteError(err))
	}
	var output struct {
		Data struct {
			Site    siteBody `json:"site"`
			Deleted bool     `json:"deleted"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Site, output.Data.Deleted, output.CorrelationID = newSiteBody(result.Site), result.Deleted,
		correlationID.String()
	response.Header().Set("ETag", strongVersionETag(result.Site.Version))
	writeManagementJSON(ctx, handler.logger, response, status, output)
	return "success"
}

func classifySiteError(err error) managementError {
	switch {
	case errors.Is(err, site.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot view or change Sites in this Network"}
	case errors.Is(err, site.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "site_not_found",
			Message: "The Site or router no longer exists"}
	case errors.Is(err, site.ErrVersionConflict):
		return managementError{Status: http.StatusPreconditionFailed, Code: "version_conflict",
			Message: "The Site changed. Reload and review it again."}
	case errors.Is(err, site.ErrNameTaken):
		return managementError{Status: http.StatusConflict, Code: "site_name_taken",
			Message: "Another Site in this Network has that name"}
	case errors.Is(err, site.ErrSiteLimit):
		return managementError{Status: http.StatusConflict, Code: "site_limit",
			Message: "This Network already has the most Sites its plan allows"}
	case errors.Is(err, site.ErrPrefixLimit):
		return managementError{Status: http.StatusConflict, Code: "site_prefix_limit",
			Message: "The Site has more prefixes than its plan allows"}
	case errors.Is(err, site.ErrRouterLimit):
		return managementError{Status: http.StatusConflict, Code: "site_router_limit",
			Message: "The Site already has the most routers it can have"}
	case errors.Is(err, site.ErrMasqueradeRequired):
		return managementError{Status: http.StatusConflict, Code: "site_masquerade_requires_single_router",
			Message: "A Site without masquerade can have one router only"}
	case errors.Is(err, site.ErrRouterNotEligible):
		return managementError{Status: http.StatusConflict, Code: "router_not_eligible",
			Message: "Only an active Device owned by the Workspace in this Network can be a router"}
	case errors.Is(err, site.ErrRouterNotOffering):
		return managementError{Status: http.StatusConflict, Code: "router_not_advertising",
			Message: "The Device does not offer the Site's prefixes. Set them in its local configuration first."}
	case errors.Is(err, site.ErrInUse):
		return managementError{Status: http.StatusConflict, Code: "site_in_use",
			Message: "Active rules name this Site. Change those rules first."}
	case errors.Is(err, site.ErrPrefixesInUse):
		return managementError{Status: http.StatusConflict, Code: "site_prefixes_in_use",
			Message: "Active rules grant prefixes this change removes. Change those rules first."}
	case errors.Is(err, site.ErrInvalidPrefix):
		return managementError{Status: http.StatusUnprocessableEntity, Code: "site_prefix_invalid",
			Message: "A prefix overlaps another, the mesh, a special range or an address clients use, or is too wide"}
	case errors.Is(err, site.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload Sites before trying again.", Retryable: true}
	}
}

// siteRouterObservationTimeout bounds reading a Site's routers' delivery
// records.
const siteRouterObservationTimeout = time.Second

type siteRouterHealthBody struct {
	// State is ok, degraded or failed; Code the router's reason.
	State      string `json:"state"`
	Code       string `json:"code"`
	ReportedAt string `json:"reported_at"`
}

// addRouterHealth adds to one Site's read what its routers report: their
// health of the Site and their route enforcement. Delivery records are
// operational: when they cannot be read the Site is answered without them.
func (handler *ManagementHandler) addRouterHealth(ctx context.Context, body *siteBody, stored site.Site) {
	if handler.siteRouterObservations == nil || len(stored.Routers) == 0 {
		return
	}
	ids := make([]node.ID, 0, len(stored.Routers))
	for _, router := range stored.Routers {
		ids = append(ids, router.DeviceID)
	}
	// Bounded, so a slow Redis delays a Site's read by at most a second.
	loadCtx, cancel := context.WithTimeout(ctx, siteRouterObservationTimeout)
	defer cancel()
	observations, err := handler.siteRouterObservations.LoadObservations(loadCtx, ids)
	if err != nil || len(observations) != len(ids) {
		handler.logger.DebugContext(ctx, "site router delivery records unavailable", "error", err)
		return
	}
	now := time.Now()
	siteID := stored.ID.String()
	for index := range body.Routers {
		observation := observations[index]
		if !observation.IsValid() {
			continue
		}
		body.Routers[index].RouteEnforcement = string(distribution.ClassifyRouteEnforcement(observation, now))
		health, current := distribution.CurrentRouteHealth(observation, now)
		if !current {
			continue
		}
		for _, entry := range health {
			if entry.Ref == siteID {
				body.Routers[index].Health = &siteRouterHealthBody{State: entry.State, Code: entry.Code,
					ReportedAt: managementTime(observation.RouteHealthAt)}
			}
		}
	}
}

func (handler *ManagementHandler) readSitePrimaryHistory(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path sitePath, session accountsession.Session, fail func(managementError) string) string {
	history, err := handler.sites.PrimaryChanges(ctx, session, path.scope, path.siteID, path.afterEvent, path.limit)
	if err != nil {
		return fail(classifySiteError(err))
	}
	var output struct {
		Data struct {
			Changes []sitePrimaryChangeBody `json:"changes"`
			Next    string                  `json:"next_after,omitempty"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Changes = make([]sitePrimaryChangeBody, 0, len(history.Changes))
	for _, change := range history.Changes {
		output.Data.Changes = append(output.Data.Changes, sitePrimaryChangeBody{
			EventID: change.EventID.String(), OccurredAt: managementTime(change.OccurredAt),
			DeviceID: optionalDeviceText(change.Device), PreviousDeviceID: optionalDeviceText(change.Previous),
			Reason: change.Reason, Generation: change.Generation,
		})
	}
	if history.HasMore && len(history.Changes) > 0 {
		output.Data.Next = history.Changes[len(history.Changes)-1].EventID.String()
	}
	output.CorrelationID = correlationID.String()
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

// addRouterUse adds how many Devices use each router of the Site; nothing
// when the counts cannot be read within a second.
func (handler *ManagementHandler) addRouterUse(ctx context.Context, body *siteBody, stored site.Site) {
	if nilContinuationDependency(handler.siteRouterUse) || len(stored.Routers) == 0 {
		return
	}
	loadCtx, cancel := context.WithTimeout(ctx, siteRouterObservationTimeout)
	defer cancel()
	uses, err := handler.siteRouterUse.CountSiteRouters(loadCtx, stored.ID.String(), time.Now())
	if err != nil {
		handler.logger.DebugContext(ctx, "site router use unavailable", "error", err)
		return
	}
	for index := range body.Routers {
		use := uses[body.Routers[index].DeviceID]
		clients, local := use.Clients, use.LocalFailover
		body.Routers[index].Clients, body.Routers[index].LocalFailoverClients = &clients, &local
	}
}
