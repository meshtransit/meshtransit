package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/platform/ratelimit"
)

const (
	dnsZoneListOperation   = "dns_zone_list"
	dnsZoneReadOperation   = "dns_zone_read"
	dnsZoneCreateOperation = "dns_zone_create"
	dnsZoneUpdateOperation = "dns_zone_update"
	dnsZoneDeleteOperation = "dns_zone_delete"
	dnsNameListOperation   = "dns_name_list"
	dnsNameReadOperation   = "dns_name_read"
	dnsNameCreateOperation = "dns_name_create"
	dnsNameUpdateOperation = "dns_name_update"
	dnsNameDeleteOperation = "dns_name_delete"
	dnsNameApplyOperation  = "dns_name_apply"
)

// DNSZoneManager lists and changes the DNS zones of a Network and the
// names they hold.
type DNSZoneManager interface {
	List(context.Context, accountsession.Session, network.Scope, dnszone.ID, int) (dnszone.Listing, error)
	Read(context.Context, accountsession.Session, network.Scope, dnszone.ID) (dnszone.Reading, error)
	Create(context.Context, accountsession.Session, network.Scope, dnszone.Definition, bool,
		publicid.ID) (dnszone.Result, error)
	Update(context.Context, accountsession.Session, network.Scope, dnszone.ID, int64, dnszone.Definition,
		publicid.ID) (dnszone.Result, error)
	Delete(context.Context, accountsession.Session, network.Scope, dnszone.ID, int64, bool,
		publicid.ID) (dnszone.Result, error)
	ListNames(context.Context, accountsession.Session, network.Scope, dnszone.ID, dnszone.NameID, string,
		int) (dnszone.NameListing, error)
	ReadName(context.Context, accountsession.Session, network.Scope, dnszone.ID,
		dnszone.NameID) (dnszone.NameReading, error)
	CreateName(context.Context, accountsession.Session, network.Scope, dnszone.ID, dnszone.NameDefinition,
		publicid.ID) (dnszone.NameOutcome, error)
	UpdateName(context.Context, accountsession.Session, network.Scope, dnszone.ID, dnszone.NameID, int64,
		dnszone.NameDefinition, publicid.ID) (dnszone.NameOutcome, error)
	DeleteName(context.Context, accountsession.Session, network.Scope, dnszone.ID, dnszone.NameID, int64,
		publicid.ID) (dnszone.NameOutcome, error)
	ApplyNames(context.Context, accountsession.Session, network.Scope, dnszone.ID, []dnszone.NameOperation,
		publicid.ID) (dnszone.NameResult, error)
}

type dnsZonePath struct {
	scope   network.Scope
	zoneID  dnszone.ID
	nameID  dnszone.NameID
	methods restMethods
	// operation is what the request's method does at the path; empty when
	// the path does not accept the method.
	operation string
	after     dnszone.ID
	afterName dnszone.NameID
	prefix    string
	limit     int
	// withNames, on a zone DELETE, deletes the names the zone holds.
	withNames bool
}

// parseDNSZonePath matches, under /api/v1/workspaces/{ws}/networks/{net}:
//
//	GET|POST         dns/zones                                list, create
//	GET|PATCH|DELETE dns/zones/{zone}                         read, update, delete
//	GET|POST         dns/zones/{zone}/names                   list, create
//	GET|PATCH|DELETE dns/zones/{zone}/names/{name}            read, update, delete
//	POST             dns/zones/{zone}/names/actions/apply     apply
//
// Only the lists take a query (after and limit, and q for names) and a zone
// DELETE with_names=true, once each.
func parseDNSZonePath(request *http.Request) (dnsZonePath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" {
		return dnsZonePath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) < 8 || len(segments) > 12 || segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "workspaces" || segments[4] != "networks" || segments[6] != "dns" || segments[7] != "zones" ||
		(len(segments) > 9 && segments[9] != "names") {
		return dnsZonePath{}, false
	}
	workspaceID, err := workspace.ParseID(segments[3])
	if err != nil || workspaceID.String() != segments[3] {
		return dnsZonePath{}, false
	}
	networkID, err := network.ParseID(segments[5])
	if err != nil || networkID.String() != segments[5] {
		return dnsZonePath{}, false
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return dnsZonePath{}, false
	}
	path := dnsZonePath{scope: scope}
	if len(segments) > 8 {
		id, err := dnszone.ParseID(segments[8])
		if err != nil || id.String() != segments[8] {
			return dnsZonePath{}, false
		}
		path.zoneID = id
	}
	var operations map[string]string
	switch {
	case len(segments) == 8:
		path.methods = collectionMethods
		operations = map[string]string{http.MethodGet: dnsZoneListOperation, http.MethodPost: dnsZoneCreateOperation}
	case len(segments) == 9:
		path.methods = restMethods{http.MethodGet, http.MethodPatch, http.MethodDelete}
		operations = map[string]string{http.MethodGet: dnsZoneReadOperation, http.MethodPatch: dnsZoneUpdateOperation,
			http.MethodDelete: dnsZoneDeleteOperation}
	case len(segments) == 10:
		path.methods = collectionMethods
		operations = map[string]string{http.MethodGet: dnsNameListOperation, http.MethodPost: dnsNameCreateOperation}
	case len(segments) == 11:
		id, err := dnszone.ParseNameID(segments[10])
		if err != nil || id.String() != segments[10] {
			return dnsZonePath{}, false
		}
		path.nameID = id
		path.methods = restMethods{http.MethodGet, http.MethodPatch, http.MethodDelete}
		operations = map[string]string{http.MethodGet: dnsNameReadOperation, http.MethodPatch: dnsNameUpdateOperation,
			http.MethodDelete: dnsNameDeleteOperation}
	default:
		if segments[10] != "actions" || segments[11] != "apply" {
			return dnsZonePath{}, false
		}
		path.methods = restMethods{http.MethodPost}
		operations = map[string]string{http.MethodPost: dnsNameApplyOperation}
	}
	if path.methods.allows(request.Method) {
		path.operation = operations[request.Method]
	}
	switch path.operation {
	case dnsZoneListOperation, dnsNameListOperation:
		return path.withPage(request.URL.RawQuery)
	case dnsZoneDeleteOperation:
		if request.URL.RawQuery == "with_names=true" {
			path.withNames = true
			return path, true
		}
	}
	return path, request.URL.RawQuery == ""
}

func (path dnsZonePath) withPage(rawQuery string) (dnsZonePath, bool) {
	path.limit = dnszone.DefaultPage
	if rawQuery == "" {
		return path, true
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return dnsZonePath{}, false
	}
	names := path.operation == dnsNameListOperation
	for key, items := range values {
		if (key != "after" && key != "limit" && (key != "q" || !names)) || len(items) != 1 || items[0] == "" {
			return dnsZonePath{}, false
		}
	}
	if value := values.Get("after"); value != "" {
		if names {
			after, err := dnszone.ParseNameID(value)
			if err != nil || after.String() != value {
				return dnsZonePath{}, false
			}
			path.afterName = after
		} else {
			after, err := dnszone.ParseID(value)
			if err != nil || after.String() != value {
				return dnsZonePath{}, false
			}
			path.after = after
		}
	}
	if value := values.Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil || strconv.Itoa(limit) != value || limit < 1 || limit > dnszone.MaximumPage {
			return dnsZonePath{}, false
		}
		path.limit = limit
	}
	path.prefix = values.Get("q")
	return path, true
}

// isDNSZoneOperation admits only the methods each path accepts.
func isDNSZoneOperation(request *http.Request) bool {
	path, ok := parseDNSZonePath(request)
	return ok && path.methods.allows(request.Method)
}

// isDNSZoneDeleteWithNames admits a zone DELETE with with_names=true, the one
// write whose query the browser guards let through.
func isDNSZoneDeleteWithNames(request *http.Request) bool {
	return request != nil && request.Method == http.MethodDelete && request.URL != nil &&
		request.URL.RawQuery == "with_names=true" && isDNSZoneOperation(request)
}

// isDNSZoneRead admits the list and one zone.
func isDNSZoneRead(request *http.Request) bool {
	return request != nil && request.Method == http.MethodGet && isDNSZoneOperation(request)
}

// dnsZoneResolverBody is a resolver Device (device_id, with its name, state
// and whether it can serve) or an address on the Internet.
type dnsZoneResolverBody struct {
	DeviceID    string `json:"device_id,omitempty"`
	DeviceName  string `json:"device_name,omitempty"`
	DeviceState string `json:"device_state,omitempty"`
	// Eligible, for a resolver Device: active, owned by the Workspace and no
	// exit node.
	Eligible *bool  `json:"eligible,omitempty"`
	Address  string `json:"address,omitempty"`
	Port     uint16 `json:"port"`
}

type dnsZoneGroupBody struct {
	GroupID string `json:"device_group_id"`
	Name    string `json:"name"`
	State   string `json:"state"`
}

type dnsZoneBody struct {
	ZoneID string `json:"dns_zone_id"`
	Domain string `json:"domain"`
	// Kind is forward (a domain) or root (every other name).
	Kind string `json:"kind"`
	// OtherNames is what the names the zone does not hold get: forward
	// (its resolvers), nxdomain or host (the host's own DNS).
	OtherNames  string                `json:"other_names"`
	FailureMode string                `json:"failure_mode"`
	Resolvers   []dnsZoneResolverBody `json:"resolvers"`
	// DeviceGroups empty: every Device of the Network.
	DeviceGroups   []dnsZoneGroupBody `json:"device_groups"`
	SearchPosition *int               `json:"search_position"`
	// Public is whether the domain exists on the Internet.
	Public          bool   `json:"public"`
	PublicConfirmed bool   `json:"public_confirmed"`
	NameCount       int    `json:"name_count"`
	Version         int64  `json:"version"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

func newDNSZoneBody(stored dnszone.Zone) dnsZoneBody {
	body := dnsZoneBody{
		ZoneID: stored.ID.String(), Domain: stored.Domain.String(), Kind: "forward",
		OtherNames: string(stored.OtherNames), FailureMode: string(stored.FailureMode),
		Resolvers: make([]dnsZoneResolverBody, 0, len(stored.Resolvers)), NameCount: stored.NameCount,
		DeviceGroups: make([]dnsZoneGroupBody, 0, len(stored.Groups)), SearchPosition: stored.SearchPosition,
		Public: stored.Class == dnszone.ClassPublic, PublicConfirmed: stored.PublicConfirmed,
		Version: stored.Version, CreatedAt: managementTime(stored.CreatedAt), UpdatedAt: managementTime(stored.UpdatedAt),
	}
	if stored.Domain.IsRoot() {
		body.Kind = "root"
	}
	for _, resolver := range stored.Resolvers {
		item := dnsZoneResolverBody{Port: resolver.Port}
		if resolver.IsDevice() {
			item.DeviceID = resolver.DeviceID.String()
			eligible := false
			if resolver.Device != nil {
				item.DeviceName, item.DeviceState = resolver.Device.Name, resolver.Device.State
				eligible = resolver.Device.Eligible()
			}
			item.Eligible = &eligible
		} else {
			item.Address = resolver.Address.String()
		}
		body.Resolvers = append(body.Resolvers, item)
	}
	for _, group := range stored.Groups {
		body.DeviceGroups = append(body.DeviceGroups, dnsZoneGroupBody{GroupID: group.ID.String(), Name: group.Name,
			State: group.State})
	}
	return body
}

// parseDNSZoneDefinition reads a whole definition; PATCH replaces it whole
// too. The domain is required to create and, when given to update, must be
// the zone's. other_names left out forwards on create and keeps the zone's
// kind on update; a zone that is not forward sends no resolvers and no
// failure mode. adopt_names, on create only, lets the zone take the names
// shorter zones hold under its domain. Addresses and IDs must be canonical
// text: the API never rewrites them.
func parseDNSZoneDefinition(response http.ResponseWriter, request *http.Request,
	create bool) (dnszone.Definition, bool, bool) {
	var body struct {
		Domain      *string `json:"domain"`
		OtherNames  *string `json:"other_names"`
		AdoptNames  *bool   `json:"adopt_names"`
		FailureMode *string `json:"failure_mode"`
		Resolvers   *[]struct {
			DeviceID *string `json:"device_id"`
			Address  *string `json:"address"`
			Port     *uint16 `json:"port"`
		} `json:"resolvers"`
		DeviceGroups    *[]string `json:"device_groups"`
		SearchPosition  *int      `json:"search_position"`
		PublicConfirmed *bool     `json:"public_confirmed"`
	}
	if !readSiteBody(response, request, &body) || (create && body.Domain == nil) || body.Resolvers == nil ||
		body.DeviceGroups == nil || (!create && body.AdoptNames != nil) ||
		len(*body.Resolvers) > dnszone.MaximumResolversPerZone || len(*body.DeviceGroups) > dnszone.MaximumGroupsPerZone {
		return dnszone.Definition{}, false, false
	}
	definition := dnszone.Definition{SearchPosition: body.SearchPosition}
	if body.FailureMode != nil {
		definition.FailureMode = dnszone.FailureMode(*body.FailureMode)
	}
	if body.OtherNames != nil {
		definition.OtherNames = dnszone.OtherNames(*body.OtherNames)
		if !definition.OtherNames.IsKnown() {
			return dnszone.Definition{}, false, false
		}
	}
	adoptNames := body.AdoptNames != nil && *body.AdoptNames
	if body.Domain != nil {
		definition.Domain = *body.Domain
	}
	if body.PublicConfirmed != nil {
		definition.PublicConfirmed = *body.PublicConfirmed
	}
	for _, item := range *body.Resolvers {
		if item.Port == nil || (item.DeviceID == nil) == (item.Address == nil) {
			return dnszone.Definition{}, false, false
		}
		resolver := dnszone.Resolver{Port: *item.Port}
		if item.DeviceID != nil {
			device, err := node.ParseID(*item.DeviceID)
			if err != nil || device.String() != *item.DeviceID {
				return dnszone.Definition{}, false, false
			}
			resolver.DeviceID = device
		} else {
			address, err := netip.ParseAddr(*item.Address)
			if err != nil || address.String() != *item.Address {
				return dnszone.Definition{}, false, false
			}
			resolver.Address = address
		}
		definition.Resolvers = append(definition.Resolvers, resolver)
	}
	for _, text := range *body.DeviceGroups {
		group, err := devicegroup.ParseID(text)
		if err != nil || group.String() != text {
			return dnszone.Definition{}, false, false
		}
		definition.Groups = append(definition.Groups, group)
	}
	return definition, adoptNames, true
}

func (handler *ManagementHandler) handleDNSZones(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path dnsZonePath, session accountsession.Session) string {
	fail := func(failure managementError) string {
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	if nilContinuationDependency(handler.dnsZones) {
		return fail(managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "DNS zones are temporarily unavailable", Retryable: true})
	}
	response.Header().Set("Cache-Control", "no-store")
	switch path.operation {
	case dnsZoneListOperation, dnsZoneReadOperation:
		return handler.readDNSZones(ctx, response, correlationID, path, session, fail)
	case dnsNameListOperation, dnsNameReadOperation, dnsNameCreateOperation, dnsNameUpdateOperation,
		dnsNameDeleteOperation, dnsNameApplyOperation:
		return handler.handleDNSNames(ctx, response, request, correlationID, path, session, fail)
	case dnsZoneCreateOperation:
		definition, adoptNames, valid := parseDNSZoneDefinition(response, request, true)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		if limited := handler.limitDNSZoneWrite(ctx, response, path, session); limited != nil {
			return fail(*limited)
		}
		result, err := handler.dnsZones.Create(ctx, session, path.scope, definition, adoptNames, correlationID)
		return handler.writeDNSZoneResult(ctx, response, correlationID, http.StatusCreated, result, false, err, fail)
	}
	expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		return fail(*precondition)
	}
	var result dnszone.Result
	var err error
	switch path.operation {
	case dnsZoneUpdateOperation:
		definition, _, valid := parseDNSZoneDefinition(response, request, false)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		if limited := handler.limitDNSZoneWrite(ctx, response, path, session); limited != nil {
			return fail(*limited)
		}
		result, err = handler.dnsZones.Update(ctx, session, path.scope, path.zoneID, expectedVersion, definition,
			correlationID)
	case dnsZoneDeleteOperation:
		if limited := handler.limitDNSZoneWrite(ctx, response, path, session); limited != nil {
			return fail(*limited)
		}
		result, err = handler.dnsZones.Delete(ctx, session, path.scope, path.zoneID, expectedVersion, path.withNames,
			correlationID)
		return handler.writeDNSZoneResult(ctx, response, correlationID, http.StatusOK, result, true, err, fail)
	default:
		return fail(*invalidManagementRequest())
	}
	return handler.writeDNSZoneResult(ctx, response, correlationID, http.StatusOK, result, false, err, fail)
}

// Zone changes one person may make to one Network (DNS design D1 §3.6):
// each rebuilds the DNS of every map of the Network, so a burst of edits
// must not resend it to every Device without end. The budget is the
// person's own, so someone who may not change zones cannot spend an
// administrator's.
const (
	dnsZoneWriteBurst  = 10
	dnsZoneWriteRefill = 6 * time.Second
)

// limitDNSZoneWrite takes one zone change from the person's budget for the
// Network, before the change reaches the store.
func (handler *ManagementHandler) limitDNSZoneWrite(ctx context.Context, response http.ResponseWriter,
	path dnsZonePath, session accountsession.Session) *managementError {
	policy, err := ratelimit.NewPolicy(dnsZoneWriteBurst, dnsZoneWriteRefill)
	if err != nil {
		return &managementError{Status: http.StatusInternalServerError, Code: "internal_failure",
			Message: "the request could not be completed"}
	}
	return handler.enforceRateLimit(ctx, response, ratelimit.SubjectNetworkChange,
		"dns_zone:"+path.scope.NetworkID().String()+":"+session.PrincipalID().String(), policy)
}

func (handler *ManagementHandler) readDNSZones(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path dnsZonePath, session accountsession.Session,
	fail func(managementError) string) string {
	if path.operation == dnsZoneReadOperation {
		reading, err := handler.dnsZones.Read(ctx, session, path.scope, path.zoneID)
		if err != nil {
			return fail(classifyDNSZoneError(err))
		}
		var output struct {
			Data struct {
				Zone      dnsZoneBody `json:"dns_zone"`
				CanManage bool        `json:"can_manage"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}
		output.Data.Zone, output.Data.CanManage = newDNSZoneBody(reading.Zone), reading.CanManage
		output.CorrelationID = correlationID.String()
		response.Header().Set("ETag", strongVersionETag(reading.Zone.Version))
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
		return "success"
	}
	listing, err := handler.dnsZones.List(ctx, session, path.scope, path.after, path.limit)
	if err != nil {
		return fail(classifyDNSZoneError(err))
	}
	bodies := make([]dnsZoneBody, 0, len(listing.Zones))
	for _, stored := range listing.Zones {
		bodies = append(bodies, newDNSZoneBody(stored))
	}
	var output struct {
		Data struct {
			Zones       []dnsZoneBody `json:"dns_zones"`
			Next        string        `json:"next_after,omitempty"`
			SystemZones struct {
				Network string `json:"network"`
				Shared  string `json:"shared"`
			} `json:"system_zones"`
			CanManage bool `json:"can_manage"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Zones, output.Data.CanManage = bodies, listing.CanManage
	output.Data.SystemZones.Network, output.Data.SystemZones.Shared = listing.System.Network, listing.System.Shared
	if listing.HasMore && len(listing.Zones) > 0 {
		output.Data.Next = listing.Zones[len(listing.Zones)-1].ID.String()
	}
	output.CorrelationID = correlationID.String()
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

func (handler *ManagementHandler) writeDNSZoneResult(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, status int, result dnszone.Result, deleted bool, err error,
	fail func(managementError) string) string {
	if err != nil {
		return fail(classifyDNSZoneError(err))
	}
	var output struct {
		Data struct {
			Zone    dnsZoneBody `json:"dns_zone"`
			Deleted bool        `json:"deleted"`
			// Names a new zone took from shorter zones, or a deleted zone
			// deleted with it.
			Names int `json:"names"`
			// AppliesWithinSeconds: maps carry the change at the latest
			// then; absent when nothing changed.
			AppliesWithinSeconds int `json:"applies_within_seconds,omitempty"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Zone, output.Data.Deleted, output.Data.Names, output.CorrelationID = newDNSZoneBody(result.Zone),
		deleted, result.Names, correlationID.String()
	output.Data.AppliesWithinSeconds = int(result.AppliesWithin / time.Second)
	response.Header().Set("ETag", strongVersionETag(result.Zone.Version))
	writeManagementJSON(ctx, handler.logger, response, status, output)
	return "success"
}

func classifyDNSZoneError(err error) managementError {
	conflict := func(code, message string) managementError {
		return managementError{Status: http.StatusConflict, Code: code, Message: message}
	}
	unprocessable := func(code, message string) managementError {
		return managementError{Status: http.StatusUnprocessableEntity, Code: code, Message: message}
	}
	switch {
	case errors.Is(err, dnszone.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "forbidden",
			Message: "You cannot view or change DNS zones in this Network"}
	case errors.Is(err, dnszone.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "dns_zone_not_found",
			Message: "The DNS zone no longer exists"}
	case errors.Is(err, dnszone.ErrVersionConflict):
		return managementError{Status: http.StatusPreconditionFailed, Code: "version_conflict",
			Message: "The DNS zone changed. Reload and review it again."}
	case errors.Is(err, dnszone.ErrDisabled):
		return conflict("dns_zones_disabled", "This deployment does not offer DNS zones yet")
	case errors.Is(err, dnszone.ErrRootUnavailable):
		return conflict("dns_root_zone_unavailable", "This deployment does not offer a zone for every other name yet")
	case errors.Is(err, dnszone.ErrDomainTaken):
		return conflict("dns_zone_exists", "This Network already has a DNS zone for that domain")
	case errors.Is(err, dnszone.ErrZoneLimit):
		return conflict("dns_zone_limit", "This Network already has the most DNS zones its plan allows")
	case errors.Is(err, dnszone.ErrSearchLimit):
		return conflict("dns_search_limit", "This Network already has the most search domains it can have")
	case errors.Is(err, dnszone.ErrPublicUnconfirmed):
		return conflict("dns_zone_public_unconfirmed",
			"The domain exists on the Internet. Confirm that Devices should ask your resolvers for its names.")
	case errors.Is(err, dnszone.ErrDomainCoversControl):
		return conflict("dns_zone_covers_control", "The domain holds names MeshTransit itself must reach")
	case errors.Is(err, dnszone.ErrResolverNotEligible):
		return conflict("dns_resolver_not_eligible",
			"A resolver Device must be an active Device owned by the Workspace in this Network and no exit node")
	case errors.Is(err, dnszone.ErrResolverPeerLimit):
		return conflict("dns_resolver_peer_limit",
			"A resolver Device would serve more Devices than it can. Send the zone to fewer Devices.")
	case errors.Is(err, dnszone.ErrGroupNotFound):
		return managementError{Status: http.StatusNotFound, Code: "device_group_not_found",
			Message: "A Device Group no longer exists in this Network"}
	case errors.Is(err, dnszone.ErrNXDomainPublic):
		return conflict("dns_zone_other_names_public",
			"A domain on the Internet cannot answer that its other names do not exist")
	case errors.Is(err, dnszone.ErrZoneHoldsNames):
		return conflict("dns_zone_holds_names",
			"The zone holds names, or would take names another zone holds. Say what happens to them.")
	case errors.Is(err, dnszone.ErrNameNotFound):
		return managementError{Status: http.StatusNotFound, Code: "dns_name_not_found",
			Message: "The DNS name no longer exists"}
	case errors.Is(err, dnszone.ErrNameTaken):
		return conflict("dns_name_conflict", "This Network already has that name")
	case errors.Is(err, dnszone.ErrNameInOtherZone):
		return conflict("dns_name_in_other_zone", "A longer zone of this Network holds that name")
	case errors.Is(err, dnszone.ErrNameLimit):
		return conflict("dns_name_limit", "The zone or the Network already has the most names it can have")
	case errors.Is(err, dnszone.ErrNameTargetInvalid):
		return unprocessable("dns_name_target_invalid",
			"A name points at an active Device of this Network, addresses outside the mesh and special ranges, "+
				"or a name outside the mesh names")
	case errors.Is(err, dnszone.ErrCNAMEAtApex):
		return unprocessable("dns_cname_at_apex", "The zone's own domain cannot be a CNAME")
	case errors.Is(err, dnszone.ErrCNAMELoop):
		return unprocessable("dns_cname_loop", "CNAMEs between this Network's names loop or chain more than 8 times")
	case errors.Is(err, dnszone.ErrDomainSpecialUse):
		return unprocessable("dns_zone_special_use", "The domain is a special-use name no DNS zone can be")
	case errors.Is(err, dnszone.ErrDomainPublicSuffix):
		return unprocessable("dns_zone_public_suffix",
			"The domain is a public suffix such as com or co.uk. Use the zone for every other name instead.")
	case errors.Is(err, dnszone.ErrDomainMeshSuffix):
		return unprocessable("dns_zone_mesh_suffix", "The domain overlaps the names MeshTransit gives Devices")
	case errors.Is(err, dnszone.ErrResolverNotInternet):
		return unprocessable("dns_resolver_not_internet",
			"A resolver address is not on the Internet. Use a Device of the Network for a private resolver.")
	case errors.Is(err, dnszone.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload DNS zones before trying again.", Retryable: true}
	}
}
