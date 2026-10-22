package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"

	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// dnsNameBody is one name of a zone (DNS design D2 §6): source is admin for
// the names set here; the names MeshTransit gives Devices and shares come
// with the system zones.
type dnsNameBody struct {
	NameID string `json:"dns_name_id"`
	ZoneID string `json:"dns_zone_id"`
	// Name is the full name; Label is relative to the zone (@ for the
	// zone's own domain).
	Name     string `json:"name"`
	Label    string `json:"label"`
	Kind     string `json:"kind"`
	Source   string `json:"source"`
	Editable bool   `json:"editable"`
	// A Device target, with its name and state (removed once it is gone);
	// fixed addresses; or a CNAME.
	DeviceID    string   `json:"device_id,omitempty"`
	DeviceName  string   `json:"device_name,omitempty"`
	DeviceState string   `json:"device_state,omitempty"`
	Addresses   []string `json:"addresses,omitempty"`
	CNAME       string   `json:"cname,omitempty"`
	Version     int64    `json:"version"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

func newDNSNameBody(stored dnszone.Name, editable bool) dnsNameBody {
	body := dnsNameBody{
		NameID: stored.ID.String(), ZoneID: stored.ZoneID.String(), Name: stored.FQDN, Label: stored.Label,
		Kind: string(stored.Kind), Source: "admin", Editable: editable, CNAME: stored.Target.CNAME,
		Version: stored.Version, CreatedAt: managementTime(stored.CreatedAt), UpdatedAt: managementTime(stored.UpdatedAt),
	}
	if stored.Target.DeviceID.IsValid() {
		body.DeviceID = stored.Target.DeviceID.String()
		if stored.Device != nil {
			body.DeviceName, body.DeviceState = stored.Device.Name, stored.Device.State
		}
	}
	for _, address := range stored.Target.Addresses {
		body.Addresses = append(body.Addresses, address.String())
	}
	return body
}

// dnsNameTargetBody is the kind and target a create, update or apply sends:
// device_id, addresses or cname. IDs and addresses must be canonical text.
type dnsNameTargetBody struct {
	Kind      *string   `json:"kind"`
	DeviceID  *string   `json:"device_id"`
	Addresses *[]string `json:"addresses"`
	CNAME     *string   `json:"cname"`
}

func (body dnsNameTargetBody) definition() (dnszone.NameDefinition, bool) {
	if body.Kind == nil {
		return dnszone.NameDefinition{}, false
	}
	definition := dnszone.NameDefinition{Kind: dnszone.NameKind(*body.Kind)}
	if body.DeviceID != nil {
		device, err := node.ParseID(*body.DeviceID)
		if err != nil || device.String() != *body.DeviceID {
			return dnszone.NameDefinition{}, false
		}
		definition.Target.DeviceID = device
	}
	if body.Addresses != nil {
		if len(*body.Addresses) == 0 || len(*body.Addresses) > dnszone.MaximumAddressesPerName {
			return dnszone.NameDefinition{}, false
		}
		for _, text := range *body.Addresses {
			address, err := netip.ParseAddr(text)
			if err != nil || address.String() != text {
				return dnszone.NameDefinition{}, false
			}
			definition.Target.Addresses = append(definition.Target.Addresses, address)
		}
	}
	if body.CNAME != nil {
		if *body.CNAME == "" {
			return dnszone.NameDefinition{}, false
		}
		definition.Target.CNAME = *body.CNAME
	}
	return definition, true
}

// parseDNSNameDefinition reads a whole name: the label to create, the kind
// and target always. PATCH replaces the kind and target; a name never
// moves, so an update sends no label.
func parseDNSNameDefinition(response http.ResponseWriter, request *http.Request,
	create bool) (dnszone.NameDefinition, bool) {
	var body struct {
		Label *string `json:"label"`
		dnsNameTargetBody
	}
	if !readSiteBody(response, request, &body) || (body.Label != nil) != create {
		return dnszone.NameDefinition{}, false
	}
	definition, valid := body.definition()
	if !valid {
		return dnszone.NameDefinition{}, false
	}
	if body.Label != nil {
		definition.Label = *body.Label
	}
	return definition, true
}

// parseDNSNameOperations reads an apply: 1 to 100 operations, a create by
// label, an update or delete by name ID and version.
func parseDNSNameOperations(response http.ResponseWriter, request *http.Request) ([]dnszone.NameOperation, bool) {
	var body struct {
		Operations *[]struct {
			Operation *string `json:"op"`
			NameID    *string `json:"dns_name_id"`
			Version   *int64  `json:"version"`
			Label     *string `json:"label"`
			dnsNameTargetBody
		} `json:"operations"`
	}
	if !readSiteBody(response, request, &body) || body.Operations == nil || len(*body.Operations) == 0 ||
		len(*body.Operations) > dnszone.MaximumNameOperations {
		return nil, false
	}
	operations := make([]dnszone.NameOperation, 0, len(*body.Operations))
	for _, item := range *body.Operations {
		if item.Operation == nil {
			return nil, false
		}
		operation := dnszone.NameOperation{Operation: dnszone.Operation(*item.Operation)}
		if operation.Operation == dnszone.OperationCreate {
			if item.NameID != nil || item.Version != nil || item.Label == nil {
				return nil, false
			}
		} else {
			if item.NameID == nil || item.Version == nil || item.Label != nil {
				return nil, false
			}
			id, err := dnszone.ParseNameID(*item.NameID)
			if err != nil || id.String() != *item.NameID {
				return nil, false
			}
			operation.NameID, operation.ExpectedVersion = id, *item.Version
		}
		if operation.Operation != dnszone.OperationDelete {
			definition, valid := item.definition()
			if !valid {
				return nil, false
			}
			operation.Definition = definition
		} else if item.Kind != nil || item.DeviceID != nil || item.Addresses != nil || item.CNAME != nil {
			return nil, false
		}
		if item.Label != nil {
			operation.Definition.Label = *item.Label
		}
		operations = append(operations, operation)
	}
	return operations, true
}

func (handler *ManagementHandler) handleDNSNames(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path dnsZonePath, session accountsession.Session,
	fail func(managementError) string) string {
	switch path.operation {
	case dnsNameListOperation:
		listing, err := handler.dnsZones.ListNames(ctx, session, path.scope, path.zoneID, path.afterName,
			path.prefix, path.limit)
		if err != nil {
			return fail(classifyDNSNameError(err))
		}
		bodies := make([]dnsNameBody, 0, len(listing.Names))
		for _, stored := range listing.Names {
			bodies = append(bodies, newDNSNameBody(stored, listing.CanManage))
		}
		var output struct {
			Data struct {
				Zone      dnsZoneBody   `json:"dns_zone"`
				Names     []dnsNameBody `json:"dns_names"`
				Next      string        `json:"next_after,omitempty"`
				CanManage bool          `json:"can_manage"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}
		output.Data.Zone, output.Data.Names, output.Data.CanManage = newDNSZoneBody(listing.Zone), bodies,
			listing.CanManage
		if listing.HasMore && len(listing.Names) > 0 {
			output.Data.Next = listing.Names[len(listing.Names)-1].ID.String()
		}
		output.CorrelationID = correlationID.String()
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
		return "success"
	case dnsNameReadOperation:
		reading, err := handler.dnsZones.ReadName(ctx, session, path.scope, path.zoneID, path.nameID)
		if err != nil {
			return fail(classifyDNSNameError(err))
		}
		var output struct {
			Data struct {
				Name      dnsNameBody `json:"dns_name"`
				CanManage bool        `json:"can_manage"`
			} `json:"data"`
			CorrelationID string `json:"correlation_id"`
		}
		output.Data.Name, output.Data.CanManage = newDNSNameBody(reading.Name, reading.CanManage), reading.CanManage
		output.CorrelationID = correlationID.String()
		response.Header().Set("ETag", strongVersionETag(reading.Name.Version))
		writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
		return "success"
	case dnsNameApplyOperation:
		operations, valid := parseDNSNameOperations(response, request)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		if limited := handler.limitDNSZoneWrite(ctx, response, path, session); limited != nil {
			return fail(*limited)
		}
		result, err := handler.dnsZones.ApplyNames(ctx, session, path.scope, path.zoneID, operations, correlationID)
		if err != nil {
			return fail(classifyDNSNameError(err))
		}
		return handler.writeDNSNameResults(ctx, response, correlationID, result)
	case dnsNameCreateOperation:
		definition, valid := parseDNSNameDefinition(response, request, true)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		if limited := handler.limitDNSZoneWrite(ctx, response, path, session); limited != nil {
			return fail(*limited)
		}
		outcome, err := handler.dnsZones.CreateName(ctx, session, path.scope, path.zoneID, definition, correlationID)
		return handler.writeDNSNameOutcome(ctx, response, correlationID, http.StatusCreated, outcome, err, fail)
	}
	expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		return fail(*precondition)
	}
	var outcome dnszone.NameOutcome
	var err error
	switch path.operation {
	case dnsNameUpdateOperation:
		definition, valid := parseDNSNameDefinition(response, request, false)
		if !valid {
			return fail(*invalidManagementRequest())
		}
		if limited := handler.limitDNSZoneWrite(ctx, response, path, session); limited != nil {
			return fail(*limited)
		}
		outcome, err = handler.dnsZones.UpdateName(ctx, session, path.scope, path.zoneID, path.nameID,
			expectedVersion, definition, correlationID)
	case dnsNameDeleteOperation:
		if limited := handler.limitDNSZoneWrite(ctx, response, path, session); limited != nil {
			return fail(*limited)
		}
		outcome, err = handler.dnsZones.DeleteName(ctx, session, path.scope, path.zoneID, path.nameID,
			expectedVersion, correlationID)
	default:
		return fail(*invalidManagementRequest())
	}
	return handler.writeDNSNameOutcome(ctx, response, correlationID, http.StatusOK, outcome, err, fail)
}

func (handler *ManagementHandler) writeDNSNameOutcome(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, status int, outcome dnszone.NameOutcome, err error,
	fail func(managementError) string) string {
	if err != nil {
		return fail(classifyDNSNameError(err))
	}
	var output struct {
		Data struct {
			Name    dnsNameBody `json:"dns_name"`
			Deleted bool        `json:"deleted"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Name, output.Data.Deleted = newDNSNameBody(outcome.Name, !outcome.Name.Deleted), outcome.Name.Deleted
	output.CorrelationID = correlationID.String()
	response.Header().Set("ETag", strongVersionETag(outcome.Name.Version))
	writeManagementJSON(ctx, handler.logger, response, status, output)
	return "success"
}

// writeDNSNameResults answers an apply with each operation's name in
// request order.
func (handler *ManagementHandler) writeDNSNameResults(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, result dnszone.NameResult) string {
	type outcomeBody struct {
		Operation string      `json:"op"`
		Name      dnsNameBody `json:"dns_name"`
		Changed   bool        `json:"changed"`
		Deleted   bool        `json:"deleted"`
	}
	var output struct {
		Data struct {
			Results []outcomeBody `json:"results"`
			Changed bool          `json:"changed"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Results = make([]outcomeBody, 0, len(result.Outcomes))
	for _, outcome := range result.Outcomes {
		output.Data.Results = append(output.Data.Results, outcomeBody{Operation: string(outcome.Operation),
			Name: newDNSNameBody(outcome.Name, !outcome.Name.Deleted), Changed: outcome.Changed,
			Deleted: outcome.Name.Deleted})
	}
	output.Data.Changed, output.CorrelationID = result.Changed, correlationID.String()
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

// classifyDNSNameError classifies like a zone error and names the failing
// operation of an apply.
func classifyDNSNameError(err error) managementError {
	classified := classifyDNSZoneError(err)
	if errors.Is(err, dnszone.ErrVersionConflict) {
		classified.Message = "The DNS name changed. Reload and review it again."
	}
	var failure *dnszone.OperationError
	if errors.As(err, &failure) {
		index := failure.Index
		classified.OperationIndex = &index
	}
	return classified
}
