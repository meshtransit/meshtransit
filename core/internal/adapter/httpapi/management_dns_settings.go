package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/publicid"
)

// The Network's DNS settings (DNS design D5b): GET reads them, PUT replaces
// the unmanaged Device Groups at the version If-Match names ("0" before the
// first change).

type dnsSettingsBody struct {
	// UnmanagedGroups are the Device Groups whose Devices get no DNS from
	// MeshTransit.
	UnmanagedGroups []dnsZoneGroupBody `json:"unmanaged_device_groups"`
	Version         int64              `json:"version"`
}

func newDNSSettingsBody(settings dnszone.Settings) dnsSettingsBody {
	body := dnsSettingsBody{Version: settings.Version,
		UnmanagedGroups: make([]dnsZoneGroupBody, 0, len(settings.UnmanagedGroups))}
	for _, group := range settings.UnmanagedGroups {
		body.UnmanagedGroups = append(body.UnmanagedGroups, dnsZoneGroupBody{GroupID: group.ID.String(),
			Name: group.Name, State: group.State})
	}
	return body
}

// isDNSSettingsWrite admits a PUT of the Network's DNS settings.
func isDNSSettingsWrite(request *http.Request) bool {
	path, ok := parseDNSZonePath(request)
	return ok && request.Method == http.MethodPut && path.operation == dnsSettingsUpdateOperation
}

// parseSettingsIfMatch reads a strong version precondition that may be 0.
func parseSettingsIfMatch(values []string) (int64, *managementError) {
	if len(values) == 1 && values[0] == strongVersionETag(0) {
		return 0, nil
	}
	return parseIfMatch(values)
}

func (handler *ManagementHandler) handleDNSSettings(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path dnsZonePath, session accountsession.Session,
	fail func(managementError) string,
) string {
	var settings dnszone.Settings
	changed := false
	if path.operation == dnsSettingsReadOperation {
		read, err := handler.dnsZones.ReadSettings(ctx, session, path.scope)
		if err != nil {
			return fail(classifyDNSZoneError(err))
		}
		settings = read
	} else {
		expected, precondition := parseSettingsIfMatch(request.Header.Values("If-Match"))
		if precondition != nil {
			return fail(*precondition)
		}
		var body struct {
			UnmanagedGroups *[]string `json:"unmanaged_device_group_ids"`
		}
		if !decodeDNSSettingsBody(response, request, &body) || body.UnmanagedGroups == nil {
			return fail(*invalidManagementRequest())
		}
		groups := make([]devicegroup.ID, 0, len(*body.UnmanagedGroups))
		for _, text := range *body.UnmanagedGroups {
			group, err := devicegroup.ParseID(text)
			if err != nil || group.String() != text {
				return fail(*invalidManagementRequest())
			}
			groups = append(groups, group)
		}
		if limited := handler.limitDNSZoneWrite(ctx, response, path, session); limited != nil {
			return fail(*limited)
		}
		result, err := handler.dnsZones.ChangeSettings(ctx, session, path.scope, expected, groups, correlationID)
		if err != nil {
			return fail(classifyDNSZoneError(err))
		}
		settings, changed = result.Settings, result.Changed
	}
	var output struct {
		Data struct {
			Settings dnsSettingsBody `json:"dns_settings"`
			Changed  *bool           `json:"changed,omitempty"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	output.Data.Settings, output.CorrelationID = newDNSSettingsBody(settings), correlationID.String()
	if path.operation == dnsSettingsUpdateOperation {
		output.Data.Changed = &changed
	}
	response.Header().Set("ETag", `"`+strconv.FormatInt(settings.Version, 10)+`"`)
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

// decodeDNSSettingsBody reads one bounded JSON object without unknown fields.
func decodeDNSSettingsBody(response http.ResponseWriter, request *http.Request, into any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return false
	}
	return !decoder.More()
}
