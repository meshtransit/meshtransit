package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/network/aliasrange"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

const (
	networkAliasRangeReadOperation   = "network_alias_range_read"
	networkAliasRangeUpdateOperation = "network_alias_range_update"
	maximumAliasRangeBodyBytes       = 1024
)

// NetworkAliasRanges reads and updates the alias ranges a receiving Network
// chose for Devices shared into it.
type NetworkAliasRanges interface {
	Read(context.Context, accountsession.Session, network.Scope) (aliasrange.State, error)
	Update(context.Context, aliasrange.Command) (aliasrange.Result, error)
}

type networkAliasRangePath struct {
	scope  network.Scope
	update bool
}

// parseNetworkAliasRangePath matches
// GET /api/v1/workspaces/{ws}/networks/{net}/alias-ranges and
// POST /api/v1/workspaces/{ws}/networks/{net}/alias-ranges/actions/update.
func parseNetworkAliasRangePath(request *http.Request) (networkAliasRangePath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		return networkAliasRangePath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	update := len(segments) == 9 && segments[7] == "actions" && segments[8] == "update"
	if (len(segments) != 7 && !update) || segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "workspaces" || segments[4] != "networks" || segments[6] != "alias-ranges" {
		return networkAliasRangePath{}, false
	}
	workspaceID, workspaceErr := workspace.ParseID(segments[3])
	networkID, networkErr := network.ParseID(segments[5])
	scope, scopeErr := network.NewScope(workspaceID, networkID)
	if workspaceErr != nil || networkErr != nil || scopeErr != nil ||
		workspaceID.String() != segments[3] || networkID.String() != segments[5] {
		return networkAliasRangePath{}, false
	}
	return networkAliasRangePath{scope: scope, update: update}, true
}

// isNetworkAliasRangeOperation admits only the method each path allows.
func isNetworkAliasRangeOperation(request *http.Request) bool {
	path, ok := parseNetworkAliasRangePath(request)
	return ok && request.Method == path.allowedMethod()
}

// isNetworkAliasRangeRead admits the exact, query-free read.
func isNetworkAliasRangeRead(request *http.Request) bool {
	path, ok := parseNetworkAliasRangePath(request)
	return ok && !path.update && request.Method == http.MethodGet
}

func (path networkAliasRangePath) operation() string {
	if path.update {
		return networkAliasRangeUpdateOperation
	}
	return networkAliasRangeReadOperation
}

func (path networkAliasRangePath) allowedMethod() string {
	if path.update {
		return http.MethodPost
	}
	return http.MethodGet
}

type networkAliasRangeFamily struct {
	// Frame is the Deployment's Resource Alias frame; null when none is active.
	Frame *string `json:"frame"`
	// Prefix is the chosen range; null means the whole frame.
	Prefix   *string `json:"prefix"`
	Retained int64   `json:"retained_aliases"`
}

type networkAliasRangeResponse struct {
	Data struct {
		NetworkID  string                  `json:"network_id"`
		Version    int64                   `json:"version"`
		IPv4       networkAliasRangeFamily `json:"ipv4"`
		IPv6       networkAliasRangeFamily `json:"ipv6"`
		LiveShares int64                   `json:"live_shares"`
		ShareLimit int64                   `json:"share_limit"`
		Changed    *bool                   `json:"changed,omitempty"`
	} `json:"data"`
	CorrelationID string `json:"correlation_id"`
}

func optionalPrefixText(prefix netip.Prefix) *string {
	if prefix == (netip.Prefix{}) {
		return nil
	}
	text := prefix.String()
	return &text
}

func newNetworkAliasRangeFamily(family aliasrange.Family) networkAliasRangeFamily {
	return networkAliasRangeFamily{Frame: optionalPrefixText(family.Frame), Prefix: optionalPrefixText(family.Prefix),
		Retained: family.Retained}
}

func (handler *ManagementHandler) handleNetworkAliasRanges(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path networkAliasRangePath, session accountsession.Session) string {
	if nilContinuationDependency(handler.aliasRanges) {
		failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Shared Device addresses are temporarily unavailable", Retryable: true}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	if !path.update {
		state, err := handler.aliasRanges.Read(ctx, session, path.scope)
		if err != nil {
			failure := classifyNetworkAliasRangeError(err)
			writeManagementError(ctx, handler.logger, response, correlationID, failure)
			return failure.Code
		}
		writeNetworkAliasRangeState(ctx, handler, response, correlationID, path.scope, state, nil)
		return "success"
	}
	expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *precondition)
		return precondition.Code
	}
	ipv4, ipv6, valid := parseNetworkAliasRangeBody(response, request)
	command := aliasrange.Command{Session: session, Scope: path.scope, ExpectedVersion: expectedVersion,
		IPv4: ipv4, IPv6: ipv6, CorrelationID: correlationID}
	if !valid || !command.IsValid() {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	result, err := handler.aliasRanges.Update(ctx, command)
	if err != nil {
		failure := classifyNetworkAliasRangeError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	changed := result.Changed
	writeNetworkAliasRangeState(ctx, handler, response, correlationID, path.scope, result.State, &changed)
	return "success"
}

func writeNetworkAliasRangeState(ctx context.Context, handler *ManagementHandler, response http.ResponseWriter,
	correlationID publicid.ID, scope network.Scope, state aliasrange.State, changed *bool) {
	var output networkAliasRangeResponse
	output.Data.NetworkID = scope.NetworkID().String()
	output.Data.Version = state.Version
	output.Data.IPv4 = newNetworkAliasRangeFamily(state.IPv4)
	output.Data.IPv6 = newNetworkAliasRangeFamily(state.IPv6)
	output.Data.LiveShares = state.LiveShares
	output.Data.ShareLimit = state.ShareLimit
	output.Data.Changed = changed
	output.CorrelationID = correlationID.String()
	response.Header().Set("ETag", strongVersionETag(state.Version))
	response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
}

// parseNetworkAliasRangeBody accepts ipv4_prefix and ipv6_prefix. An omitted
// key leaves the family unchanged; null returns it to the whole frame.
func parseNetworkAliasRangeBody(response http.ResponseWriter, request *http.Request) (ipv4, ipv6 aliasrange.Change, valid bool) {
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return aliasrange.Change{}, aliasrange.Change{}, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maximumAliasRangeBodyBytes))
	if err != nil {
		return aliasrange.Change{}, aliasrange.Change{}, false
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&fields); err != nil || fields == nil || ensureJSONEnd(decoder) != nil {
		return aliasrange.Change{}, aliasrange.Change{}, false
	}
	for key := range fields {
		if key != "ipv4_prefix" && key != "ipv6_prefix" {
			return aliasrange.Change{}, aliasrange.Change{}, false
		}
	}
	ipv4, ok4 := parseAliasRangeField(fields, "ipv4_prefix")
	ipv6, ok6 := parseAliasRangeField(fields, "ipv6_prefix")
	return ipv4, ipv6, ok4 && ok6
}

func parseAliasRangeField(fields map[string]json.RawMessage, key string) (aliasrange.Change, bool) {
	value, present := fields[key]
	if !present {
		return aliasrange.Change{}, true
	}
	if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return aliasrange.Change{Present: true}, true
	}
	var text string
	if err := json.Unmarshal(value, &text); err != nil {
		return aliasrange.Change{}, false
	}
	prefix, err := netip.ParsePrefix(text)
	if err != nil || prefix.String() != text || prefix != prefix.Masked() {
		return aliasrange.Change{}, false
	}
	return aliasrange.Change{Present: true, Prefix: prefix}, true
}

func classifyNetworkAliasRangeError(err error) managementError {
	switch {
	case errors.Is(err, aliasrange.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot view or change shared Device addresses in this Network"}
	case errors.Is(err, aliasrange.ErrOutsideFrame):
		return managementError{Status: http.StatusUnprocessableEntity, Code: "alias_range_outside_frame",
			Message: "Choose a range inside the shared Device address frame"}
	case errors.Is(err, aliasrange.ErrInUse):
		return managementError{Status: http.StatusConflict, Code: "alias_range_in_use",
			Message: "A shared Device still uses an address outside this range. Keep those addresses inside the range."}
	case errors.Is(err, aliasrange.ErrVersionConflict):
		return managementError{Status: http.StatusPreconditionFailed, Code: "version_conflict",
			Message: "Shared Device addresses changed. Reload and review them again."}
	case errors.Is(err, aliasrange.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload shared Device addresses before trying again."}
	}
}
