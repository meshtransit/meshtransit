package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/devicelifetime"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	networkDeviceLifetimeReadOperation   = "network_device_lifetime_read"
	networkDeviceLifetimeUpdateOperation = "network_device_lifetime_update"
	maximumDeviceLifetimeBodyBytes       = 256
)

// NetworkDeviceLifetimes reads and sets how long Devices that sign in to a
// Network through the browser live.
type NetworkDeviceLifetimes interface {
	Read(context.Context, accountsession.Session, network.Scope) (devicelifetime.State, error)
	Update(context.Context, devicelifetime.Command) (devicelifetime.Result, error)
}

type networkDeviceLifetimePath struct {
	scope  network.Scope
	update bool
}

// deviceLifetimeMethods read the lifetime and change it.
var deviceLifetimeMethods = restMethods{http.MethodGet, http.MethodPatch}

// parseNetworkDeviceLifetimePath matches GET and PATCH
// /api/v1/workspaces/{ws}/networks/{net}/device-lifetime.
func parseNetworkDeviceLifetimePath(request *http.Request) (networkDeviceLifetimePath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		return networkDeviceLifetimePath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) != 7 || segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "workspaces" || segments[4] != "networks" || segments[6] != "device-lifetime" {
		return networkDeviceLifetimePath{}, false
	}
	workspaceID, workspaceErr := workspace.ParseID(segments[3])
	networkID, networkErr := network.ParseID(segments[5])
	scope, scopeErr := network.NewScope(workspaceID, networkID)
	if workspaceErr != nil || networkErr != nil || scopeErr != nil ||
		workspaceID.String() != segments[3] || networkID.String() != segments[5] {
		return networkDeviceLifetimePath{}, false
	}
	return networkDeviceLifetimePath{scope: scope, update: request.Method == http.MethodPatch}, true
}

// isNetworkDeviceLifetimeOperation admits only the methods the path allows.
func isNetworkDeviceLifetimeOperation(request *http.Request) bool {
	path, ok := parseNetworkDeviceLifetimePath(request)
	return ok && path.allowedMethod(request.Method) != ""
}

// isNetworkDeviceLifetimeRead admits the exact, query-free read.
func isNetworkDeviceLifetimeRead(request *http.Request) bool {
	path, ok := parseNetworkDeviceLifetimePath(request)
	return ok && !path.update && request.Method == http.MethodGet
}

func (path networkDeviceLifetimePath) operation() string {
	if path.update {
		return networkDeviceLifetimeUpdateOperation
	}
	return networkDeviceLifetimeReadOperation
}

func (networkDeviceLifetimePath) allowedMethod(method string) string {
	return deviceLifetimeMethods.allowedMethod(method)
}

type networkDeviceLifetimeResponse struct {
	Data struct {
		NetworkID string `json:"network_id"`
		Version   int64  `json:"version"`
		// DeviceLifetimeSeconds is null when signed-in Devices never expire.
		DeviceLifetimeSeconds *int64 `json:"device_lifetime_seconds"`
		NeverExpires          bool   `json:"never_expires"`
		// Default is true while the Network has chosen nothing.
		Default bool  `json:"default"`
		Changed *bool `json:"changed,omitempty"`
	} `json:"data"`
	CorrelationID string `json:"correlation_id"`
}

func (handler *ManagementHandler) handleNetworkDeviceLifetime(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path networkDeviceLifetimePath,
	session accountsession.Session) string {
	if nilContinuationDependency(handler.deviceLifetimes) {
		failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Device lifetime is temporarily unavailable", Retryable: true}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	if !path.update {
		state, err := handler.deviceLifetimes.Read(ctx, session, path.scope)
		if err != nil {
			failure := classifyNetworkDeviceLifetimeError(err)
			writeManagementError(ctx, handler.logger, response, correlationID, failure)
			return failure.Code
		}
		writeNetworkDeviceLifetime(ctx, handler, response, correlationID, path.scope, state, nil)
		return "success"
	}
	expectedVersion, precondition := parseIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *precondition)
		return precondition.Code
	}
	lifetime, never, valid := parseNetworkDeviceLifetimeBody(response, request)
	command := devicelifetime.Command{Session: session, Scope: path.scope, ExpectedVersion: expectedVersion,
		Lifetime: lifetime, NeverExpires: never, CorrelationID: correlationID}
	if !valid || !command.IsValid() {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	result, err := handler.deviceLifetimes.Update(ctx, command)
	if err != nil {
		failure := classifyNetworkDeviceLifetimeError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	changed := result.Changed
	writeNetworkDeviceLifetime(ctx, handler, response, correlationID, path.scope, result.State, &changed)
	return "success"
}

func writeNetworkDeviceLifetime(ctx context.Context, handler *ManagementHandler, response http.ResponseWriter,
	correlationID publicid.ID, scope network.Scope, state devicelifetime.State, changed *bool) {
	var output networkDeviceLifetimeResponse
	output.Data.NetworkID = scope.NetworkID().String()
	output.Data.Version = state.Version
	if !state.NeverExpires {
		seconds := int64(state.Lifetime / time.Second)
		output.Data.DeviceLifetimeSeconds = &seconds
	}
	output.Data.NeverExpires = state.NeverExpires
	output.Data.Default = state.Default
	output.Data.Changed = changed
	output.CorrelationID = correlationID.String()
	response.Header().Set("ETag", strongVersionETag(state.Version))
	response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
}

// parseNetworkDeviceLifetimeBody accepts exactly one of
// {"device_lifetime_seconds": N} and {"never_expires": true}.
func parseNetworkDeviceLifetimeBody(response http.ResponseWriter, request *http.Request) (time.Duration, bool, bool) {
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return 0, false, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maximumDeviceLifetimeBodyBytes))
	if err != nil {
		return 0, false, false
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&fields); err != nil || len(fields) != 1 || ensureJSONEnd(decoder) != nil {
		return 0, false, false
	}
	if value, ok := fields["never_expires"]; ok {
		return 0, true, bytes.Equal(bytes.TrimSpace(value), []byte("true"))
	}
	value, ok := fields["device_lifetime_seconds"]
	if !ok {
		return 0, false, false
	}
	// A plain positive integer: no sign, exponent, fraction or leading zero.
	digits := string(bytes.TrimSpace(value))
	if len(digits) == 0 || len(digits) > 12 || digits[0] < '1' || digits[0] > '9' {
		return 0, false, false
	}
	seconds, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, false, false
	}
	return time.Duration(seconds) * time.Second, false, true
}

func classifyNetworkDeviceLifetimeError(err error) managementError {
	switch {
	case errors.Is(err, devicelifetime.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot view or change the Device lifetime of this Network"}
	case errors.Is(err, devicelifetime.ErrNoInteractiveProfile):
		return managementError{Status: http.StatusConflict, Code: "sign_in_unavailable",
			Message: "Nobody can sign in to this Network, so it has no Device lifetime"}
	case errors.Is(err, devicelifetime.ErrVersionConflict):
		return managementError{Status: http.StatusPreconditionFailed, Code: "version_conflict",
			Message: "The Device lifetime changed. Reload it and try again."}
	case errors.Is(err, devicelifetime.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Reload the Device lifetime before trying again."}
	}
}
