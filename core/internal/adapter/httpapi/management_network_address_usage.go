package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/addressusage"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const networkAddressUsageReadOperation = "network_address_usage_read"

// NetworkAddressUsage reads how full a Network's address ranges are.
type NetworkAddressUsage interface {
	Read(context.Context, accountsession.Session, network.Scope) (addressusage.State, error)
}

// parseNetworkAddressUsagePath matches the exact, query-free
// GET /api/v1/workspaces/{ws}/networks/{net}/address-usage.
func parseNetworkAddressUsagePath(request *http.Request) (network.Scope, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" {
		return network.Scope{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) != 7 || segments[0] != "api" || segments[1] != "v1" || segments[2] != "workspaces" ||
		segments[4] != "networks" || segments[6] != "address-usage" {
		return network.Scope{}, false
	}
	workspaceID, workspaceErr := workspace.ParseID(segments[3])
	networkID, networkErr := network.ParseID(segments[5])
	scope, scopeErr := network.NewScope(workspaceID, networkID)
	if workspaceErr != nil || networkErr != nil || scopeErr != nil ||
		workspaceID.String() != segments[3] || networkID.String() != segments[5] {
		return network.Scope{}, false
	}
	return scope, true
}

// isNetworkAddressUsageRead admits only GET on the exact path.
func isNetworkAddressUsageRead(request *http.Request) bool {
	_, ok := parseNetworkAddressUsagePath(request)
	return ok && request.Method == http.MethodGet
}

type networkAddressUsageRange struct {
	Family int    `json:"family"`
	Prefix string `json:"prefix"`
	// Capacity is null for a range that cannot run out (IPv6 /95 or wider).
	Capacity            *int64     `json:"capacity"`
	InUse               int64      `json:"in_use"`
	HeldByExpired       int64      `json:"held_by_expired"`
	HeldAfterRevocation int64      `json:"held_after_revocation"`
	NextRelease         *time.Time `json:"next_release"`
}

type networkAddressUsageResponse struct {
	Data struct {
		NetworkID string                     `json:"network_id"`
		Ranges    []networkAddressUsageRange `json:"ranges"`
	} `json:"data"`
	CorrelationID string `json:"correlation_id"`
}

func (handler *ManagementHandler) readNetworkAddressUsage(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, scope network.Scope, session accountsession.Session) string {
	if nilContinuationDependency(handler.addressUsage) {
		failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Address usage is temporarily unavailable", Retryable: true}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	state, err := handler.addressUsage.Read(ctx, session, scope)
	if err != nil {
		failure := classifyNetworkAddressUsageError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	var output networkAddressUsageResponse
	output.Data.NetworkID = scope.NetworkID().String()
	output.Data.Ranges = make([]networkAddressUsageRange, 0, len(state.Ranges))
	for _, usage := range state.Ranges {
		item := networkAddressUsageRange{Family: 6, Prefix: usage.Prefix.String(), InUse: usage.InUse,
			HeldByExpired: usage.HeldByExpired, HeldAfterRevocation: usage.HeldAfterRevocation}
		if usage.Prefix.Addr().Is4() {
			item.Family = 4
		}
		if usage.Capacity > 0 {
			capacity := usage.Capacity
			item.Capacity = &capacity
		}
		if !usage.NextRelease.IsZero() {
			release := usage.NextRelease.UTC()
			item.NextRelease = &release
		}
		output.Data.Ranges = append(output.Data.Ranges, item)
	}
	output.CorrelationID = correlationID.String()
	response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

func classifyNetworkAddressUsageError(err error) managementError {
	switch {
	case errors.Is(err, addressusage.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot view the addresses of this Network"}
	case errors.Is(err, addressusage.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Address usage could not be read. Try again.", Retryable: true}
	}
}
