package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/network/provisioning"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

// NetworkCreator creates Networks with non-overlapping Workspace prefixes.
type NetworkCreator interface {
	Create(context.Context, provisioning.Command) (provisioning.Result, error)
}

// parseNetworkCollectionPath matches POST /api/v1/workspaces/{workspace}/networks.
func parseNetworkCollectionPath(request *http.Request) (string, bool) {
	if request == nil || request.URL == nil || request.URL.RawQuery != "" || request.URL.RawPath != "" {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(parts) != 5 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "workspaces" || parts[3] == "" ||
		parts[4] != "networks" {
		return "", false
	}
	return parts[3], true
}

type networkCreationResponse struct {
	Data struct {
		ID          string    `json:"id"`
		DisplayName string    `json:"display_name"`
		DisplayCode string    `json:"display_code"`
		IPv4Prefix  string    `json:"ipv4_prefix"`
		IPv6Prefix  string    `json:"ipv6_prefix"`
		Version     int64     `json:"version"`
		CreatedAt   time.Time `json:"created_at"`
	} `json:"data"`
	CorrelationID string `json:"correlation_id"`
}

func (handler *ManagementHandler) createNetwork(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, workspacePath string, session accountsession.Session) string {
	if nilContinuationDependency(handler.networkCreations) {
		failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Network creation is temporarily unavailable"}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	var body struct {
		NetworkID   string `json:"network_id"`
		DisplayName string `json:"display_name"`
		IPv4Prefix  string `json:"ipv4_prefix"`
		IPv6Prefix  string `json:"ipv6_prefix"`
	}
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || ensureJSONEnd(decoder) != nil {
		writeManagementError(ctx, handler.logger, response, correlationID, *invalidManagementRequest())
		return "invalid_request"
	}
	workspaceID, workspaceErr := workspace.ParseID(workspacePath)
	networkID, networkErr := network.ParseID(body.NetworkID)
	ipv4, ipv4Err := netip.ParsePrefix(body.IPv4Prefix)
	ipv6, ipv6Err := netip.ParsePrefix(body.IPv6Prefix)
	command := provisioning.Command{Session: session, WorkspaceID: workspaceID, NetworkID: networkID,
		DisplayName: body.DisplayName, IPv4Prefix: ipv4, IPv6Prefix: ipv6, CorrelationID: correlationID}
	if errors.Join(workspaceErr, networkErr, ipv4Err, ipv6Err) != nil || !command.IsValid() {
		failure := *invalidManagementRequest()
		failure.Message = "Choose a name, an IPv4 prefix /16–/28 inside 100.64.0.0/10 and an IPv6 prefix /56–/112."
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	result, err := handler.networkCreations.Create(ctx, command)
	if err != nil {
		failure := classifyNetworkCreationError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	var output networkCreationResponse
	output.Data.ID = result.NetworkID.String()
	output.Data.DisplayName = command.DisplayName
	output.Data.DisplayCode = result.DisplayCode.String()
	output.Data.IPv4Prefix = ipv4.String()
	output.Data.IPv6Prefix = ipv6.String()
	output.Data.Version = result.Version
	output.Data.CreatedAt = result.CreatedAt
	output.CorrelationID = correlationID.String()
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	response.Header().Set("ETag", strongVersionETag(result.Version))
	writeManagementJSON(ctx, handler.logger, response, status, output)
	return "success"
}

func classifyNetworkCreationError(err error) managementError {
	switch {
	case errors.Is(err, provisioning.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "Only the owner, admins and Network admins can create Networks."}
	case errors.Is(err, provisioning.ErrPrefixOverlap):
		return managementError{Status: http.StatusConflict, Code: "network_prefix_overlap",
			Message: "This prefix overlaps another Network in the Workspace. Choose a free range."}
	case errors.Is(err, provisioning.ErrPrefixOutsidePool):
		return managementError{Status: http.StatusUnprocessableEntity, Code: "network_prefix_outside_pool",
			Message: "This prefix is outside the Workspace address pools."}
	case errors.Is(err, provisioning.ErrConflict):
		return managementError{Status: http.StatusConflict, Code: "resource_conflict",
			Message: "A Network with this name exists, or this request ID was used for another Network."}
	case errors.Is(err, provisioning.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "The result is uncertain. Refresh Networks before trying again."}
	}
}

func isNetworkCollectionPost(request *http.Request) bool {
	_, ok := parseNetworkCollectionPath(request)
	return ok && request.Method == http.MethodPost
}
