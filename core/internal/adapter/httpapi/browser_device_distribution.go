package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/platform/ratelimit"
)

// SessionDeviceDistribution requires current exact-scope device.read for
// every page of policy distribution status (R1-65).
type SessionDeviceDistribution interface {
	Read(context.Context, accountsession.Session, network.Scope, node.ID, int) (distribution.Page, error)
}

func parseDeviceDistributionPath(request *http.Request) (network.Scope, bool) {
	if request == nil || request.URL == nil || request.Method != http.MethodGet {
		return network.Scope{}, false
	}
	parts := strings.Split(request.URL.Path, "/")
	if len(parts) != 9 || parts[0] != "" || parts[1] != "api" || parts[2] != "v1" ||
		parts[3] != "workspaces" || parts[5] != "networks" || parts[7] != "devices" || parts[8] != "distribution" {
		return network.Scope{}, false
	}
	workspaceID, workspaceErr := workspace.ParseID(parts[4])
	networkID, networkErr := network.ParseID(parts[6])
	scope, err := network.NewScope(workspaceID, networkID)
	return scope, workspaceErr == nil && networkErr == nil && err == nil &&
		workspaceID.String() == parts[4] && networkID.String() == parts[6]
}

type deviceDistributionPageToken struct {
	Version     int    `json:"v"`
	WorkspaceID string `json:"workspace_id"`
	NetworkID   string `json:"network_id"`
	After       string `json:"after"`
}

func encodeDeviceDistributionPageToken(scope network.Scope, after node.ID) (string, error) {
	if !scope.IsValid() || !after.IsValid() {
		return "", distribution.ErrInvalidRequest
	}
	payload, err := json.Marshal(deviceDistributionPageToken{Version: 1, WorkspaceID: scope.WorkspaceID().String(),
		NetworkID: scope.NetworkID().String(), After: after.String()})
	return base64.RawURLEncoding.EncodeToString(payload), err
}

func parseDeviceDistributionQuery(raw string, scope network.Scope) (int, node.ID, error) {
	values, err := url.ParseQuery(raw)
	if err != nil || !scope.IsValid() {
		return 0, node.ID{}, distribution.ErrInvalidRequest
	}
	for key, entries := range values {
		if (key != "page_size" && key != "page_token") || len(entries) != 1 || entries[0] == "" {
			return 0, node.ID{}, distribution.ErrInvalidRequest
		}
	}
	limit := 50
	if value := values.Get("page_size"); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil || limit < 1 || limit > distribution.MaximumPageSize || strconv.Itoa(limit) != value {
			return 0, node.ID{}, distribution.ErrInvalidRequest
		}
	}
	encoded := values.Get("page_token")
	if encoded == "" {
		return limit, node.ID{}, nil
	}
	if len(encoded) > 512 {
		return 0, node.ID{}, distribution.ErrInvalidRequest
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return 0, node.ID{}, distribution.ErrInvalidRequest
	}
	var wire deviceDistributionPageToken
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || ensureJSONEnd(decoder) != nil || wire.Version != 1 ||
		wire.WorkspaceID != scope.WorkspaceID().String() || wire.NetworkID != scope.NetworkID().String() {
		return 0, node.ID{}, distribution.ErrInvalidRequest
	}
	after, err := node.ParseID(wire.After)
	if err != nil || after.String() != wire.After {
		return 0, node.ID{}, distribution.ErrInvalidRequest
	}
	return limit, after, nil
}

type deviceDistributionItem struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	State    string `json:"state"`
	// Status is in_sync, behind, offline, never_connected or unknown.
	Status                   string     `json:"status"`
	Online                   bool       `json:"online"`
	DeliveredNetworkRevision *int64     `json:"delivered_network_revision"`
	DeliveredPolicyRevision  *int64     `json:"delivered_policy_revision"`
	DeliveredAt              *time.Time `json:"delivered_at"`
	LastSeenAt               *time.Time `json:"last_seen_at"`
}

type deviceDistributionData struct {
	WorkspaceID           string                   `json:"workspace_id"`
	NetworkID             string                   `json:"network_id"`
	NetworkRevision       int64                    `json:"network_revision"`
	PolicyRevision        int64                    `json:"policy_revision"`
	ObservationsAvailable bool                     `json:"observations_available"`
	Devices               []deviceDistributionItem `json:"devices"`
}

type deviceDistributionEnvelope struct {
	Data          deviceDistributionData `json:"data"`
	NextPageToken string                 `json:"next_page_token,omitempty"`
	CorrelationID string                 `json:"correlation_id"`
}

func newDeviceDistributionItem(device distribution.Device) deviceDistributionItem {
	item := deviceDistributionItem{ID: device.ID.String(), Hostname: device.Hostname, State: device.State,
		Status: string(device.Status), Online: device.Observation.Online}
	if device.Status == distribution.StatusUnknown {
		item.Online = false
		return item
	}
	if observation := device.Observation; observation.Known {
		networkRevision, policyRevision := observation.NetworkRevision, observation.PolicyRevision
		deliveredAt, seenAt := observation.DeliveredAt.UTC(), observation.SeenAt.UTC()
		item.DeliveredNetworkRevision, item.DeliveredPolicyRevision = &networkRevision, &policyRevision
		item.DeliveredAt, item.LastSeenAt = &deliveredAt, &seenAt
	}
	return item
}

func (browser *BrowserManagement) readDeviceDistribution(ctx context.Context, response *browserManagementResponse,
	request *http.Request, admission *browserManagementAdmission, scope network.Scope,
) error {
	correlationID, err := browser.management.correlationIDs.NewID()
	if err != nil || !correlationID.IsValid() {
		return ErrBrowserManagementUnavailable
	}
	setManagementSecurityHeaders(response.header, correlationID)
	fail := func(value managementError) {
		writeManagementError(ctx, browser.management.logger, response, correlationID, value)
	}
	address, err := browser.management.clientIPs.Resolve(request)
	if err != nil {
		fail(*invalidManagementRequest())
		return nil
	}
	if limitErr := browser.management.enforceAdmittedRateLimit(ctx, admission, continuationBudget{
		response: response, kind: ratelimit.SubjectSource, raw: address.String(), policy: browser.management.sourcePolicy,
	}); limitErr != nil {
		fail(*limitErr)
		return nil
	}
	session, err := admission.authenticate(ctx, request)
	if err != nil {
		fail(classifyAuthenticationError(err))
		return nil
	}
	if limitErr := browser.management.enforceAdmittedRateLimit(ctx, admission, continuationBudget{
		response: response, kind: ratelimit.SubjectAccountSession, raw: session.ID().String(), policy: browser.management.sessionPolicy,
	}); limitErr != nil {
		fail(*limitErr)
		return nil
	}
	limit, after, err := parseDeviceDistributionQuery(request.URL.RawQuery, scope)
	if err != nil {
		fail(*invalidManagementRequest())
		return nil
	}
	page, err := browser.distribution.Read(ctx, session, scope, after, limit)
	if err != nil {
		value := internalManagementError()
		switch {
		case errors.Is(err, distribution.ErrForbidden):
			value = managementError{Status: http.StatusForbidden, Code: "device_distribution_forbidden",
				Message: "Policy distribution status is unavailable for this scope"}
		case errors.Is(err, distribution.ErrInvalidRequest):
			value = *invalidManagementRequest()
		case errors.Is(err, distribution.ErrUnavailable), errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			value = managementError{Status: http.StatusServiceUnavailable, Code: "device_distribution_unavailable",
				Message: "Policy distribution status is temporarily unavailable", Retryable: true}
		}
		fail(value)
		return nil
	}
	if page.Scope != scope || page.NetworkRevision < 1 || len(page.Devices) > limit {
		fail(internalManagementError())
		return nil
	}
	data := deviceDistributionData{WorkspaceID: scope.WorkspaceID().String(), NetworkID: scope.NetworkID().String(),
		NetworkRevision: page.NetworkRevision, PolicyRevision: page.PolicyRevision,
		ObservationsAvailable: page.ObservationsAvailable, Devices: make([]deviceDistributionItem, 0, len(page.Devices))}
	for _, device := range page.Devices {
		data.Devices = append(data.Devices, newDeviceDistributionItem(device))
	}
	next := ""
	if page.Next != (node.ID{}) {
		next, err = encodeDeviceDistributionPageToken(scope, page.Next)
		if err != nil {
			return ErrBrowserManagementUnavailable
		}
	}
	writeManagementJSON(ctx, browser.management.logger, response, http.StatusOK,
		deviceDistributionEnvelope{Data: data, NextPageToken: next, CorrelationID: correlationID.String()})
	return nil
}
