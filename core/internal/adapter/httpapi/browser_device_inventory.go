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
	"meshtransit.net/core/internal/domain/node/inventory"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/platform/ratelimit"
)

// SessionDeviceInventory requires current exact-scope device.read for every page.
type SessionDeviceInventory interface {
	List(context.Context, accountsession.Session, network.Scope, int, inventory.Cursor) (inventory.Page, error)
}

func parseDeviceInventoryPath(request *http.Request) (network.Scope, bool) {
	if request == nil || request.URL == nil || request.Method != http.MethodGet {
		return network.Scope{}, false
	}
	parts := strings.Split(request.URL.Path, "/")
	if len(parts) != 8 || parts[0] != "" || parts[1] != "api" || parts[2] != "v1" ||
		parts[3] != "workspaces" || parts[5] != "networks" || parts[7] != "devices" {
		return network.Scope{}, false
	}
	workspaceID, workspaceErr := workspace.ParseID(parts[4])
	networkID, networkErr := network.ParseID(parts[6])
	scope, err := network.NewScope(workspaceID, networkID)
	return scope, workspaceErr == nil && networkErr == nil && err == nil &&
		workspaceID.String() == parts[4] && networkID.String() == parts[6]
}

type deviceInventoryPageToken struct {
	Version     int    `json:"v"`
	WorkspaceID string `json:"workspace_id"`
	NetworkID   string `json:"network_id"`
	After       string `json:"after"`
	Revision    int64  `json:"inventory_revision"`
}

func encodeDeviceInventoryPageToken(scope network.Scope, cursor inventory.Cursor) (string, error) {
	if !scope.IsValid() || !cursor.IsValid() {
		return "", inventory.ErrInvalidRequest
	}
	payload, err := json.Marshal(deviceInventoryPageToken{Version: 1,
		WorkspaceID: scope.WorkspaceID().String(), NetworkID: scope.NetworkID().String(),
		After: cursor.After.String(), Revision: cursor.Revision})
	return base64.RawURLEncoding.EncodeToString(payload), err
}

func parseDeviceInventoryQuery(raw string, scope network.Scope) (int, inventory.Cursor, error) {
	values, err := url.ParseQuery(raw)
	if err != nil || !scope.IsValid() {
		return 0, inventory.Cursor{}, inventory.ErrInvalidRequest
	}
	for key, entries := range values {
		if (key != "page_size" && key != "page_token") || len(entries) != 1 || entries[0] == "" {
			return 0, inventory.Cursor{}, inventory.ErrInvalidRequest
		}
	}
	limit := 50
	if value := values.Get("page_size"); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil || limit < 1 || limit > inventory.MaximumPageSize || strconv.Itoa(limit) != value {
			return 0, inventory.Cursor{}, inventory.ErrInvalidRequest
		}
	}
	cursor := inventory.Cursor{}
	if encoded := values.Get("page_token"); encoded != "" {
		if len(encoded) > 512 {
			return 0, cursor, inventory.ErrInvalidRequest
		}
		payload, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded {
			return 0, cursor, inventory.ErrInvalidRequest
		}
		var wire deviceInventoryPageToken
		decoder := json.NewDecoder(strings.NewReader(string(payload)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&wire) != nil || ensureJSONEnd(decoder) != nil || wire.Version != 1 ||
			wire.WorkspaceID != scope.WorkspaceID().String() || wire.NetworkID != scope.NetworkID().String() {
			return 0, cursor, inventory.ErrInvalidRequest
		}
		id, err := node.ParseID(wire.After)
		cursor = inventory.Cursor{After: id, Revision: wire.Revision}
		if err != nil || !cursor.IsValid() {
			return 0, cursor, inventory.ErrInvalidRequest
		}
	}
	return limit, cursor, nil
}

type deviceInventoryItem struct {
	ID        string    `json:"id"`
	Hostname  string    `json:"hostname"`
	State     string    `json:"state"`
	Ephemeral bool      `json:"is_ephemeral"`
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Ownership is "member" or "workspace"; Owner is set for a member Device.
	Ownership       string                 `json:"ownership"`
	Owner           *deviceInventoryMember `json:"owner"`
	SuspendedReason *string                `json:"suspended_reason"`
	HandoverTo      *deviceInventoryMember `json:"handover_to"`
}

type deviceInventoryMember struct {
	PrincipalID string `json:"principal_id"`
	DisplayName string `json:"display_name"`
}

func newDeviceInventoryMember(member inventory.Member) *deviceInventoryMember {
	if !member.PrincipalID.IsValid() {
		return nil
	}
	return &deviceInventoryMember{PrincipalID: member.PrincipalID.String(), DisplayName: member.DisplayName}
}

func newDeviceInventoryItem(device inventory.Device) deviceInventoryItem {
	lifecycle := device.Lifecycle()
	item := deviceInventoryItem{ID: device.ID().String(), Hostname: device.Hostname(),
		State: device.State(), Ephemeral: device.Ephemeral(), Version: device.Version(),
		CreatedAt: device.CreatedAt(), UpdatedAt: device.UpdatedAt(), ExpiresAt: device.ExpiresAt(),
		Ownership: lifecycle.Ownership, Owner: newDeviceInventoryMember(lifecycle.Owner),
		HandoverTo: newDeviceInventoryMember(lifecycle.HandoverTo)}
	if item.Ownership == "" {
		item.Ownership = "member"
	}
	if lifecycle.SuspendedReason != "" {
		reason := lifecycle.SuspendedReason
		item.SuspendedReason = &reason
	}
	return item
}

type deviceInventoryData struct {
	WorkspaceID string                `json:"workspace_id"`
	NetworkID   string                `json:"network_id"`
	Revision    int64                 `json:"inventory_revision"`
	Devices     []deviceInventoryItem `json:"devices"`
}
type deviceInventoryEnvelope struct {
	Data          deviceInventoryData `json:"data"`
	NextPageToken string              `json:"next_page_token,omitempty"`
	CorrelationID string              `json:"correlation_id"`
}

func (browser *BrowserManagement) readDeviceInventory(ctx context.Context, response *browserManagementResponse,
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
	limit, cursor, err := parseDeviceInventoryQuery(request.URL.RawQuery, scope)
	if err != nil {
		fail(*invalidManagementRequest())
		return nil
	}
	page, err := browser.inventory.List(ctx, session, scope, limit, cursor)
	if err != nil {
		value := internalManagementError()
		switch {
		case errors.Is(err, inventory.ErrForbidden):
			value = managementError{Status: http.StatusForbidden, Code: "device_inventory_forbidden", Message: "Device inventory is unavailable for this scope"}
		case errors.Is(err, inventory.ErrRevisionChanged):
			value = managementError{Status: http.StatusConflict, Code: "inventory_revision_changed", Message: "Device inventory changed; refresh the list"}
		case errors.Is(err, inventory.ErrInvalidRequest):
			value = *invalidManagementRequest()
		case errors.Is(err, inventory.ErrUnavailable), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			value = managementError{Status: http.StatusServiceUnavailable, Code: "device_inventory_unavailable", Message: "Device inventory is temporarily unavailable", Retryable: true}
		}
		fail(value)
		return nil
	}
	if page.Scope() != scope || page.Revision() < 1 {
		fail(internalManagementError())
		return nil
	}
	data := deviceInventoryData{WorkspaceID: scope.WorkspaceID().String(), NetworkID: scope.NetworkID().String(),
		Revision: page.Revision(), Devices: make([]deviceInventoryItem, 0, limit)}
	for _, device := range page.Devices() {
		data.Devices = append(data.Devices, newDeviceInventoryItem(device))
	}
	next := ""
	if cursor, ok := page.Next(); ok {
		next, err = encodeDeviceInventoryPageToken(scope, cursor)
		if err != nil {
			return ErrBrowserManagementUnavailable
		}
	}
	writeManagementJSON(ctx, browser.management.logger, response, http.StatusOK,
		deviceInventoryEnvelope{Data: data, NextPageToken: next, CorrelationID: correlationID.String()})
	return nil
}
