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

	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/node/inventory"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/platform/ratelimit"
)

// SessionDeviceInventory requires current exact-scope device.read for every
// page and every Device read.
type SessionDeviceInventory interface {
	List(context.Context, accountsession.Session, network.Scope, inventory.Query) (inventory.Page, error)
	Get(context.Context, accountsession.Session, network.Scope, node.ID) (inventory.Record, error)
	Names(context.Context, accountsession.Session, network.Scope, []node.ID) (map[node.ID]string, error)
}

// defaultDeviceInventoryPage is the Console's page of ten rows.
const defaultDeviceInventoryPage = 10

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

// parseDeviceItemPath matches GET /api/v1/workspaces/{ws}/networks/{net}/devices/{device}
// with no query.
func parseDeviceItemPath(request *http.Request) (network.Scope, node.ID, bool) {
	if request == nil || request.URL == nil || request.Method != http.MethodGet || request.URL.RawQuery != "" {
		return network.Scope{}, node.ID{}, false
	}
	parts := strings.Split(request.URL.Path, "/")
	if len(parts) != 9 || parts[0] != "" || parts[1] != "api" || parts[2] != "v1" ||
		parts[3] != "workspaces" || parts[5] != "networks" || parts[7] != "devices" {
		return network.Scope{}, node.ID{}, false
	}
	workspaceID, workspaceErr := workspace.ParseID(parts[4])
	networkID, networkErr := network.ParseID(parts[6])
	deviceID, deviceErr := node.ParseID(parts[8])
	scope, err := network.NewScope(workspaceID, networkID)
	return scope, deviceID, workspaceErr == nil && networkErr == nil && deviceErr == nil && err == nil &&
		workspaceID.String() == parts[4] && networkID.String() == parts[6] && deviceID.String() == parts[8]
}

// deviceInventoryPageToken continues a page in name order. It carries the
// filters it was issued for, so a token cannot continue another search.
type deviceInventoryPageToken struct {
	Version       int    `json:"v"`
	WorkspaceID   string `json:"workspace_id"`
	NetworkID     string `json:"network_id"`
	NamePrefix    string `json:"q"`
	State         string `json:"state"`
	AfterHostname string `json:"after_hostname"`
	After         string `json:"after"`
}

func encodeDeviceInventoryPageToken(scope network.Scope, query inventory.Query, cursor inventory.Cursor) (string, error) {
	if !scope.IsValid() || !cursor.IsValid() {
		return "", inventory.ErrInvalidRequest
	}
	payload, err := json.Marshal(deviceInventoryPageToken{Version: 2,
		WorkspaceID: scope.WorkspaceID().String(), NetworkID: scope.NetworkID().String(),
		NamePrefix: query.NamePrefix, State: string(query.State),
		AfterHostname: cursor.AfterHostname, After: cursor.After.String()})
	return base64.RawURLEncoding.EncodeToString(payload), err
}

// deviceInventoryIncludeStatus is the one value include takes: each row
// then carries its connection and policy status (D-1).
const deviceInventoryIncludeStatus = "status"

// parseDeviceInventoryQuery reads page_size (1-100, 10 by default),
// page_token, q (a name prefix), state (active or inactive) and include
// (status), each once. include adds to the rows and never changes which
// rows a page holds, so a page token does not carry it.
func parseDeviceInventoryQuery(raw string, scope network.Scope) (inventory.Query, error) {
	query, _, err := parseDeviceInventoryRequest(raw, scope)
	return query, err
}

// parseDeviceInventoryRequest is parseDeviceInventoryQuery that also says
// whether the rows should carry their status.
func parseDeviceInventoryRequest(raw string, scope network.Scope) (inventory.Query, bool, error) {
	query, err := parseDeviceInventoryValues(raw, scope)
	if err != nil {
		return inventory.Query{}, false, err
	}
	values, _ := url.ParseQuery(raw)
	return query, values.Get("include") == deviceInventoryIncludeStatus, nil
}

func parseDeviceInventoryValues(raw string, scope network.Scope) (inventory.Query, error) {
	values, err := url.ParseQuery(raw)
	if err != nil || !scope.IsValid() {
		return inventory.Query{}, inventory.ErrInvalidRequest
	}
	for key, entries := range values {
		known := key == "page_size" || key == "page_token" || key == "q" || key == "state" || key == "include"
		if !known || len(entries) != 1 || entries[0] == "" ||
			(key == "include" && entries[0] != deviceInventoryIncludeStatus) {
			return inventory.Query{}, inventory.ErrInvalidRequest
		}
	}
	query := inventory.Query{Limit: defaultDeviceInventoryPage, NamePrefix: values.Get("q"),
		State: inventory.StateFilter(values.Get("state"))}
	if value := values.Get("page_size"); value != "" {
		query.Limit, err = strconv.Atoi(value)
		if err != nil || strconv.Itoa(query.Limit) != value {
			return inventory.Query{}, inventory.ErrInvalidRequest
		}
	}
	if encoded := values.Get("page_token"); encoded != "" {
		if len(encoded) > 1024 {
			return inventory.Query{}, inventory.ErrInvalidRequest
		}
		payload, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded {
			return inventory.Query{}, inventory.ErrInvalidRequest
		}
		var wire deviceInventoryPageToken
		decoder := json.NewDecoder(strings.NewReader(string(payload)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&wire) != nil || ensureJSONEnd(decoder) != nil || wire.Version != 2 ||
			wire.WorkspaceID != scope.WorkspaceID().String() || wire.NetworkID != scope.NetworkID().String() ||
			wire.NamePrefix != query.NamePrefix || wire.State != string(query.State) {
			return inventory.Query{}, inventory.ErrInvalidRequest
		}
		id, err := node.ParseID(wire.After)
		query.Cursor = inventory.Cursor{AfterHostname: wire.AfterHostname, After: id}
		if err != nil || id.String() != wire.After || !query.Cursor.IsValid() {
			return inventory.Query{}, inventory.ErrInvalidRequest
		}
	}
	if !query.IsValid() {
		return inventory.Query{}, inventory.ErrInvalidRequest
	}
	return query, nil
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
	// DNSName is <label>.<workspace code>.<network code>.<suffix>, null for
	// a Device that holds no name (revoked).
	DNSName *string `json:"dns_name"`
	// AdvertisedPrefixes are the subnets the Device offers to forward as a
	// router, canonical and sorted: the first 16 in a list, all on one
	// Device's read. AdvertisedPrefixCount counts them all.
	AdvertisedPrefixes    []string `json:"advertised_prefixes"`
	AdvertisedPrefixCount int      `json:"advertised_prefix_count"`
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

func newDeviceInventoryItem(device inventory.Device, zone dnsname.Zone) deviceInventoryItem {
	lifecycle := device.Lifecycle()
	item := deviceInventoryItem{ID: device.ID().String(), Hostname: device.Hostname(),
		State: device.State(), Ephemeral: device.Ephemeral(), Version: device.Version(),
		CreatedAt: device.CreatedAt(), UpdatedAt: device.UpdatedAt(), ExpiresAt: device.ExpiresAt(),
		Ownership: lifecycle.Ownership, Owner: newDeviceInventoryMember(lifecycle.Owner),
		HandoverTo: newDeviceInventoryMember(lifecycle.HandoverTo)}
	if item.Ownership == "" {
		item.Ownership = "member"
	}
	offer, count := device.Offer()
	item.AdvertisedPrefixes, item.AdvertisedPrefixCount = make([]string, len(offer)), count
	for index, prefix := range offer {
		item.AdvertisedPrefixes[index] = prefix.String()
	}
	if lifecycle.SuspendedReason != "" {
		reason := lifecycle.SuspendedReason
		item.SuspendedReason = &reason
	}
	if label, labeled := device.DNSLabel(); labeled {
		if name, named := zone.DeviceName(label); named {
			item.DNSName = &name
		}
	}
	return item
}

type deviceInventoryData struct {
	WorkspaceID string                `json:"workspace_id"`
	NetworkID   string                `json:"network_id"`
	Revision    int64                 `json:"inventory_revision"`
	Devices     []deviceInventoryItem `json:"devices"`
}

// deviceListStatus is one row's connection and policy status (D-1): the
// same classification as the Device's own status read, without the detail.
type deviceListStatus struct {
	// Status is in_sync, behind, offline, never_connected or unknown.
	Status                   string     `json:"status"`
	Online                   bool       `json:"online"`
	LastSeenAt               *time.Time `json:"last_seen_at"`
	DeliveredNetworkRevision *int64     `json:"delivered_network_revision"`
	// Enforcement is enforced, applying, mismatch, not_reported or unknown.
	Enforcement string `json:"enforcement"`
	// Platform is what the Device's client runs on; null when unknown.
	Platform *devicePlatformItem `json:"platform"`
	// PublicAddresses are its addresses on the Internet; empty when unknown.
	PublicAddresses []devicePublicAddressItem `json:"public_addresses"`
}

// deviceInventoryStatusRow is a list row with its status; Status is null
// for a Device that receives no policy (expired, revoked, deleted) and when
// Core could not read delivery records.
type deviceInventoryStatusRow struct {
	deviceInventoryItem
	Status *deviceListStatus `json:"status"`
}

type deviceInventoryStatusData struct {
	WorkspaceID string `json:"workspace_id"`
	NetworkID   string `json:"network_id"`
	Revision    int64  `json:"inventory_revision"`
	// NetworkRevision and PolicyRevision are what an in_sync Device holds;
	// null when no row needed them or they could not be read.
	NetworkRevision       *int64                     `json:"network_revision"`
	PolicyRevision        *int64                     `json:"policy_revision"`
	ObservationsAvailable bool                       `json:"observations_available"`
	Devices               []deviceInventoryStatusRow `json:"devices"`
}

type deviceInventoryStatusEnvelope struct {
	Data          deviceInventoryStatusData `json:"data"`
	NextPageToken string                    `json:"next_page_token,omitempty"`
	CorrelationID string                    `json:"correlation_id"`
}

func newDeviceListStatus(device distribution.Device, countries CountryLookup) *deviceListStatus {
	status := &deviceListStatus{Status: string(device.Status), Online: device.Observation.Online,
		Enforcement: string(device.Enforcement), PublicAddresses: []devicePublicAddressItem{}}
	if device.Status == distribution.StatusUnknown {
		status.Online = false
	}
	if status.Enforcement == "" {
		status.Enforcement = string(distribution.EnforcementUnknown)
	}
	if observation := device.Observation; device.Status != distribution.StatusUnknown && observation.Known {
		seenAt, revision := observation.SeenAt.UTC(), observation.NetworkRevision
		status.LastSeenAt, status.DeliveredNetworkRevision = &seenAt, &revision
		status.Platform = newDevicePlatformItem(observation.Platform)
		status.PublicAddresses = newDevicePublicAddresses(observation.Connectivity, countries)
	}
	return status
}

type deviceInventoryEnvelope struct {
	Data          deviceInventoryData `json:"data"`
	NextPageToken string              `json:"next_page_token,omitempty"`
	CorrelationID string              `json:"correlation_id"`
}

// beginDeviceRead budgets, authenticates and prepares the response of one
// Device inventory read; ok is false when it already answered.
func (browser *BrowserManagement) beginDeviceRead(ctx context.Context, response *browserManagementResponse,
	request *http.Request, admission *browserManagementAdmission,
) (session accountsession.Session, fail func(managementError), correlation string, ok bool, err error) {
	correlationID, err := browser.management.correlationIDs.NewID()
	if err != nil || !correlationID.IsValid() {
		return accountsession.Session{}, nil, "", false, ErrBrowserManagementUnavailable
	}
	setManagementSecurityHeaders(response.header, correlationID)
	fail = func(value managementError) {
		writeManagementError(ctx, browser.management.logger, response, correlationID, value)
	}
	address, err := browser.management.clientIPs.Resolve(request)
	if err != nil {
		fail(*invalidManagementRequest())
		return accountsession.Session{}, nil, "", false, nil
	}
	if limitErr := browser.management.enforceAdmittedRateLimit(ctx, admission, continuationBudget{
		response: response, kind: ratelimit.SubjectSource, raw: address.String(), policy: browser.management.sourcePolicy,
	}); limitErr != nil {
		fail(*limitErr)
		return accountsession.Session{}, nil, "", false, nil
	}
	session, err = admission.authenticate(ctx, request)
	if err != nil {
		fail(classifyAuthenticationError(err))
		return accountsession.Session{}, nil, "", false, nil
	}
	if limitErr := browser.management.enforceAdmittedRateLimit(ctx, admission, continuationBudget{
		response: response, kind: ratelimit.SubjectAccountSession, raw: session.ID().String(), policy: browser.management.sessionPolicy,
	}); limitErr != nil {
		fail(*limitErr)
		return accountsession.Session{}, nil, "", false, nil
	}
	return session, fail, correlationID.String(), true, nil
}

func classifyDeviceInventoryError(err error) managementError {
	switch {
	case errors.Is(err, inventory.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "device_inventory_forbidden", Message: "Device inventory is unavailable for this scope"}
	case errors.Is(err, inventory.ErrNotFound):
		return managementError{Status: http.StatusNotFound, Code: "device_not_found", Message: "The Device is not in this Network"}
	case errors.Is(err, inventory.ErrInvalidRequest):
		return *invalidManagementRequest()
	case errors.Is(err, inventory.ErrUnavailable), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return managementError{Status: http.StatusServiceUnavailable, Code: "device_inventory_unavailable", Message: "Device inventory is temporarily unavailable", Retryable: true}
	default:
		return internalManagementError()
	}
}

func (browser *BrowserManagement) readDeviceInventory(ctx context.Context, response *browserManagementResponse,
	request *http.Request, admission *browserManagementAdmission, scope network.Scope,
) error {
	session, fail, correlationID, ok, err := browser.beginDeviceRead(ctx, response, request, admission)
	if !ok {
		return err
	}
	query, withStatus, err := parseDeviceInventoryRequest(request.URL.RawQuery, scope)
	if err != nil {
		fail(*invalidManagementRequest())
		return nil
	}
	page, err := browser.inventory.List(ctx, session, scope, query)
	if err != nil {
		fail(classifyDeviceInventoryError(err))
		return nil
	}
	if page.Scope() != scope || page.Revision() < 1 {
		fail(internalManagementError())
		return nil
	}
	workspaceCode, networkCode := page.DisplayCodes()
	zone, err := dnsname.NewZone(workspaceCode, networkCode, browser.management.dnsSuffix)
	if err != nil {
		fail(internalManagementError())
		return nil
	}
	data := deviceInventoryData{WorkspaceID: scope.WorkspaceID().String(), NetworkID: scope.NetworkID().String(),
		Revision: page.Revision(), Devices: make([]deviceInventoryItem, 0, query.Limit)}
	for _, device := range page.Devices() {
		data.Devices = append(data.Devices, newDeviceInventoryItem(device, zone))
	}
	next := ""
	if cursor, ok := page.Next(); ok {
		next, err = encodeDeviceInventoryPageToken(scope, query, cursor)
		if err != nil {
			return ErrBrowserManagementUnavailable
		}
	}
	if withStatus {
		return browser.writeDeviceInventoryStatus(ctx, response, session, scope, page, data, next, fail, correlationID)
	}
	writeManagementJSON(ctx, browser.management.logger, response, http.StatusOK,
		deviceInventoryEnvelope{Data: data, NextPageToken: next, CorrelationID: correlationID})
	return nil
}

// writeDeviceInventoryStatus answers a page whose rows carry their status:
// one revision read and one batch of delivery records for the page's
// active and suspended Devices, never a read per Device. A Core without
// delivery records still answers the page, with null statuses.
func (browser *BrowserManagement) writeDeviceInventoryStatus(ctx context.Context, response *browserManagementResponse,
	session accountsession.Session, scope network.Scope, page inventory.Page, data deviceInventoryData, next string,
	fail func(managementError), correlationID string,
) error {
	envelope := deviceInventoryStatusEnvelope{NextPageToken: next, CorrelationID: correlationID,
		Data: deviceInventoryStatusData{WorkspaceID: data.WorkspaceID, NetworkID: data.NetworkID,
			Revision: data.Revision, Devices: make([]deviceInventoryStatusRow, len(data.Devices))}}
	held := make([]distribution.TargetDevice, 0, len(data.Devices))
	rows := make([]int, 0, len(data.Devices))
	for index, device := range page.Devices() {
		envelope.Data.Devices[index] = deviceInventoryStatusRow{deviceInventoryItem: data.Devices[index]}
		if state := device.State(); state == "active" || state == "suspended" {
			held = append(held, distribution.TargetDevice{ID: device.ID(), Hostname: device.Hostname(), State: state})
			rows = append(rows, index)
		}
	}
	if len(held) > 0 && browser.distribution != nil {
		report, err := browser.distribution.ReadPage(ctx, session, scope, held)
		switch {
		case errors.Is(err, distribution.ErrForbidden):
			fail(classifyDeviceDistributionError(err))
			return nil
		case errors.Is(err, distribution.ErrInvalidRequest), errors.Is(err, distribution.ErrInvalidResult):
			// A bad page or bad evidence is a Core fault, not an outage: fail closed.
			fail(internalManagementError())
			return nil
		case err != nil:
			// The revisions could not be read; the page still stands, with null
			// statuses, and the cause is logged so blank columns are explained.
			browser.management.logger.WarnContext(ctx, "device list status unavailable",
				"correlation_id", correlationID, "error", err)
		case report.Scope != scope || len(report.Devices) != len(held):
			fail(internalManagementError())
			return nil
		default:
			networkRevision, policyRevision := report.NetworkRevision, report.PolicyRevision
			envelope.Data.NetworkRevision, envelope.Data.PolicyRevision = &networkRevision, &policyRevision
			envelope.Data.ObservationsAvailable = report.ObservationsAvailable
			for position, row := range rows {
				if report.Devices[position].ID != held[position].ID {
					fail(internalManagementError())
					return nil
				}
				envelope.Data.Devices[row].Status = newDeviceListStatus(report.Devices[position], browser.management.countries)
			}
		}
	}
	writeManagementJSON(ctx, browser.management.logger, response, http.StatusOK, envelope)
	return nil
}

type deviceEnrollmentBody struct {
	// Kind is "browser" or "key".
	Kind        string                 `json:"kind"`
	KeyID       *string                `json:"key_id"`
	Description *string                `json:"description"`
	CreatedBy   *deviceInventoryMember `json:"created_by"`
}

type deviceTagRefBody struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type deviceRecordEnvelope struct {
	Data struct {
		WorkspaceID string               `json:"workspace_id"`
		NetworkID   string               `json:"network_id"`
		Device      deviceInventoryItem  `json:"device"`
		Enrollment  deviceEnrollmentBody `json:"enrollment"`
		Tags        []deviceTagRefBody   `json:"tags"`
		// Addresses are the mesh addresses the Device holds now, IPv4 first.
		Addresses []string `json:"addresses"`
	} `json:"data"`
	CorrelationID string `json:"correlation_id"`
}

func newDeviceEnrollmentBody(enrollment inventory.Enrollment) deviceEnrollmentBody {
	if !enrollment.ByKey {
		return deviceEnrollmentBody{Kind: "browser"}
	}
	keyID, description := enrollment.KeyID.String(), enrollment.KeyDescription
	return deviceEnrollmentBody{Kind: "key", KeyID: &keyID, Description: &description,
		CreatedBy: newDeviceInventoryMember(enrollment.KeyCreatedBy)}
}

// readDevice answers one Device of the scope and how it was enrolled.
func (browser *BrowserManagement) readDevice(ctx context.Context, response *browserManagementResponse,
	request *http.Request, admission *browserManagementAdmission, scope network.Scope, id node.ID,
) error {
	session, fail, correlationID, ok, err := browser.beginDeviceRead(ctx, response, request, admission)
	if !ok {
		return err
	}
	record, err := browser.inventory.Get(ctx, session, scope, id)
	if err != nil {
		fail(classifyDeviceInventoryError(err))
		return nil
	}
	zone, err := dnsname.NewZone(record.WorkspaceCode, record.NetworkCode, browser.management.dnsSuffix)
	if err != nil || record.Scope != scope {
		fail(internalManagementError())
		return nil
	}
	var envelope deviceRecordEnvelope
	envelope.Data.WorkspaceID, envelope.Data.NetworkID = scope.WorkspaceID().String(), scope.NetworkID().String()
	envelope.Data.Device = newDeviceInventoryItem(record.Device, zone)
	envelope.Data.Enrollment = newDeviceEnrollmentBody(record.Enrollment)
	envelope.Data.Tags = make([]deviceTagRefBody, len(record.Tags))
	for index, tag := range record.Tags {
		envelope.Data.Tags[index] = deviceTagRefBody{ID: tag.ID.String(), Name: tag.Name}
	}
	envelope.Data.Addresses = make([]string, len(record.Addresses))
	for index, address := range record.Addresses {
		envelope.Data.Addresses[index] = address.String()
	}
	envelope.CorrelationID = correlationID
	writeManagementJSON(ctx, browser.management.logger, response, http.StatusOK, envelope)
	return nil
}
