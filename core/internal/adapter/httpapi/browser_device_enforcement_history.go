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
	"meshtransit.net/core/internal/domain/node/enforcementledger"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/platform/ratelimit"
)

const enforcementHistoryDefaultPageSize = 50

// SessionEnforcementHistory requires current exact-scope device.read for every
// page of recorded enforcement evidence (R1-69).
type SessionEnforcementHistory interface {
	Read(ctx context.Context, session accountsession.Session, scope network.Scope, at time.Time, after node.ID,
		limit int) (enforcementledger.HistoryPage, error)
}

func parseEnforcementHistoryPath(request *http.Request) (network.Scope, bool) {
	if request == nil || request.URL == nil || request.Method != http.MethodGet {
		return network.Scope{}, false
	}
	parts := strings.Split(request.URL.Path, "/")
	if len(parts) != 9 || parts[0] != "" || parts[1] != "api" || parts[2] != "v1" ||
		parts[3] != "workspaces" || parts[5] != "networks" || parts[7] != "devices" ||
		parts[8] != "enforcement-history" {
		return network.Scope{}, false
	}
	workspaceID, workspaceErr := workspace.ParseID(parts[4])
	networkID, networkErr := network.ParseID(parts[6])
	scope, err := network.NewScope(workspaceID, networkID)
	return scope, workspaceErr == nil && networkErr == nil && err == nil &&
		workspaceID.String() == parts[4] && networkID.String() == parts[6]
}

// The page token pins the instant, so later pages read the same moment even
// when "at" was omitted on the first page.
type enforcementHistoryPageToken struct {
	Version     int    `json:"v"`
	WorkspaceID string `json:"workspace_id"`
	NetworkID   string `json:"network_id"`
	At          string `json:"at"`
	After       string `json:"after"`
}

type enforcementHistoryQuery struct {
	at    time.Time
	after node.ID
	limit int
}

func encodeEnforcementHistoryPageToken(scope network.Scope, at time.Time, after node.ID) (string, error) {
	if !scope.IsValid() || at.IsZero() || !after.IsValid() {
		return "", enforcementledger.ErrInvalidRequest
	}
	payload, err := json.Marshal(enforcementHistoryPageToken{Version: 1, WorkspaceID: scope.WorkspaceID().String(),
		NetworkID: scope.NetworkID().String(), At: at.UTC().Format(time.RFC3339Nano), After: after.String()})
	return base64.RawURLEncoding.EncodeToString(payload), err
}

func parseEnforcementHistoryQuery(raw string, scope network.Scope) (enforcementHistoryQuery, error) {
	invalid := enforcementledger.ErrInvalidRequest
	values, err := url.ParseQuery(raw)
	if err != nil || !scope.IsValid() {
		return enforcementHistoryQuery{}, invalid
	}
	for key, entries := range values {
		if (key != "at" && key != "page_size" && key != "page_token") || len(entries) != 1 || entries[0] == "" {
			return enforcementHistoryQuery{}, invalid
		}
	}
	query := enforcementHistoryQuery{limit: enforcementHistoryDefaultPageSize}
	if value := values.Get("page_size"); value != "" {
		query.limit, err = strconv.Atoi(value)
		if err != nil || query.limit < 1 || query.limit > enforcementledger.MaximumHistoryPageSize ||
			strconv.Itoa(query.limit) != value {
			return enforcementHistoryQuery{}, invalid
		}
	}
	if value := values.Get("at"); value != "" {
		if len(value) > 40 {
			return enforcementHistoryQuery{}, invalid
		}
		if query.at, err = time.Parse(time.RFC3339Nano, value); err != nil {
			return enforcementHistoryQuery{}, invalid
		}
		query.at = query.at.UTC().Truncate(time.Microsecond)
	}
	encoded := values.Get("page_token")
	if encoded == "" {
		return query, nil
	}
	if len(encoded) > 512 {
		return enforcementHistoryQuery{}, invalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return enforcementHistoryQuery{}, invalid
	}
	var wire enforcementHistoryPageToken
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || ensureJSONEnd(decoder) != nil || wire.Version != 1 ||
		wire.WorkspaceID != scope.WorkspaceID().String() || wire.NetworkID != scope.NetworkID().String() {
		return enforcementHistoryQuery{}, invalid
	}
	at, err := time.Parse(time.RFC3339Nano, wire.At)
	if err != nil || (!query.at.IsZero() && !query.at.Equal(at)) {
		return enforcementHistoryQuery{}, invalid
	}
	query.at = at.UTC()
	if query.after, err = node.ParseID(wire.After); err != nil || query.after.String() != wire.After {
		return enforcementHistoryQuery{}, invalid
	}
	return query, nil
}

type enforcementEvidenceItem struct {
	ID              string     `json:"id"`
	Hostname        *string    `json:"hostname"`
	State           string     `json:"state"`
	NetworkRevision int64      `json:"network_revision"`
	DeliveredDigest string     `json:"delivered_digest"`
	DeliveredGrants int        `json:"delivered_grants"`
	EnforcedDigest  string     `json:"enforced_digest"`
	EnforcedGrants  int        `json:"enforced_grants"`
	AppliedAt       time.Time  `json:"applied_at"`
	ReportedAt      time.Time  `json:"reported_at"`
	ValidFrom       time.Time  `json:"valid_from"`
	ValidTo         *time.Time `json:"valid_to"`
}

type enforcementHistoryData struct {
	WorkspaceID   string                    `json:"workspace_id"`
	NetworkID     string                    `json:"network_id"`
	At            time.Time                 `json:"at"`
	RecordedSince *time.Time                `json:"recorded_since"`
	Devices       []enforcementEvidenceItem `json:"devices"`
}

type enforcementHistoryEnvelope struct {
	Data          enforcementHistoryData `json:"data"`
	NextPageToken string                 `json:"next_page_token,omitempty"`
	CorrelationID string                 `json:"correlation_id"`
}

func newEnforcementEvidenceItem(evidence enforcementledger.Evidence) enforcementEvidenceItem {
	item := enforcementEvidenceItem{
		ID: evidence.DeviceID.String(), State: string(evidence.State), NetworkRevision: evidence.NetworkRevision,
		DeliveredDigest: evidence.Delivered.Digest.String(), DeliveredGrants: evidence.Delivered.Grants,
		EnforcedDigest: evidence.Enforced.Digest.String(), EnforcedGrants: evidence.Enforced.Grants,
		AppliedAt: evidence.AppliedAt.UTC(), ReportedAt: evidence.ReportedAt.UTC(), ValidFrom: evidence.ValidFrom.UTC(),
	}
	if evidence.Hostname != "" {
		hostname := evidence.Hostname
		item.Hostname = &hostname
	}
	if !evidence.ValidTo.IsZero() {
		validTo := evidence.ValidTo.UTC()
		item.ValidTo = &validTo
	}
	return item
}

func (browser *BrowserManagement) readEnforcementHistory(ctx context.Context, response *browserManagementResponse,
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
	query, err := parseEnforcementHistoryQuery(request.URL.RawQuery, scope)
	if err != nil {
		fail(*invalidManagementRequest())
		return nil
	}
	page, err := browser.enforcementHistory.Read(ctx, session, scope, query.at, query.after, query.limit)
	if err != nil {
		value := internalManagementError()
		switch {
		case errors.Is(err, enforcementledger.ErrForbidden):
			value = managementError{Status: http.StatusForbidden, Code: "enforcement_history_forbidden",
				Message: "Enforcement history is unavailable for this scope"}
		case errors.Is(err, enforcementledger.ErrInvalidRequest):
			value = *invalidManagementRequest()
		case errors.Is(err, enforcementledger.ErrUnavailable), errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			value = managementError{Status: http.StatusServiceUnavailable, Code: "enforcement_history_unavailable",
				Message: "Enforcement history is temporarily unavailable", Retryable: true}
		}
		fail(value)
		return nil
	}
	if page.Scope != scope || page.At.IsZero() || len(page.Devices) > query.limit {
		fail(internalManagementError())
		return nil
	}
	data := enforcementHistoryData{WorkspaceID: scope.WorkspaceID().String(), NetworkID: scope.NetworkID().String(),
		At: page.At.UTC(), Devices: make([]enforcementEvidenceItem, 0, len(page.Devices))}
	if !page.RecordedSince.IsZero() {
		since := page.RecordedSince.UTC()
		data.RecordedSince = &since
	}
	for _, evidence := range page.Devices {
		data.Devices = append(data.Devices, newEnforcementEvidenceItem(evidence))
	}
	next := ""
	if page.Next != (node.ID{}) {
		next, err = encodeEnforcementHistoryPageToken(scope, page.At, page.Next)
		if err != nil {
			return ErrBrowserManagementUnavailable
		}
	}
	writeManagementJSON(ctx, browser.management.logger, response, http.StatusOK,
		enforcementHistoryEnvelope{Data: data, NextPageToken: next, CorrelationID: correlationID.String()})
	return nil
}
