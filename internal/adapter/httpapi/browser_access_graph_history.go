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

	"github.com/meshtransit/meshtransit/internal/accessgraph/ledger"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/ratelimit"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const accessGraphHistoryDefaultPageSize = 100

// SessionAccessGraphHistory requires current exact-scope policy.read and
// device.read for every page of the access edge ledger (R1-68).
type SessionAccessGraphHistory interface {
	Read(context.Context, accountsession.Session, network.Scope, ledger.Query) (ledger.Page, error)
}

func parseAccessGraphHistoryPath(request *http.Request) (network.Scope, bool) {
	if request == nil || request.URL == nil || request.Method != http.MethodGet {
		return network.Scope{}, false
	}
	parts := strings.Split(request.URL.Path, "/")
	if len(parts) != 9 || parts[0] != "" || parts[1] != "api" || parts[2] != "v1" ||
		parts[3] != "workspaces" || parts[5] != "networks" || parts[7] != "access-graph" || parts[8] != "history" {
		return network.Scope{}, false
	}
	workspaceID, workspaceErr := workspace.ParseID(parts[4])
	networkID, networkErr := network.ParseID(parts[6])
	scope, err := network.NewScope(workspaceID, networkID)
	return scope, workspaceErr == nil && networkErr == nil && err == nil &&
		workspaceID.String() == parts[4] && networkID.String() == parts[6]
}

// The page token pins the instant and the filters, so later pages read the
// same moment even when "at" was omitted on the first page.
type accessGraphHistoryPageToken struct {
	Version     int    `json:"v"`
	WorkspaceID string `json:"workspace_id"`
	NetworkID   string `json:"network_id"`
	At          string `json:"at"`
	Filter      string `json:"filter"`
	After       string `json:"after"`
}

func accessGraphHistoryFilter(query ledger.Query) string {
	optional := func(id node.ID) string {
		if id == (node.ID{}) {
			return "-"
		}
		return id.String()
	}
	protocol := "-"
	if query.Protocol != policy.ProtocolUnknown {
		protocol = query.Protocol.String()
	}
	return strings.Join([]string{optional(query.Device), optional(query.Source), optional(query.Destination),
		protocol}, ",")
}

func encodeAccessGraphHistoryPageToken(scope network.Scope, query ledger.Query, at time.Time, after ledger.EdgeKey) (string, error) {
	if !scope.IsValid() || at.IsZero() || after.IsZero() {
		return "", ledger.ErrInvalidRequest
	}
	payload, err := json.Marshal(accessGraphHistoryPageToken{Version: 1, WorkspaceID: scope.WorkspaceID().String(),
		NetworkID: scope.NetworkID().String(), At: at.UTC().Format(time.RFC3339Nano),
		Filter: accessGraphHistoryFilter(query), After: after.String()})
	return base64.RawURLEncoding.EncodeToString(payload), err
}

func parseOptionalDevice(values url.Values, key string) (node.ID, error) {
	value := values.Get(key)
	if value == "" {
		return node.ID{}, nil
	}
	id, err := node.ParseID(value)
	if err != nil || id.String() != value {
		return node.ID{}, ledger.ErrInvalidRequest
	}
	return id, nil
}

func parseAccessGraphHistoryQuery(raw string, scope network.Scope) (ledger.Query, error) {
	values, err := url.ParseQuery(raw)
	if err != nil || !scope.IsValid() {
		return ledger.Query{}, ledger.ErrInvalidRequest
	}
	allowed := map[string]bool{"at": true, "device": true, "source": true, "destination": true, "protocol": true,
		"page_size": true, "page_token": true}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 || entries[0] == "" {
			return ledger.Query{}, ledger.ErrInvalidRequest
		}
	}
	query := ledger.Query{Limit: accessGraphHistoryDefaultPageSize}
	if value := values.Get("page_size"); value != "" {
		query.Limit, err = strconv.Atoi(value)
		if err != nil || query.Limit < 1 || query.Limit > ledger.MaximumPageSize || strconv.Itoa(query.Limit) != value {
			return ledger.Query{}, ledger.ErrInvalidRequest
		}
	}
	if value := values.Get("at"); value != "" {
		if len(value) > 40 {
			return ledger.Query{}, ledger.ErrInvalidRequest
		}
		query.At, err = time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return ledger.Query{}, ledger.ErrInvalidRequest
		}
		query.At = query.At.UTC().Truncate(time.Microsecond)
	}
	if query.Device, err = parseOptionalDevice(values, "device"); err != nil {
		return ledger.Query{}, err
	}
	if query.Source, err = parseOptionalDevice(values, "source"); err != nil {
		return ledger.Query{}, err
	}
	if query.Destination, err = parseOptionalDevice(values, "destination"); err != nil {
		return ledger.Query{}, err
	}
	switch values.Get("protocol") {
	case "":
	case "tcp":
		query.Protocol = policy.ProtocolTCP
	case "udp":
		query.Protocol = policy.ProtocolUDP
	case "icmp":
		query.Protocol = policy.ProtocolICMP
	default:
		return ledger.Query{}, ledger.ErrInvalidRequest
	}
	encoded := values.Get("page_token")
	if encoded == "" {
		return query, nil
	}
	if len(encoded) > 1024 {
		return ledger.Query{}, ledger.ErrInvalidRequest
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != encoded {
		return ledger.Query{}, ledger.ErrInvalidRequest
	}
	var wire accessGraphHistoryPageToken
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || ensureJSONEnd(decoder) != nil || wire.Version != 1 ||
		wire.WorkspaceID != scope.WorkspaceID().String() || wire.NetworkID != scope.NetworkID().String() ||
		wire.Filter != accessGraphHistoryFilter(query) {
		return ledger.Query{}, ledger.ErrInvalidRequest
	}
	at, err := time.Parse(time.RFC3339Nano, wire.At)
	if err != nil || (!query.At.IsZero() && !query.At.Equal(at)) {
		return ledger.Query{}, ledger.ErrInvalidRequest
	}
	query.At = at.UTC()
	if query.After, err = ledger.ParseEdgeKey(wire.After); err != nil {
		return ledger.Query{}, err
	}
	return query, nil
}

type accessGraphHistorySnapshotItem struct {
	ID              string    `json:"id"`
	NetworkRevision int64     `json:"network_revision"`
	EffectiveAt     time.Time `json:"effective_at"`
	RecordedAt      time.Time `json:"recorded_at"`
	EdgeCount       int       `json:"edge_count"`
	Digest          string    `json:"digest"`
}

type accessGraphHistoryEdgeItem struct {
	EdgeID                        string     `json:"edge_id"`
	AccessRuleID                  string     `json:"access_rule_id"`
	SelectorKind                  string     `json:"selector_kind"`
	SourceDeviceID                string     `json:"source_device_id"`
	SourceHostname                *string    `json:"source_hostname"`
	DestinationDeviceID           *string    `json:"destination_device_id"`
	DestinationHostname           *string    `json:"destination_hostname"`
	DestinationImportedResourceID *string    `json:"destination_imported_resource_id"`
	TrustContractID               *string    `json:"trust_contract_id"`
	DestinationResourceID         *string    `json:"destination_resource_id"`
	DestinationResourceGroupID    *string    `json:"destination_resource_group_id"`
	SourceSelectorKind            *string    `json:"source_selector_kind"`
	SourceSelectorID              *string    `json:"source_selector_id"`
	DestinationSelectorKind       *string    `json:"destination_selector_kind"`
	DestinationSelectorID         *string    `json:"destination_selector_id"`
	Protocol                      string     `json:"protocol"`
	PortFirst                     []int      `json:"destination_port_range_first"`
	PortLast                      []int      `json:"destination_port_range_last"`
	ValidFromRevision             int64      `json:"valid_from_revision"`
	ValidFrom                     time.Time  `json:"valid_from"`
	ValidToRevision               *int64     `json:"valid_to_revision"`
	ValidTo                       *time.Time `json:"valid_to"`
	ExpiresAt                     *time.Time `json:"expires_at"`
}

type accessGraphHistoryData struct {
	WorkspaceID     string                          `json:"workspace_id"`
	NetworkID       string                          `json:"network_id"`
	At              time.Time                       `json:"at"`
	RecordedSince   *time.Time                      `json:"recorded_since"`
	NetworkRevision *int64                          `json:"network_revision"`
	Snapshot        *accessGraphHistorySnapshotItem `json:"snapshot"`
	Edges           []accessGraphHistoryEdgeItem    `json:"edges"`
}

type accessGraphHistoryEnvelope struct {
	Data          accessGraphHistoryData `json:"data"`
	NextPageToken string                 `json:"next_page_token,omitempty"`
	CorrelationID string                 `json:"correlation_id"`
}

func optionalPublicText(id publicid.ID) *string {
	if id == (publicid.ID{}) {
		return nil
	}
	value := id.String()
	return &value
}

func optionalTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	utc := value.UTC()
	return &utc
}

func newAccessGraphHistoryEdgeItem(edge ledger.Edge) accessGraphHistoryEdgeItem {
	item := accessGraphHistoryEdgeItem{EdgeID: edge.Key.String(), AccessRuleID: edge.AccessRuleID.String(),
		SelectorKind: edge.SelectorKind, SourceDeviceID: edge.SourceDeviceID.String(),
		SourceHostname: optionalText(edge.SourceHostname), DestinationHostname: optionalText(edge.DestinationHostname),
		DestinationImportedResourceID: optionalPublicText(edge.ImportedResourceID),
		TrustContractID:               optionalPublicText(edge.TrustContractID),
		DestinationResourceID:         optionalPublicText(edge.ResourceID),
		DestinationResourceGroupID:    optionalPublicText(edge.ResourceGroupID),
		SourceSelectorKind:            optionalText(edge.SourceSelectorKind),
		SourceSelectorID:              optionalPublicText(edge.SourceSelectorID),
		DestinationSelectorKind:       optionalText(edge.DestinationSelectorKind),
		DestinationSelectorID:         optionalPublicText(edge.DestinationSelectorID),
		Protocol:                      edge.Protocol.String(), PortFirst: make([]int, 0, len(edge.Ports)),
		PortLast: make([]int, 0, len(edge.Ports)), ValidFromRevision: edge.ValidFromRevision,
		ValidFrom: edge.ValidFrom.UTC(), ValidTo: optionalTime(edge.ValidTo), ExpiresAt: optionalTime(edge.ExpiresAt)}
	if edge.DestinationDeviceID != (node.ID{}) {
		value := edge.DestinationDeviceID.String()
		item.DestinationDeviceID = &value
	}
	if edge.ValidToRevision > 0 {
		revision := edge.ValidToRevision
		item.ValidToRevision = &revision
	}
	for _, portRange := range edge.Ports {
		item.PortFirst = append(item.PortFirst, int(portRange.First()))
		item.PortLast = append(item.PortLast, int(portRange.Last()))
	}
	return item
}

func newAccessGraphHistoryData(scope network.Scope, page ledger.Page) accessGraphHistoryData {
	data := accessGraphHistoryData{WorkspaceID: scope.WorkspaceID().String(), NetworkID: scope.NetworkID().String(),
		At: page.At.UTC(), RecordedSince: optionalTime(page.RecordedSince),
		Edges: make([]accessGraphHistoryEdgeItem, 0, len(page.Edges))}
	if page.NetworkRevision > 0 {
		revision := page.NetworkRevision
		data.NetworkRevision = &revision
	}
	if snapshot := page.Snapshot; snapshot != nil {
		data.Snapshot = &accessGraphHistorySnapshotItem{ID: snapshot.ID.String(),
			NetworkRevision: snapshot.NetworkRevision, EffectiveAt: snapshot.EffectiveAt.UTC(),
			RecordedAt: snapshot.RecordedAt.UTC(), EdgeCount: snapshot.EdgeCount, Digest: snapshot.Digest}
	}
	for _, edge := range page.Edges {
		data.Edges = append(data.Edges, newAccessGraphHistoryEdgeItem(edge))
	}
	return data
}

func (browser *BrowserManagement) readAccessGraphHistory(ctx context.Context, response *browserManagementResponse,
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
	query, err := parseAccessGraphHistoryQuery(request.URL.RawQuery, scope)
	if err != nil {
		fail(*invalidManagementRequest())
		return nil
	}
	page, err := browser.history.Read(ctx, session, scope, query)
	if err != nil {
		value := internalManagementError()
		switch {
		case errors.Is(err, ledger.ErrForbidden):
			value = managementError{Status: http.StatusForbidden, Code: "access_graph_history_forbidden",
				Message: "Access Graph history is unavailable for this scope"}
		case errors.Is(err, ledger.ErrInvalidRequest):
			value = *invalidManagementRequest()
		case errors.Is(err, ledger.ErrUnavailable), errors.Is(err, context.Canceled),
			errors.Is(err, context.DeadlineExceeded):
			value = managementError{Status: http.StatusServiceUnavailable, Code: "access_graph_history_unavailable",
				Message: "Access Graph history is temporarily unavailable", Retryable: true}
		}
		fail(value)
		return nil
	}
	if page.Scope != scope || page.At.IsZero() || len(page.Edges) > query.Limit {
		fail(internalManagementError())
		return nil
	}
	next := ""
	if !page.Next.IsZero() {
		next, err = encodeAccessGraphHistoryPageToken(scope, query, page.At, page.Next)
		if err != nil {
			return ErrBrowserManagementUnavailable
		}
	}
	writeManagementJSON(ctx, browser.management.logger, response, http.StatusOK,
		accessGraphHistoryEnvelope{Data: newAccessGraphHistoryData(scope, page), NextPageToken: next,
			CorrelationID: correlationID.String()})
	return nil
}
