package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	"github.com/meshtransit/meshtransit/core/internal/domain/audit/history"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

const (
	auditEventListOperation = "audit_event_list"
	// maximumAuditEventQueryBytes bounds the listing query string.
	maximumAuditEventQueryBytes = 2048
)

// AuditHistoryReader lists one page of a Workspace's audit history.
type AuditHistoryReader interface {
	List(context.Context, accountsession.Session, history.Query) (history.Page, error)
}

type auditEventListPath struct {
	workspaceID workspace.ID
}

// parseAuditEventListPath matches GET /api/v1/workspaces/{ws}/audit-events.
// The query string is validated separately by parseAuditEventListQuery.
func parseAuditEventListPath(request *http.Request) (auditEventListPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" {
		return auditEventListPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) != 5 || segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "workspaces" || segments[4] != "audit-events" {
		return auditEventListPath{}, false
	}
	workspaceID, err := workspace.ParseID(segments[3])
	if err != nil || workspaceID.String() != segments[3] {
		return auditEventListPath{}, false
	}
	return auditEventListPath{workspaceID: workspaceID}, true
}

// isAuditEventListRead admits only the GET listing.
func isAuditEventListRead(request *http.Request) bool {
	_, ok := parseAuditEventListPath(request)
	return ok && request.Method == http.MethodGet
}

var auditEventQueryKeys = map[string]bool{
	"network_id": true, "since": true, "until": true, "target_kind": true, "target_id": true,
	"actor_id": true, "actor_kind": true, "action": true, "result": true, "correlation_id": true,
	"change_id": true, "page_size": true, "page_token": true,
}

// parseAuditEventListQuery accepts each known key at most once and never
// empty. target_kind is a comma-separated list; times are RFC 3339.
func parseAuditEventListQuery(raw string, workspaceID workspace.ID) (history.Query, bool) {
	if len(raw) > maximumAuditEventQueryBytes {
		return history.Query{}, false
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return history.Query{}, false
	}
	for key, entries := range values {
		if !auditEventQueryKeys[key] || len(entries) != 1 || entries[0] == "" {
			return history.Query{}, false
		}
	}
	query := history.Query{WorkspaceID: workspaceID, ActorKind: values.Get("actor_kind"),
		Action: values.Get("action"), Result: values.Get("result")}
	ids := []struct {
		key    string
		target *publicid.ID
	}{
		{"target_id", &query.TargetID}, {"actor_id", &query.ActorID},
		{"correlation_id", &query.CorrelationID}, {"change_id", &query.ChangeID},
	}
	for _, field := range ids {
		if value := values.Get(field.key); value != "" {
			id, err := publicid.Parse(value)
			if err != nil || id.String() != value {
				return history.Query{}, false
			}
			*field.target = id
		}
	}
	if value := values.Get("network_id"); value != "" {
		networkID, err := network.ParseID(value)
		if err != nil || networkID.String() != value {
			return history.Query{}, false
		}
		query.NetworkID = networkID
	}
	for key, target := range map[string]*time.Time{"since": &query.Since, "until": &query.Until} {
		if value := values.Get(key); value != "" {
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return history.Query{}, false
			}
			*target = parsed.UTC()
		}
	}
	if value := values.Get("target_kind"); value != "" {
		query.TargetKinds = strings.Split(value, ",")
	}
	if value := values.Get("page_size"); value != "" {
		size, err := strconv.Atoi(value)
		if err != nil || size < 1 || size > history.MaximumPageSize || strconv.Itoa(size) != value {
			return history.Query{}, false
		}
		query.PageSize = size
	}
	if value := values.Get("page_token"); value != "" {
		cursor, err := history.ParseCursor(value)
		if err != nil {
			return history.Query{}, false
		}
		query.Cursor = &cursor
	}
	return query, true
}

type auditEventListResponse struct {
	Data struct {
		Records       []audit.Record    `json:"records"`
		Actors        map[string]string `json:"actors"`
		NextPageToken *string           `json:"next_page_token"`
		Since         string            `json:"since"`
		Until         string            `json:"until"`
	} `json:"data"`
	CorrelationID string `json:"correlation_id"`
}

func (handler *ManagementHandler) listAuditEvents(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path auditEventListPath, session accountsession.Session) string {
	if nilContinuationDependency(handler.auditHistory) {
		failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Activity is temporarily unavailable", Retryable: true}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	query, valid := parseAuditEventListQuery(request.URL.RawQuery, path.workspaceID)
	if !valid {
		failure := *invalidManagementRequest()
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	page, err := handler.auditHistory.List(ctx, session, query)
	if err != nil {
		failure := classifyAuditHistoryError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	var output auditEventListResponse
	output.Data.Records = page.Records
	if output.Data.Records == nil {
		output.Data.Records = []audit.Record{}
	}
	output.Data.Actors = page.Actors
	if output.Data.Actors == nil {
		output.Data.Actors = map[string]string{}
	}
	if page.Next != nil {
		token := page.Next.Token()
		output.Data.NextPageToken = &token
	}
	output.Data.Since = page.Since.UTC().Format(time.RFC3339Nano)
	output.Data.Until = page.Until.UTC().Format(time.RFC3339Nano)
	output.CorrelationID = correlationID.String()
	response.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(ctx, handler.logger, response, http.StatusOK, output)
	return "success"
}

func classifyAuditHistoryError(err error) managementError {
	switch {
	case errors.Is(err, history.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot view activity in this Workspace or Network"}
	case errors.Is(err, history.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Activity is temporarily unavailable", Retryable: true}
	}
}
