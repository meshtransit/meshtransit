package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/audit/exportformat"
	"github.com/meshtransit/meshtransit/internal/audit/history"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const (
	auditEventExportOperation = "audit_event_export"
	maximumAuditExportQuery   = 512
)

// AuditExporter assembles a bounded export of whole audit streams.
type AuditExporter interface {
	Export(context.Context, accountsession.Session, history.ExportQuery) (history.Export, error)
}

type auditEventExportPath struct {
	workspaceID workspace.ID
}

// parseAuditEventExportPath matches GET /api/v1/workspaces/{ws}/audit-events/export.
func parseAuditEventExportPath(request *http.Request) (auditEventExportPath, bool) {
	if request == nil || request.URL == nil || request.URL.RawPath != "" {
		return auditEventExportPath{}, false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, "/"), "/")
	if len(segments) != 6 || segments[0] != "api" || segments[1] != "v1" ||
		segments[2] != "workspaces" || segments[4] != "audit-events" || segments[5] != "export" {
		return auditEventExportPath{}, false
	}
	workspaceID, err := workspace.ParseID(segments[3])
	if err != nil || workspaceID.String() != segments[3] {
		return auditEventExportPath{}, false
	}
	return auditEventExportPath{workspaceID: workspaceID}, true
}

// isAuditEventExportRead admits only the GET export.
func isAuditEventExportRead(request *http.Request) bool {
	_, ok := parseAuditEventExportPath(request)
	return ok && request.Method == http.MethodGet
}

type auditExportRequest struct {
	query  history.ExportQuery
	format string
}

// parseAuditEventExportQuery accepts format (json or csv, default json),
// network_id, since and until, each at most once and never empty.
func parseAuditEventExportQuery(raw string, workspaceID workspace.ID) (auditExportRequest, bool) {
	if len(raw) > maximumAuditExportQuery {
		return auditExportRequest{}, false
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return auditExportRequest{}, false
	}
	for key, entries := range values {
		switch key {
		case "format", "network_id", "since", "until":
		default:
			return auditExportRequest{}, false
		}
		if len(entries) != 1 || entries[0] == "" {
			return auditExportRequest{}, false
		}
	}
	request := auditExportRequest{query: history.ExportQuery{WorkspaceID: workspaceID}, format: "json"}
	if value := values.Get("format"); value != "" {
		if value != "json" && value != "csv" {
			return auditExportRequest{}, false
		}
		request.format = value
	}
	if value := values.Get("network_id"); value != "" {
		networkID, err := network.ParseID(value)
		if err != nil || networkID.String() != value {
			return auditExportRequest{}, false
		}
		request.query.NetworkID = networkID
	}
	for key, target := range map[string]*time.Time{"since": &request.query.Since, "until": &request.query.Until} {
		if value := values.Get(key); value != "" {
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return auditExportRequest{}, false
			}
			*target = parsed.UTC()
		}
	}
	return request, true
}

func (handler *ManagementHandler) exportAuditEvents(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path auditEventExportPath, session accountsession.Session) string {
	if nilContinuationDependency(handler.auditExports) {
		failure := managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Activity export is temporarily unavailable", Retryable: true}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	parsed, valid := parseAuditEventExportQuery(request.URL.RawQuery, path.workspaceID)
	if !valid {
		failure := *invalidManagementRequest()
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	export, err := handler.auditExports.Export(ctx, session, parsed.query)
	if err != nil {
		failure := classifyAuditExportError(err)
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	var body bytes.Buffer
	contentType, extension := "application/json", "json"
	if parsed.format == "csv" {
		contentType, extension = "text/csv; charset=utf-8", "csv"
		err = exportformat.WriteCSV(&body, export)
	} else {
		err = exportformat.WriteJSON(&body, export)
	}
	if err != nil {
		failure := managementError{Status: http.StatusInternalServerError, Code: "internal_failure",
			Message: "the request could not be completed"}
		writeManagementError(ctx, handler.logger, response, correlationID, failure)
		return failure.Code
	}
	name := "meshtransit-audit-" + path.workspaceID.String() + "-" +
		export.GeneratedAt.UTC().Format("20060102T150405Z") + "." + extension
	header := response.Header()
	header.Set("Content-Type", contentType)
	header.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	header.Set("Cache-Control", "no-store")
	header.Set("X-Correlation-Id", correlationID.String())
	response.WriteHeader(http.StatusOK)
	if _, err := response.Write(body.Bytes()); err != nil && handler.logger != nil {
		handler.logger.DebugContext(ctx, "audit export write failed", "error", err)
	}
	return "success"
}

func classifyAuditExportError(err error) managementError {
	switch {
	case errors.Is(err, history.ErrExportTooLarge):
		return managementError{Status: http.StatusUnprocessableEntity, Code: "audit_export_too_large",
			Message: "This range holds more evidence than one export. Choose a shorter range."}
	case errors.Is(err, history.ErrForbidden):
		return managementError{Status: http.StatusForbidden, Code: "permission_denied",
			Message: "You cannot export activity in this Workspace or Network"}
	case errors.Is(err, history.ErrInvalid):
		return *invalidManagementRequest()
	default:
		return managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Activity export is temporarily unavailable", Retryable: true}
	}
}
