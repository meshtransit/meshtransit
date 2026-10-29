package httpapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	// kubernetesExportFormat names the file meshctl kube audit-check reads.
	kubernetesExportFormat = "meshtransit-kube-operations/v1"
	// kubernetesExportMaximumBytes bounds one export's body (Q132).
	kubernetesExportMaximumBytes = 64 << 20
	// kubernetesExportDeadline bounds one export from start to end.
	kubernetesExportDeadline = 120 * time.Second
	// kubernetesExportWriteDeadline bounds each write to a slow client.
	kubernetesExportWriteDeadline = 30 * time.Second
	// kubernetesExportsPerReplica bounds the exports one API replica runs
	// at once, whatever their Workspace.
	kubernetesExportsPerReplica = 3
	// kubernetesExportSettle keeps an export's records off the last minute:
	// gateways' records still committing there would be missed, and
	// audit-check would report them missing (review d1d-b M1).
	kubernetesExportSettle = time.Minute
)

// kubernetesExportSlots admits at most one export a Workspace and
// kubernetesExportsPerReplica in all on this replica.
type kubernetesExportSlots struct {
	mutex      sync.Mutex
	workspaces map[string]bool
}

func newKubernetesExportSlots() *kubernetesExportSlots {
	return &kubernetesExportSlots{workspaces: map[string]bool{}}
}

func (slots *kubernetesExportSlots) take(workspace string) (func(), bool) {
	slots.mutex.Lock()
	defer slots.mutex.Unlock()
	if slots.workspaces[workspace] || len(slots.workspaces) >= kubernetesExportsPerReplica {
		return nil, false
	}
	slots.workspaces[workspace] = true
	return func() {
		slots.mutex.Lock()
		defer slots.mutex.Unlock()
		delete(slots.workspaces, workspace)
	}, true
}

// kubernetesExportFile is the file's header: what meshctl reads, then the
// records, then complete: true when every record came (K1d §3.2).
type kubernetesExportFile struct {
	Format                 string   `json:"format"`
	ClusterID              string   `json:"cluster_id"`
	GatewayNamespace       string   `json:"gateway_namespace"`
	PrivilegedGroups       []string `json:"privileged_groups"`
	SecretResources        []string `json:"secret_resources"`
	AuditSettingsVersion   int64    `json:"audit_settings_version"`
	AuditSettingsUpdatedAt *string  `json:"audit_settings_updated_at"`
	From                   string   `json:"from"`
	To                     string   `json:"to"`
	RecordsFrom            string   `json:"records_from"`
	RecordsTo              string   `json:"records_to"`
}

type kubernetesExportRecordBody struct {
	AuditID      string   `json:"audit_id"`
	ReceivedAt   string   `json:"received_at"`
	Class        string   `json:"class"`
	Groups       []string `json:"groups"`
	Verb         string   `json:"verb"`
	APIGroup     string   `json:"api_group"`
	Resource     string   `json:"resource"`
	Subresource  string   `json:"subresource"`
	Namespace    string   `json:"namespace"`
	Name         string   `json:"name"`
	Impersonated string   `json:"impersonated"`
	Status       int      `json:"status"`
}

// countingWriter counts what reaches the client and refuses past a cap.
type countingWriter struct {
	writer  *bufio.Writer
	written int
}

var errKubernetesExportTooLarge = errors.New("kubernetes export: over its byte cap")

func (writer *countingWriter) Write(data []byte) (int, error) {
	if writer.written+len(data) > kubernetesExportMaximumBytes {
		return 0, errKubernetesExportTooLarge
	}
	written, err := writer.writer.Write(data)
	writer.written += written
	return written, err
}

// exportKubernetesOperations streams a cluster's operations as meshctl
// kube audit-check reads them (audit.export, K1d d1d-b). Refusals come
// before the body; a failure in the body writes a token no JSON reader
// accepts inside the open records and cuts the connection, so a cut file
// is never read as a whole one.
func (handler *ManagementHandler) exportKubernetesOperations(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path kubernetesClusterPath, session accountsession.Session,
	fail func(managementError) string) string {
	release, admitted := handler.kubernetesExports.take(path.scope.WorkspaceID().String())
	if !admitted {
		return fail(managementError{Status: http.StatusTooManyRequests, Code: "export_busy",
			Message:   "Another export of this Workspace is running, or this replica runs its most; try again",
			Retryable: true})
	}
	defer release()
	from, to, settled := resolveKubernetesExportRange(path.operations, time.Now())
	if !settled {
		return fail(managementError{Status: http.StatusUnprocessableEntity, Code: "range_not_settled",
			Message: "An export ends at least 6 minutes ago: records of the last minutes may still be committing"})
	}
	query := kubecluster.ExportQuery{Session: session, Scope: path.scope, ClusterID: path.clusterID, From: from, To: to}
	manager := handler.kubernetesClusters
	// Refusals come within the request's own timeout.
	header, err := manager.BeginExport(ctx, query)
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	if header.Count > kubecluster.MaximumExportRecords {
		return fail(managementError{Status: http.StatusUnprocessableEntity, Code: "range_too_large",
			Message: "The range holds more than 200000 operations; export a shorter one"})
	}
	if header.GatewayNamespace == "" {
		return fail(managementError{Status: http.StatusConflict, Code: "gateway_namespace_unknown",
			Message: "The cluster has no signing trust yet: its gateway's namespace is unknown"})
	}
	recordsFrom, recordsTo := query.RecordsRange()
	file := kubernetesExportFile{Format: kubernetesExportFormat, ClusterID: path.clusterID.String(),
		GatewayNamespace: header.GatewayNamespace, PrivilegedGroups: nonNilStrings(header.Settings.PrivilegedGroups),
		SecretResources: nonNilStrings(header.Settings.SecretResources), AuditSettingsVersion: header.Settings.Version,
		AuditSettingsUpdatedAt: optionalManagementTime(header.Settings.UpdatedAt), From: managementTime(from),
		To: managementTime(to), RecordsFrom: managementTime(recordsFrom), RecordsTo: managementTime(recordsTo)}
	opening, err := json.Marshal(file)
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	// The body runs past the request's timeout, up to its own deadline; a
	// client that leaves cancels it (review d1d-b H1).
	exportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), kubernetesExportDeadline)
	defer cancel()
	stop := context.AfterFunc(ctx, func() {
		if errors.Is(ctx.Err(), context.Canceled) {
			cancel()
		}
	})
	defer stop()
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Content-Disposition", `attachment; filename="kubernetes-operations.json"`)
	controller := http.NewResponseController(response)
	_ = controller.SetWriteDeadline(time.Now().Add(kubernetesExportWriteDeadline))
	response.WriteHeader(http.StatusOK)
	buffered := bufio.NewWriterSize(response, 64<<10)
	out := &countingWriter{writer: buffered}
	count, err := handler.streamKubernetesExport(exportCtx, controller, buffered, out, opening, query)
	if err == nil {
		_, err = out.Write([]byte(`],"complete":true}` + "\n"))
	}
	if err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		// Inside the open records array: no reader takes the file as whole.
		_, _ = buffered.WriteString("\n!export_failed " + kubernetesExportFailure(err) + "\n")
		_ = buffered.Flush()
		// Records already sent are evidence too (review d1d-b M3).
		handler.logger.LogAttrs(exportCtx, slog.LevelWarn, "kubernetes operations export failed",
			slog.String("event", "kubernetes_operations_export_failed"),
			slog.String("principal_id", session.PrincipalID().String()),
			slog.String("workspace_id", path.scope.WorkspaceID().String()),
			slog.String("network_id", path.scope.NetworkID().String()),
			slog.String("cluster_id", path.clusterID.String()), slog.String("from", managementTime(from)),
			slog.String("to", managementTime(to)), slog.Int("records", count),
			slog.String("failure", kubernetesExportFailure(err)),
			slog.String("correlation_id", correlationID.String()), slog.String("error", err.Error()))
		panic(http.ErrAbortHandler)
	}
	// Who exported which records is evidence: the log goes to the SIEM, as
	// audit-exports does (Q155).
	handler.logger.LogAttrs(exportCtx, slog.LevelInfo, "kubernetes operations exported",
		slog.String("event", "kubernetes_operations_exported"),
		slog.String("principal_id", session.PrincipalID().String()),
		slog.String("workspace_id", path.scope.WorkspaceID().String()),
		slog.String("network_id", path.scope.NetworkID().String()),
		slog.String("cluster_id", path.clusterID.String()), slog.String("from", managementTime(from)),
		slog.String("to", managementTime(to)), slog.Int("records", count),
		slog.String("correlation_id", correlationID.String()))
	return "success"
}

func (handler *ManagementHandler) streamKubernetesExport(ctx context.Context, controller *http.ResponseController,
	buffered *bufio.Writer, out *countingWriter, opening []byte, query kubecluster.ExportQuery) (int, error) {
	// The header object, reopened to append the records.
	if _, err := out.Write(append(opening[:len(opening)-1], []byte(`,"records":[`)...)); err != nil {
		return 0, err
	}
	encoder := json.NewEncoder(out)
	count := 0
	var after kubecluster.PageCursor
	for {
		_ = controller.SetWriteDeadline(time.Now().Add(kubernetesExportWriteDeadline))
		records, err := handler.kubernetesClusters.ExportPage(ctx, query, after)
		if err != nil {
			return count, err
		}
		for _, record := range records {
			if count == kubecluster.MaximumExportRecords {
				return count, errKubernetesExportTooLarge
			}
			if count > 0 {
				if _, err := out.Write([]byte{','}); err != nil {
					return count, err
				}
			}
			if err := encoder.Encode(kubernetesExportRecordBody{AuditID: record.AuditID.String(),
				ReceivedAt: managementTime(record.ReceivedAt), Class: record.Class, Groups: record.Groups,
				Verb: record.Verb, APIGroup: record.APIGroup, Resource: record.Resource,
				Subresource: record.Subresource, Namespace: record.Namespace, Name: record.Name,
				Impersonated: record.Impersonated, Status: record.Status}); err != nil {
				return count, err
			}
			count++
			after = kubecluster.PageCursor{At: record.ReceivedAt, ID: record.AuditID}
		}
		_ = controller.SetWriteDeadline(time.Now().Add(kubernetesExportWriteDeadline))
		if err := buffered.Flush(); err != nil {
			return count, err
		}
		if len(records) < kubecluster.ExportPageSize {
			return count, nil
		}
	}
}

// resolveKubernetesExportRange fills a missing range (the day up to 6
// minutes ago) and reports whether its records, 5 minutes past to, end a
// settled minute ago.
func resolveKubernetesExportRange(query kubernetesOperationQuery, now time.Time) (time.Time, time.Time, bool) {
	latest := now.UTC().Add(-kubecluster.ExportClockWindow - kubernetesExportSettle).Truncate(time.Second)
	if query.to.IsZero() {
		query.to = latest
	}
	from, to := query.resolve(now)
	return from, to, !to.After(latest)
}

func kubernetesExportFailure(err error) string {
	switch {
	case errors.Is(err, errKubernetesExportTooLarge):
		return "too_large"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	default:
		return "unavailable"
	}
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
