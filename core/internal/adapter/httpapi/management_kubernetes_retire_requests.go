package httpapi

import (
	"context"
	"log/slog"
	"net/http"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

// kubernetesCARetireRequestBody is a request to retire a CA as approvers
// and audit readers read it (K1d d2a).
type kubernetesCARetireRequestBody struct {
	RequestID   string  `json:"request_id"`
	CAID        string  `json:"ca_id"`
	CAVersion   int64   `json:"ca_version"`
	Reason      string  `json:"reason"`
	ChangeRef   string  `json:"change_ref"`
	Note        string  `json:"note"`
	RequestedBy *string `json:"requested_by_principal_id"`
	State       string  `json:"state"`
	Refusal     *string `json:"refusal"`
	CreatedAt   string  `json:"created_at"`
	ExpiresAt   string  `json:"expires_at"`
	FinishedAt  *string `json:"finished_at"`
}

func newKubernetesCARetireRequestBody(request kubecluster.CARetireRequest) kubernetesCARetireRequestBody {
	body := kubernetesCARetireRequestBody{RequestID: request.ID.String(), CAID: request.CAID.String(),
		CAVersion: request.CAVersion, Reason: request.Reason, ChangeRef: request.ChangeRef, Note: request.Note,
		State: request.State, CreatedAt: managementTime(request.CreatedAt),
		ExpiresAt: managementTime(request.ExpiresAt), FinishedAt: optionalManagementTime(request.FinishedAt)}
	if request.RequestedBy.IsValid() {
		by := request.RequestedBy.String()
		body.RequestedBy = &by
	}
	if request.Refusal != "" {
		refusal := request.Refusal
		body.Refusal = &refusal
	}
	return body
}

// serveKubernetesCARetireRequests lists a cluster's requests to retire a CA
// (approve or audit.read) or records one (approve), which the CA worker
// carries out; Core checks the grants.
func (handler *ManagementHandler) serveKubernetesCARetireRequests(ctx context.Context,
	response http.ResponseWriter, request *http.Request, correlationID publicid.ID, path kubernetesClusterPath,
	session accountsession.Session, fail func(managementError) string) string {
	manager := handler.kubernetesClusters
	if path.operation == kubernetesCARetireListOperation {
		page, err := manager.ListCARetireRequests(ctx, kubecluster.PageQuery{Session: session, Scope: path.scope,
			ClusterID: path.clusterID, After: path.page.after, Limit: path.page.limit})
		if err != nil {
			return fail(classifyKubernetesClusterError(err))
		}
		bodies := make([]kubernetesCARetireRequestBody, len(page.Requests))
		for index, retire := range page.Requests {
			bodies[index] = newKubernetesCARetireRequestBody(retire)
		}
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
			Requests      []kubernetesCARetireRequestBody `json:"ca_retire_requests"`
			NextPageToken string                          `json:"next_page_token,omitempty"`
		}{bodies, encodeKubernetesPageToken(path.scope, path.clusterID, path.operation, page.Next)})
		return "success"
	}
	var body struct {
		CAID      string `json:"ca_id"`
		CAVersion int64  `json:"ca_version"`
		Reason    string `json:"reason"`
		ChangeRef string `json:"change_ref"`
		Note      string `json:"note"`
	}
	if !readDeviceGroupBody(response, request, &body) {
		return fail(*invalidManagementRequest())
	}
	caID, ok := canonicalPublicID(body.CAID)
	if !ok {
		return fail(*invalidManagementRequest())
	}
	result, err := manager.RequestCARetire(ctx, kubecluster.CARetireRequestCommand{Session: session,
		Scope: path.scope, ClusterID: path.clusterID, CAID: caID, CAVersion: body.CAVersion, Reason: body.Reason,
		ChangeRef: body.ChangeRef, Note: body.Note, CorrelationID: correlationID})
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
		// After commit: who asked to retire which CA and why goes to the
		// SIEM; the note stays in Core (it may say more than a log should).
		handler.logger.LogAttrs(ctx, slog.LevelWarn, "kubernetes CA retire requested",
			slog.String("event", "kubernetes_ca_retire_requested"),
			slog.String("principal_id", session.PrincipalID().String()),
			slog.String("workspace_id", path.scope.WorkspaceID().String()),
			slog.String("network_id", path.scope.NetworkID().String()),
			slog.String("cluster_id", path.clusterID.String()),
			slog.String("request_id", result.Request.ID.String()), slog.String("ca_id", caID.String()),
			slog.String("reason", result.Request.Reason), slog.String("change_ref", result.Request.ChangeRef),
			slog.String("correlation_id", correlationID.String()))
	}
	writeKubernetesData(ctx, handler, response, correlationID, status, struct {
		Created bool                          `json:"created"`
		Request kubernetesCARetireRequestBody `json:"request"`
	}{result.Created, newKubernetesCARetireRequestBody(result.Request)})
	return "success"
}
