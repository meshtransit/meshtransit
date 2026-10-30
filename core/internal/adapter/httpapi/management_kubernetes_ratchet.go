package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

// changeKubernetesTokenRatchet suspends a replica's pod token ratchet for a
// while, or resumes it (kubernetes_cluster.approve, K1d d2b); Core checks
// the grant.
func (handler *ManagementHandler) changeKubernetesTokenRatchet(ctx context.Context,
	response http.ResponseWriter, request *http.Request, correlationID publicid.ID, path kubernetesClusterPath,
	session accountsession.Session, fail func(managementError) string) string {
	suspends := path.operation == kubernetesRatchetSuspendOperation
	change := kubecluster.RatchetChange{Session: session, Scope: path.scope, ClusterID: path.clusterID,
		DeviceID: path.deviceID, CorrelationID: correlationID}
	if suspends {
		var body struct {
			DurationSeconds int64  `json:"duration_seconds"`
			Reason          string `json:"reason"`
			ChangeRef       string `json:"change_ref"`
		}
		if !readDeviceGroupBody(response, request, &body) || body.DurationSeconds <= 0 ||
			body.DurationSeconds > int64(kubecluster.MaximumRatchetSuspension/time.Second) {
			return fail(*invalidManagementRequest())
		}
		change.Duration = time.Duration(body.DurationSeconds) * time.Second
		change.Reason, change.ChangeRef = body.Reason, body.ChangeRef
	} else {
		var body struct {
			Reason    string `json:"reason"`
			ChangeRef string `json:"change_ref"`
		}
		if !readDeviceGroupBody(response, request, &body) {
			return fail(*invalidManagementRequest())
		}
		change.Reason, change.ChangeRef = body.Reason, body.ChangeRef
	}
	result, err := handler.kubernetesClusters.ChangeTokenRatchet(ctx, change)
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	if result.Changed {
		// After commit: a suspension lets a copy of the replica's Secret
		// connect without a pod token, so who did it and its change reference go
		// to the SIEM; the reason stays in the audit event.
		event, message := "kubernetes_gateway_token_ratchet_resumed", "kubernetes gateway token ratchet resumed"
		if suspends {
			event, message = "kubernetes_gateway_token_ratchet_suspended", "kubernetes gateway token ratchet suspended"
		}
		handler.logger.LogAttrs(ctx, slog.LevelWarn, message, slog.String("event", event),
			slog.String("principal_id", session.PrincipalID().String()),
			slog.String("workspace_id", path.scope.WorkspaceID().String()),
			slog.String("network_id", path.scope.NetworkID().String()),
			slog.String("cluster_id", path.clusterID.String()), slog.String("device_id", path.deviceID.String()),
			slog.String("suspended_until", managementTimeOrEmpty(result.SuspendedUntil)),
			slog.String("change_ref", change.ChangeRef),
			slog.String("correlation_id", correlationID.String()))
	}
	writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
		Changed        bool    `json:"changed"`
		SuspendedUntil *string `json:"ratchet_suspended_until"`
	}{result.Changed, optionalManagementTime(result.SuspendedUntil)})
	return "success"
}

func managementTimeOrEmpty(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	return managementTime(at)
}
