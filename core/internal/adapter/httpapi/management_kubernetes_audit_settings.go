package httpapi

import (
	"context"
	"net/http"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

// isKubernetesAuditSettingsWrite admits the PUT of a cluster's audit
// settings (K1d d1d).
func isKubernetesAuditSettingsWrite(request *http.Request) bool {
	path, ok := parseKubernetesClusterPath(request)
	return ok && request.Method == http.MethodPut && path.operation == kubernetesAuditSettingsReplaceOperation
}

type kubernetesAuditSettingsBody struct {
	PrivilegedGroups []string `json:"privileged_groups"`
	SecretResources  []string `json:"secret_resources"`
	Version          int64    `json:"version"`
	UpdatedAt        *string  `json:"updated_at"`
}

func newKubernetesAuditSettingsBody(settings kubecluster.AuditSettings) kubernetesAuditSettingsBody {
	body := kubernetesAuditSettingsBody{PrivilegedGroups: settings.PrivilegedGroups,
		SecretResources: settings.SecretResources, Version: settings.Version,
		UpdatedAt: optionalManagementTime(settings.UpdatedAt)}
	if body.PrivilegedGroups == nil {
		body.PrivilegedGroups = []string{}
	}
	if body.SecretResources == nil {
		body.SecretResources = []string{}
	}
	return body
}

// serveKubernetesAuditSettings reads (network.read) or replaces
// (kubernetes_cluster.manage and audit.export, If-Match: its version, "0"
// before any) a cluster's audit settings (K1d d1d, Q133).
func (handler *ManagementHandler) serveKubernetesAuditSettings(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path kubernetesClusterPath, session accountsession.Session,
	fail func(managementError) string) string {
	manager := handler.kubernetesClusters
	if path.operation == kubernetesAuditSettingsReadOperation {
		settings, err := manager.ReadAuditSettings(ctx, session, path.scope, path.clusterID)
		if err != nil {
			return fail(classifyKubernetesClusterError(err))
		}
		response.Header().Set("ETag", trustVersionETag(settings.Version))
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK,
			newKubernetesAuditSettingsBody(settings))
		return "success"
	}
	expected, precondition := parseTrustIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		return fail(*precondition)
	}
	var body struct {
		PrivilegedGroups *[]string `json:"privileged_groups"`
		SecretResources  *[]string `json:"secret_resources"`
	}
	if !readDeviceGroupBody(response, request, &body) || body.PrivilegedGroups == nil || body.SecretResources == nil {
		return fail(*invalidManagementRequest())
	}
	result, err := manager.ReplaceAuditSettings(ctx, kubecluster.AuditSettingsReplacement{Session: session,
		Scope: path.scope, ClusterID: path.clusterID, ExpectedVersion: expected,
		PrivilegedGroups: *body.PrivilegedGroups, SecretResources: *body.SecretResources,
		CorrelationID: correlationID})
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	response.Header().Set("ETag", trustVersionETag(result.Settings.Version))
	writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
		kubernetesAuditSettingsBody
		Changed bool `json:"changed"`
	}{newKubernetesAuditSettingsBody(result.Settings), result.Changed})
	return "success"
}
