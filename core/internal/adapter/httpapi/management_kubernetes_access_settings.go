package httpapi

import (
	"context"
	"net/http"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

// isKubernetesAccessSettingsWrite admits the PUT of a cluster's access
// settings (K2d d4b).
func isKubernetesAccessSettingsWrite(request *http.Request) bool {
	path, ok := parseKubernetesClusterPath(request)
	return ok && request.Method == http.MethodPut && path.operation == kubernetesAccessSettingsReplaceOperation
}

type kubernetesAccessSettingsBody struct {
	AccessContact string  `json:"access_contact"`
	Version       int64   `json:"version"`
	UpdatedAt     *string `json:"updated_at"`
}

func newKubernetesAccessSettingsBody(settings kubecluster.AccessSettings) kubernetesAccessSettingsBody {
	return kubernetesAccessSettingsBody{AccessContact: settings.AccessContact, Version: settings.Version,
		UpdatedAt: optionalManagementTime(settings.UpdatedAt)}
}

// serveKubernetesAccessSettings reads (network.read) or replaces
// (kubernetes_cluster.manage, If-Match: its version, "0" before any) a
// cluster's access contact, which its gateways name when an access profile
// refuses a request (K2 §29.1).
func (handler *ManagementHandler) serveKubernetesAccessSettings(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path kubernetesClusterPath, session accountsession.Session,
	fail func(managementError) string) string {
	manager := handler.kubernetesClusters
	if path.operation == kubernetesAccessSettingsReadOperation {
		settings, err := manager.ReadAccessSettings(ctx, session, path.scope, path.clusterID)
		if err != nil {
			return fail(classifyKubernetesClusterError(err))
		}
		response.Header().Set("ETag", trustVersionETag(settings.Version))
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK,
			newKubernetesAccessSettingsBody(settings))
		return "success"
	}
	expected, precondition := parseTrustIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		return fail(*precondition)
	}
	var body struct {
		AccessContact *string `json:"access_contact"`
	}
	if !readDeviceGroupBody(response, request, &body) || body.AccessContact == nil ||
		!kubecluster.ValidAccessContact(*body.AccessContact) {
		return fail(*invalidManagementRequest())
	}
	result, err := manager.ReplaceAccessSettings(ctx, kubecluster.AccessSettingsReplacement{Session: session,
		Scope: path.scope, ClusterID: path.clusterID, ExpectedVersion: expected,
		AccessContact: *body.AccessContact, CorrelationID: correlationID})
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	response.Header().Set("ETag", trustVersionETag(result.Settings.Version))
	writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
		kubernetesAccessSettingsBody
		Changed bool `json:"changed"`
	}{newKubernetesAccessSettingsBody(result.Settings), result.Changed})
	return "success"
}
