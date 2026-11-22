package httpapi

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// V1-12 step 1e: a cluster's trust mode, its install tokens and the
// administrator's actions on an install-token trust (design §3.2–3.4).
//
//	GET   kubernetes-clusters/{c}/trust                              mode, trust, install tokens
//	PUT   kubernetes-clusters/{c}/trust-mode                         set (If-Match)
//	POST  kubernetes-clusters/{c}/install-tokens                     issue
//	POST  kubernetes-clusters/{c}/signing-trust/actions/confirm      confirm (If-Match)
//	POST  kubernetes-clusters/{c}/signing-trust/actions/choose       choose a side (If-Match)
//	POST  kubernetes-clusters/{c}/signing-trust/actions/reset        reset (If-Match)
//
// An install token is a join key: it is listed, read and revoked with the
// cluster's join keys.
const (
	kubernetesTrustReadOperation     = "kubernetes_cluster_trust_read"
	kubernetesTrustModeOperation     = "kubernetes_cluster_trust_mode_set"
	kubernetesInstallTokenOperation  = "kubernetes_install_token_issue" //nolint:gosec // a metric operation name, no secret
	kubernetesTrustConfirmOperation  = "kubernetes_signing_trust_confirm"
	kubernetesTrustChooseOperation   = "kubernetes_signing_trust_choose"
	kubernetesTrustResetOperation    = "kubernetes_signing_trust_reset"
	kubernetesTrustActionPathSegment = "signing-trust"
)

// KubernetesTrustManager sets trust modes, issues install tokens and acts on
// install-token trusts; the cluster manager offers it when Core composes
// both (V1-12).
type KubernetesTrustManager interface {
	ReadClusterTrust(context.Context, accountsession.Session, network.Scope,
		kubecluster.ID) (kubecluster.ClusterTrustView, error)
	SetClusterTrustMode(context.Context, kubecluster.TrustModeChange) (kubecluster.TrustModeResult, error)
	IssueInstallToken(context.Context, kubecluster.InstallTokenRequest) (kubecluster.IssuedInstallToken, error)
	ConfirmClusterTrust(context.Context, kubecluster.TrustDecision) (kubecluster.TrustDecisionResult, error)
	ChooseClusterTrust(context.Context, kubecluster.TrustDecision) (kubecluster.TrustDecisionResult, error)
	ResetClusterTrust(context.Context, kubecluster.TrustReset) (kubecluster.TrustDecisionResult, error)
}

// routeKubernetesTrust matches the V1-12 paths after the cluster.
func (path *kubernetesClusterPath) routeKubernetesTrust(rest []string) (map[string]string, bool) {
	switch {
	case len(rest) == 2 && rest[1] == "trust":
		path.methods = restMethods{http.MethodGet}
		return map[string]string{http.MethodGet: kubernetesTrustReadOperation}, true
	case len(rest) == 2 && rest[1] == "trust-mode":
		path.methods = restMethods{http.MethodPut}
		return map[string]string{http.MethodPut: kubernetesTrustModeOperation}, true
	case len(rest) == 2 && rest[1] == "install-tokens":
		path.methods = restMethods{http.MethodPost}
		return map[string]string{http.MethodPost: kubernetesInstallTokenOperation}, true
	case len(rest) == 4 && rest[1] == kubernetesTrustActionPathSegment && rest[2] == "actions":
		operation := map[string]string{"confirm": kubernetesTrustConfirmOperation,
			"choose": kubernetesTrustChooseOperation, "reset": kubernetesTrustResetOperation}[rest[3]]
		if operation == "" {
			return nil, false
		}
		path.methods = restMethods{http.MethodPost}
		return map[string]string{http.MethodPost: operation}, true
	default:
		return nil, false
	}
}

// isKubernetesTrustModeWrite admits a cluster's trust mode change, a PUT.
func isKubernetesTrustModeWrite(request *http.Request) bool {
	path, ok := parseKubernetesClusterPath(request)
	return ok && request.Method == http.MethodPut && path.operation == kubernetesTrustModeOperation
}

func isKubernetesTrustOperation(operation string) bool {
	switch operation {
	case kubernetesTrustReadOperation, kubernetesTrustModeOperation, kubernetesInstallTokenOperation,
		kubernetesTrustConfirmOperation,
		kubernetesTrustChooseOperation, kubernetesTrustResetOperation:
		return true
	}
	return false
}

// serveKubernetesTrust answers the V1-12 operations; Core checks approve
// and manage.
func (handler *ManagementHandler) serveKubernetesTrust(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path kubernetesClusterPath, session accountsession.Session,
	fail func(managementError) string) string {
	trusts, ok := handler.kubernetesClusters.(KubernetesTrustManager)
	if !ok || trusts == nil {
		return fail(managementError{Status: http.StatusServiceUnavailable, Code: "temporarily_unavailable",
			Message: "Kubernetes install tokens are temporarily unavailable", Retryable: true})
	}
	if path.operation == kubernetesTrustReadOperation {
		return handler.readKubernetesTrust(ctx, trusts, response, correlationID, path, session, fail)
	}
	if path.operation == kubernetesInstallTokenOperation {
		return handler.issueKubernetesInstallToken(ctx, trusts, response, request, correlationID, path, session, fail)
	}
	version, precondition := parseIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		return fail(*precondition)
	}
	switch path.operation {
	case kubernetesTrustModeOperation:
		var body struct {
			TrustMode *string `json:"trust_mode"`
		}
		if !readDeviceGroupBody(response, request, &body) || body.TrustMode == nil ||
			!kubecluster.TrustMode(*body.TrustMode).IsKnown() {
			return fail(*invalidManagementRequest())
		}
		result, err := trusts.SetClusterTrustMode(ctx, kubecluster.TrustModeChange{Session: session,
			Scope: path.scope, ClusterID: path.clusterID, Mode: kubecluster.TrustMode(*body.TrustMode),
			Version: version, CorrelationID: correlationID})
		if err != nil {
			return fail(classifyKubernetesClusterError(err))
		}
		response.Header().Set("ETag", strongVersionETag(result.Cluster.Version()))
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
			Changed       bool                  `json:"changed"`
			TrustMode     string                `json:"trust_mode"`
			RevokedTokens int                   `json:"revoked_tokens"`
			Cluster       kubernetesClusterBody `json:"kubernetes_cluster"`
		}{result.Changed, string(result.Mode), result.RevokedTokens, newKubernetesClusterBody(result.Cluster)})
		return "success"
	case kubernetesTrustResetOperation:
		var body struct {
			Reason *string `json:"reason"`
		}
		if !readDeviceGroupBody(response, request, &body) || body.Reason == nil ||
			!kubecluster.ValidResetReason(*body.Reason) {
			return fail(*invalidManagementRequest())
		}
		result, err := trusts.ResetClusterTrust(ctx, kubecluster.TrustReset{Session: session, Scope: path.scope,
			ClusterID: path.clusterID, Reason: *body.Reason, Version: version, CorrelationID: correlationID})
		return handler.writeKubernetesTrustResult(ctx, response, correlationID, path, session, result, err, fail)
	default:
		var body struct {
			Digest *string `json:"digest"`
		}
		if !readDeviceGroupBody(response, request, &body) || body.Digest == nil {
			return fail(*invalidManagementRequest())
		}
		digest, ok := parseTrustDigest(*body.Digest)
		if !ok {
			return fail(*invalidManagementRequest())
		}
		decision := kubecluster.TrustDecision{Session: session, Scope: path.scope, ClusterID: path.clusterID,
			Digest: digest, Version: version, CorrelationID: correlationID}
		var result kubecluster.TrustDecisionResult
		var err error
		if path.operation == kubernetesTrustConfirmOperation {
			result, err = trusts.ConfirmClusterTrust(ctx, decision)
		} else {
			result, err = trusts.ChooseClusterTrust(ctx, decision)
		}
		return handler.writeKubernetesTrustResult(ctx, response, correlationID, path, session, result, err, fail)
	}
}

// parseTrustDigest reads a cluster trust digest: 64 lowercase hex digits.
func parseTrustDigest(text string) ([32]byte, bool) {
	if len(text) != 64 {
		return [32]byte{}, false
	}
	for _, character := range text {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return [32]byte{}, false
		}
	}
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 32 {
		return [32]byte{}, false
	}
	return [32]byte(raw), true
}

func (handler *ManagementHandler) writeKubernetesTrustResult(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path kubernetesClusterPath, session accountsession.Session,
	result kubecluster.TrustDecisionResult, err error, fail func(managementError) string) string {
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	if result.Changed {
		// After commit: who chose, confirmed or reset a cluster's trust, and
		// which gateways that moved, go to the SIEM.
		handler.logger.LogAttrs(ctx, slog.LevelWarn, "kubernetes cluster trust changed",
			slog.String("event", path.operation),
			slog.String("principal_id", session.PrincipalID().String()),
			slog.String("workspace_id", path.scope.WorkspaceID().String()),
			slog.String("network_id", path.scope.NetworkID().String()),
			slog.String("cluster_id", path.clusterID.String()),
			slog.Int("resumed_devices", len(result.ResumedDevices)),
			slog.Int("revoked_devices", len(result.RevokedDevices)),
			slog.Int("suspended_devices", len(result.SuspendedDevices)),
			slog.Int("revoked_tokens", result.RevokedTokens),
			slog.String("correlation_id", correlationID.String()))
	}
	ids := func(values []publicid.ID) []string {
		texts := make([]string, len(values))
		for index, value := range values {
			texts[index] = value.String()
		}
		return texts
	}
	response.Header().Set("ETag", strongVersionETag(result.Cluster.Version()))
	writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
		Changed          bool                  `json:"changed"`
		ResumedDevices   []string              `json:"resumed_device_ids"`
		RevokedDevices   []string              `json:"revoked_device_ids"`
		SuspendedDevices []string              `json:"suspended_device_ids"`
		RevokedTokens    int                   `json:"revoked_tokens"`
		Cluster          kubernetesClusterBody `json:"kubernetes_cluster"`
	}{result.Changed, ids(result.ResumedDevices), ids(result.RevokedDevices), ids(result.SuspendedDevices),
		result.RevokedTokens, newKubernetesClusterBody(result.Cluster)})
	return "success"
}

func (handler *ManagementHandler) issueKubernetesInstallToken(ctx context.Context, trusts KubernetesTrustManager,
	response http.ResponseWriter, request *http.Request, correlationID publicid.ID, path kubernetesClusterPath,
	session accountsession.Session, fail func(managementError) string) string {
	var body struct {
		Replicas        *int   `json:"replicas"`
		LifetimeSeconds *int64 `json:"lifetime_seconds"`
	}
	if !readDeviceGroupBody(response, request, &body) || body.Replicas == nil {
		return fail(*invalidManagementRequest())
	}
	tokenRequest := kubecluster.InstallTokenRequest{Session: session, Scope: path.scope, ClusterID: path.clusterID,
		Replicas: *body.Replicas, Lifetime: kubecluster.DefaultInstallTokenLifetime, CorrelationID: correlationID}
	if body.LifetimeSeconds != nil {
		seconds := *body.LifetimeSeconds
		if seconds <= 0 || seconds > int64(kubecluster.MaxInstallTokenLifetime/time.Second) {
			return fail(*invalidManagementRequest())
		}
		tokenRequest.Lifetime = time.Duration(seconds) * time.Second
	}
	if !kubecluster.ValidInstallToken(tokenRequest.Lifetime, tokenRequest.Replicas) {
		return fail(*invalidManagementRequest())
	}
	issued, err := trusts.IssueInstallToken(ctx, tokenRequest)
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	handler.logger.LogAttrs(ctx, slog.LevelInfo, "kubernetes install token issued",
		slog.String("event", "kubernetes_install_token_issued"),
		slog.String("principal_id", session.PrincipalID().String()),
		slog.String("cluster_id", path.clusterID.String()), slog.String("key_id", issued.Key.ID().String()),
		slog.Int("replicas", issued.Replicas), slog.String("correlation_id", correlationID.String()))
	writeKubernetesData(ctx, handler, response, correlationID, http.StatusCreated, struct {
		Key      kubernetesJoinKeyBody `json:"join_key"`
		Replicas int                   `json:"replicas"`
		// Secret is shown only here; Core keeps a digest of it.
		Secret string `json:"secret"`
	}{newKubernetesJoinKeyBody(issued.Key), issued.Replicas, issued.Presentation.Reveal()})
	return "success"
}

type kubernetesTrustSideBody struct {
	Digest         string   `json:"digest"`
	Issuer         string   `json:"issuer"`
	Namespace      string   `json:"namespace"`
	ServiceAccount string   `json:"service_account"`
	StatefulSet    string   `json:"statefulset"`
	KeyThumbprints []string `json:"key_thumbprints"`
}

func newKubernetesTrustSideBody(side kubecluster.TrustSide) kubernetesTrustSideBody {
	thumbprints := make([]string, len(side.KeyThumbprints))
	for index, thumbprint := range side.KeyThumbprints {
		thumbprints[index] = hex.EncodeToString(thumbprint[:])
	}
	return kubernetesTrustSideBody{Digest: hex.EncodeToString(side.Digest[:]), Issuer: side.Issuer,
		Namespace: side.Namespace, ServiceAccount: side.ServiceAccount, StatefulSet: side.StatefulSet,
		KeyThumbprints: thumbprints}
}

type kubernetesContestedBody struct {
	kubernetesTrustSideBody
	ContestedAt string `json:"contested_at"`
}

type kubernetesTrustBody struct {
	kubernetesTrustSideBody
	TrustID     string                   `json:"trust_id"`
	Version     int64                    `json:"version"`
	Source      string                   `json:"source"`
	State       string                   `json:"state"`
	SetAt       string                   `json:"set_at"`
	ConfirmedAt *string                  `json:"confirmed_at"`
	ConfirmedBy *string                  `json:"confirmed_by"`
	Contested   *kubernetesContestedBody `json:"contested"`
}

type kubernetesInstallTokenBody struct {
	KeyID        string `json:"key_id"`
	State        string `json:"state"`
	Replicas     int    `json:"replicas"`
	UsedOrdinals []int  `json:"used_ordinals"`
	CreatedBy    string `json:"created_by"`
	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"expires_at"`
}

// readKubernetesTrust answers a cluster's trust mode and trust, and its
// install tokens for those who manage it; the ETag is the cluster's version,
// which the trust actions take as If-Match.
func (handler *ManagementHandler) readKubernetesTrust(ctx context.Context, trusts KubernetesTrustManager,
	response http.ResponseWriter, correlationID publicid.ID, path kubernetesClusterPath,
	session accountsession.Session, fail func(managementError) string) string {
	view, err := trusts.ReadClusterTrust(ctx, session, path.scope, path.clusterID)
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	var trust *kubernetesTrustBody
	if view.Trust != nil {
		read := view.Trust
		trust = &kubernetesTrustBody{kubernetesTrustSideBody: newKubernetesTrustSideBody(read.Side),
			TrustID: read.ID.String(), Version: read.Version, Source: string(read.Source), State: string(read.State),
			SetAt: managementTime(read.SetAt), ConfirmedAt: optionalManagementTime(read.ConfirmedAt)}
		if read.ConfirmedBy.IsValid() {
			confirmer := read.ConfirmedBy.String()
			trust.ConfirmedBy = &confirmer
		}
		if read.Contested != nil {
			trust.Contested = &kubernetesContestedBody{kubernetesTrustSideBody: newKubernetesTrustSideBody(*read.Contested),
				ContestedAt: managementTime(read.ContestedAt)}
		}
	}
	var tokens []kubernetesInstallTokenBody
	if view.CanManage {
		tokens = make([]kubernetesInstallTokenBody, 0, len(view.Tokens))
		for _, token := range view.Tokens {
			used := token.UsedOrdinals
			if used == nil {
				used = []int{}
			}
			tokens = append(tokens, kubernetesInstallTokenBody{KeyID: token.KeyID.String(), State: token.State,
				Replicas: token.Replicas, UsedOrdinals: used, CreatedBy: token.CreatedBy.String(),
				CreatedAt: managementTime(token.CreatedAt), ExpiresAt: managementTime(token.ExpiresAt)})
		}
	}
	response.Header().Set("ETag", strongVersionETag(view.ClusterVersion))
	writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
		ClusterVersion int64                        `json:"cluster_version"`
		TrustMode      string                       `json:"trust_mode"`
		Trust          *kubernetesTrustBody         `json:"trust"`
		CanManage      bool                         `json:"can_manage"`
		InstallTokens  []kubernetesInstallTokenBody `json:"install_tokens"`
	}{view.ClusterVersion, string(view.Mode), trust, view.CanManage, tokens})
	return "success"
}
