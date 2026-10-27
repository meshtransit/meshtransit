package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/kubejoin"
)

// maximumTrustReplacementBytes bounds a pasted trust: a JWKS of 16 KiB and
// a few short fields.
const maximumTrustReplacementBytes = 32 << 10

// kubernetesSigningTrustRead is the trust's own read (K1.1b): the trust,
// null when the cluster has none, and whether the caller may replace it.
type kubernetesSigningTrustRead struct {
	NetworkID  string                      `json:"network_id"`
	ClusterID  string                      `json:"cluster_id"`
	Trust      *kubernetesSigningTrustBody `json:"trust"`
	CanReplace bool                        `json:"can_replace_trust"`
}

func (handler *ManagementHandler) readKubernetesSigningTrust(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path kubernetesClusterPath, session accountsession.Session,
	fail func(managementError) string) string {
	signing, err := handler.kubernetesClusters.ReadSigning(ctx, session, path.scope, path.clusterID)
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	body := kubernetesSigningTrustRead{NetworkID: path.scope.NetworkID().String(),
		ClusterID: path.clusterID.String(), CanReplace: signing.CanReplaceTrust}
	var version int64
	if signing.Trust != nil {
		body.Trust, version = newKubernetesSigningTrustBody(*signing.Trust), signing.Trust.Version
	}
	response.Header().Set("ETag", trustVersionETag(version))
	writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, body)
	return "success"
}

func (handler *ManagementHandler) replaceKubernetesSigningTrust(ctx context.Context, response http.ResponseWriter,
	request *http.Request, correlationID publicid.ID, path kubernetesClusterPath, session accountsession.Session,
	fail func(managementError) string) string {
	expected, precondition := parseTrustIfMatch(request.Header.Values("If-Match"))
	if precondition != nil {
		return fail(*precondition)
	}
	body, ok := readTrustReplacementBody(response, request)
	if !ok {
		return fail(*invalidManagementRequest())
	}
	jwks, err := kubejoin.ParseJWKS(body.JWKS)
	if err != nil {
		failure := managementError{Status: http.StatusUnprocessableEntity, Code: "signing_keys_invalid",
			Message: "The signing keys are not a JWKS Core accepts", JWKSRule: string(kubejoin.RuleJSON)}
		if refused, ok := errors.AsType[*kubejoin.JWKSError](err); ok {
			failure.JWKSRule = string(refused.Rule)
		}
		return fail(failure)
	}
	if !kubejoin.ValidIssuer(*body.Issuer) || !kubejoin.ValidNamespace(*body.Namespace) ||
		!kubejoin.ValidName(*body.ServiceAccount) || !kubejoin.ValidName(*body.StatefulSet) {
		return fail(managementError{Status: http.StatusUnprocessableEntity, Code: "signing_identity_invalid",
			Message: "The issuer must be https, and the namespace, ServiceAccount and StatefulSet Kubernetes names"})
	}
	if !kubecluster.ValidTrustReason(*body.Reason) {
		return fail(*invalidManagementRequest())
	}
	result, err := handler.kubernetesClusters.ReplaceTrust(ctx, kubecluster.TrustReplacement{Session: session,
		Scope: path.scope, ClusterID: path.clusterID, ExpectedVersion: expected, Issuer: *body.Issuer, JWKS: jwks,
		Namespace: *body.Namespace, ServiceAccount: *body.ServiceAccount, StatefulSet: *body.StatefulSet,
		Reason: *body.Reason, CorrelationID: correlationID})
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	response.Header().Set("ETag", trustVersionETag(result.Trust.Version))
	writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
		Changed bool                        `json:"changed"`
		Trust   *kubernetesSigningTrustBody `json:"trust"`
	}{result.Changed, newKubernetesSigningTrustBody(result.Trust)})
	return "success"
}

type trustReplacementBody struct {
	Issuer         *string         `json:"issuer"`
	JWKS           json.RawMessage `json:"jwks"`
	Namespace      *string         `json:"namespace"`
	ServiceAccount *string         `json:"service_account"`
	StatefulSet    *string         `json:"statefulset"`
	Reason         *string         `json:"reason"`
}

// readTrustReplacementBody reads the body strictly: one JSON object with no
// member twice, even in another case, no unknown member, every member set,
// and a JWKS object kept as sent.
func readTrustReplacementBody(response http.ResponseWriter, request *http.Request) (trustReplacementBody, bool) {
	var body trustReplacementBody
	if request.Body == nil || !validJSONContentType(singleHeader(request.Header, "Content-Type")) {
		return body, false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maximumTrustReplacementBytes))
	if err != nil || kubejoin.CheckStrictJSON(raw) != nil {
		return body, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil || ensureJSONEnd(decoder) != nil || body.Issuer == nil || body.JWKS == nil ||
		body.Namespace == nil || body.ServiceAccount == nil || body.StatefulSet == nil || body.Reason == nil {
		return trustReplacementBody{}, false
	}
	return body, true
}

// parseTrustIfMatch is parseIfMatch that also takes "0": the cluster has no
// trust yet.
func parseTrustIfMatch(values []string) (int64, *managementError) {
	if len(values) == 1 && values[0] == `"0"` {
		return 0, nil
	}
	return parseIfMatch(values)
}

// trustVersionETag is the trust's version as a strong ETag, "0" for none.
func trustVersionETag(version int64) string {
	if version <= 0 || version == math.MaxInt64 {
		return `"0"`
	}
	return `"` + strconv.FormatInt(version, 10) + `"`
}
