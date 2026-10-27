package httpapi

import (
	"context"
	"encoding/hex"
	"net/http"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

// kubernetesSigningBody is a cluster's signing read (K1.1 design §9). Only
// this route carries it, so the bodies older Consoles read keep their
// shape; a Core without it answers 404, and the Console hides the section.
type kubernetesSigningBody struct {
	NetworkID string                      `json:"network_id"`
	ClusterID string                      `json:"cluster_id"`
	Trust     *kubernetesSigningTrustBody `json:"trust"`
	Replicas  []kubernetesSigningReplica  `json:"replicas"`
	Requests  *[]kubernetesSigningRequest `json:"replica_requests"`
	Truncated bool                        `json:"replica_requests_truncated"`
	Warnings  *kubernetesKeyWarningsBody  `json:"token_warnings"`
}

type kubernetesSigningTrustBody struct {
	Issuer         string   `json:"issuer"`
	KeyThumbprints []string `json:"key_thumbprints"`
	Namespace      string   `json:"namespace"`
	ServiceAccount string   `json:"service_account"`
	StatefulSet    string   `json:"statefulset"`
	Version        int64    `json:"version"`
	Source         string   `json:"source"`
	SetAt          string   `json:"set_at"`
}

type kubernetesSigningReplica struct {
	DeviceID          string  `json:"device_id"`
	PodName           string  `json:"pod_name"`
	LastTokenRotation *string `json:"last_token_rotation_at"`
}

// kubernetesSigningRequest is a waiting request's signing material; at
// code version 1 it has none and must join again.
type kubernetesSigningRequest struct {
	RequestID         string  `json:"request_id"`
	CodeVersion       int     `json:"code_version"`
	Issuer            *string `json:"issuer"`
	Namespace         *string `json:"namespace"`
	ServiceAccount    *string `json:"service_account"`
	StatefulSet       *string `json:"statefulset"`
	PodName           *string `json:"pod_name"`
	JoinKeyThumbprint *string `json:"join_key_thumbprint"`
	TrustState        string  `json:"trust_state"`
}

func (handler *ManagementHandler) readKubernetesClusterSigning(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path kubernetesClusterPath, session accountsession.Session,
	fail func(managementError) string) string {
	signing, err := handler.kubernetesClusters.ReadSigning(ctx, session, path.scope, path.clusterID)
	if err != nil {
		return fail(classifyKubernetesClusterError(err))
	}
	body := kubernetesSigningBody{NetworkID: path.scope.NetworkID().String(), ClusterID: path.clusterID.String(),
		Replicas: make([]kubernetesSigningReplica, 0, len(signing.Replicas)), Truncated: signing.RequestsTruncated}
	if trust := signing.Trust; trust != nil {
		thumbprints := make([]string, 0, len(trust.KeyThumbprints))
		for _, thumbprint := range trust.KeyThumbprints {
			thumbprints = append(thumbprints, hex.EncodeToString(thumbprint[:]))
		}
		body.Trust = &kubernetesSigningTrustBody{Issuer: trust.Issuer, KeyThumbprints: thumbprints,
			Namespace: trust.Namespace, ServiceAccount: trust.ServiceAccount, StatefulSet: trust.StatefulSet,
			Version: trust.Version, Source: string(trust.Source), SetAt: managementTime(trust.SetAt)}
	}
	for _, replica := range signing.Replicas {
		listed := kubernetesSigningReplica{DeviceID: replica.DeviceID.String(), PodName: replica.PodName}
		if !replica.LastTokenRotation.IsZero() {
			rotated := managementTime(replica.LastTokenRotation)
			listed.LastTokenRotation = &rotated
		}
		body.Replicas = append(body.Replicas, listed)
	}
	if signing.Requests != nil {
		requests := make([]kubernetesSigningRequest, 0, len(signing.Requests))
		for _, request := range signing.Requests {
			requests = append(requests, newKubernetesSigningRequest(request, signing.StateOf(request)))
		}
		body.Requests = &requests
	}
	if signing.TokenWarnings != nil {
		warnings := newKubernetesKeyWarningsBody(*signing.TokenWarnings)
		body.Warnings = &warnings
	}
	writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, body)
	return "success"
}

func newKubernetesSigningRequest(request kubecluster.RequestSigning,
	state kubecluster.RequestTrustState) kubernetesSigningRequest {
	listed := kubernetesSigningRequest{RequestID: request.RequestID.String(), CodeVersion: request.CodeVersion,
		TrustState: string(state)}
	if request.CodeVersion == 2 {
		thumbprint := hex.EncodeToString(request.JoinKeyThumbprint[:])
		listed.Issuer, listed.Namespace, listed.ServiceAccount = &request.Issuer, &request.Namespace,
			&request.ServiceAccount
		listed.StatefulSet, listed.PodName, listed.JoinKeyThumbprint = &request.StatefulSet, &request.PodName,
			&thumbprint
	}
	return listed
}
