package httpapi

import (
	"context"
	"encoding/base64"
	"net/http"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

// isKubernetesPagedList reports the lists that take page_size and
// page_token (K1d).
func isKubernetesPagedList(operation string) bool {
	switch operation {
	case kubernetesJoinKeyListOperation, kubernetesRequestListOperation, kubernetesReplicaListOperation,
		kubernetesCAListOperation, kubernetesCARetireListOperation:
		return true
	default:
		return false
	}
}

// kubernetesReplicaReadBody is a replica of the replica reads: the
// detail's fields and when it first proved a pod token.
type kubernetesReplicaReadBody struct {
	kubernetesReplicaBody
	TokenFirstProvenAt *string `json:"token_first_proven_at"`
}

func newKubernetesReplicaReadBody(replica kubecluster.Replica) kubernetesReplicaReadBody {
	return kubernetesReplicaReadBody{kubernetesReplicaBody: kubernetesReplicaBody{
		DeviceID: replica.DeviceID.String(), Name: replica.Name, Ordinal: replica.Ordinal, State: replica.State,
		CreatedAt: managementTime(replica.CreatedAt)}, TokenFirstProvenAt: optionalManagementTime(
		replica.TokenFirstProvenAt)}
}

func optionalManagementTime(at time.Time) *string {
	if at.IsZero() {
		return nil
	}
	text := managementTime(at)
	return &text
}

type kubernetesCABody struct {
	CAID              string  `json:"ca_id"`
	Kind              string  `json:"kind"`
	IssuerCAID        *string `json:"issuer_ca_id"`
	State             string  `json:"state"`
	Reason            string  `json:"reason"`
	StateReason       string  `json:"state_reason"`
	Fingerprint       string  `json:"fingerprint_sha256"`
	CertificatePEM    string  `json:"certificate_pem"`
	ClusterDNSName    string  `json:"cluster_dns_name"`
	NotBefore         string  `json:"not_before"`
	NotAfter          string  `json:"not_after"`
	CreatedAt         string  `json:"created_at"`
	ActivatedAt       *string `json:"activated_at"`
	RetiringAt        *string `json:"retiring_at"`
	RetiredAt         *string `json:"retired_at"`
	ChangedByOperator bool    `json:"changed_by_operator"`
	Version           int64   `json:"version"`
}

func newKubernetesCABody(ca kubecluster.CertificateAuthority) kubernetesCABody {
	body := kubernetesCABody{CAID: ca.ID.String(), Kind: string(ca.Kind), State: ca.State, Reason: ca.Reason,
		StateReason: ca.StateReason, Fingerprint: ca.Fingerprint, CertificatePEM: certificatePEM(ca.Certificate),
		ClusterDNSName: ca.ClusterDNSName, NotBefore: managementTime(ca.NotBefore),
		NotAfter: managementTime(ca.NotAfter), CreatedAt: managementTime(ca.CreatedAt),
		ActivatedAt: optionalManagementTime(ca.ActivatedAt), RetiringAt: optionalManagementTime(ca.RetiringAt),
		RetiredAt: optionalManagementTime(ca.RetiredAt), ChangedByOperator: ca.ChangedByOperator,
		Version: ca.Version}
	if ca.IssuerID != (publicid.ID{}) {
		issuer := ca.IssuerID.String()
		body.IssuerCAID = &issuer
	}
	return body
}

// certificatePEM is one CERTIFICATE block, lines of 64 characters.
func certificatePEM(der []byte) string {
	encoded := base64.StdEncoding.EncodeToString(der)
	pem := "-----BEGIN CERTIFICATE-----\n"
	for len(encoded) > 64 {
		pem += encoded[:64] + "\n"
		encoded = encoded[64:]
	}
	return pem + encoded + "\n-----END CERTIFICATE-----\n"
}

// readKubernetesReplicasAndCAs serves a page or one row of a cluster's
// replicas or certificate authorities (K1d d1b).
func (handler *ManagementHandler) readKubernetesReplicasAndCAs(ctx context.Context, response http.ResponseWriter,
	correlationID publicid.ID, path kubernetesClusterPath, session accountsession.Session,
	fail func(managementError) string) string {
	manager := handler.kubernetesClusters
	query := kubecluster.PageQuery{Session: session, Scope: path.scope, ClusterID: path.clusterID,
		After: path.page.after, Limit: path.page.limit}
	next := func(cursor kubecluster.PageCursor) string {
		return encodeKubernetesPageToken(path.scope, path.clusterID, path.operation, cursor)
	}
	switch path.operation {
	case kubernetesReplicaListOperation:
		page, err := manager.ListReplicas(ctx, query)
		if err != nil {
			return fail(classifyKubernetesClusterError(err))
		}
		bodies := make([]kubernetesReplicaReadBody, len(page.Replicas))
		for index, replica := range page.Replicas {
			bodies[index] = newKubernetesReplicaReadBody(replica)
		}
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
			Replicas      []kubernetesReplicaReadBody `json:"replicas"`
			NextPageToken string                      `json:"next_page_token,omitempty"`
		}{bodies, next(page.Next)})
	case kubernetesReplicaReadOperation:
		replica, err := manager.ReadReplica(ctx, session, path.scope, path.clusterID, path.deviceID)
		if err != nil {
			return fail(classifyKubernetesClusterError(err))
		}
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, newKubernetesReplicaReadBody(replica))
	case kubernetesCAListOperation:
		page, err := manager.ListCertificateAuthorities(ctx, query)
		if err != nil {
			return fail(classifyKubernetesClusterError(err))
		}
		bodies := make([]kubernetesCABody, len(page.CAs))
		for index, ca := range page.CAs {
			bodies[index] = newKubernetesCABody(ca)
		}
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, struct {
			CAs           []kubernetesCABody `json:"certificate_authorities"`
			NextPageToken string             `json:"next_page_token,omitempty"`
		}{bodies, next(page.Next)})
	default:
		ca, err := manager.ReadCertificateAuthority(ctx, session, path.scope, path.clusterID, path.caID)
		if err != nil {
			return fail(classifyKubernetesClusterError(err))
		}
		writeKubernetesData(ctx, handler, response, correlationID, http.StatusOK, newKubernetesCABody(ca))
	}
	return "success"
}
