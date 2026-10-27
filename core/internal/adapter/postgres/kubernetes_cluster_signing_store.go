package postgres

import (
	"context"
	"encoding/hex"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/kubejoin"
)

const readKubernetesClusterSigningSQL = `SELECT mesh_ops.read_kubernetes_cluster_signing_v1(` +
	sessionArguments + `,$10::UUID,$11::UUID,$12::UUID)::TEXT`

// maximumTrustKeys bounds the keys of a trust as read: a JWKS of 16 KiB
// holds far fewer.
const maximumTrustKeys = 64

type kubernetesSigningTrustDocument struct {
	Issuer         string    `json:"issuer"`
	KeyThumbprints []string  `json:"key_thumbprints"`
	Namespace      string    `json:"namespace"`
	ServiceAccount string    `json:"service_account"`
	StatefulSet    string    `json:"statefulset"`
	Version        int64     `json:"version"`
	Source         string    `json:"source"`
	SetAt          time.Time `json:"set_at"`
}

type kubernetesSigningReplicaDocument struct {
	DeviceID          string     `json:"device_id"`
	PodName           string     `json:"pod_name"`
	LastTokenRotation *time.Time `json:"last_token_rotation_at"`
}

type kubernetesSigningRequestDocument struct {
	RequestID         string  `json:"request_id"`
	CodeVersion       int     `json:"code_version"`
	Issuer            *string `json:"issuer"`
	Namespace         *string `json:"namespace"`
	ServiceAccount    *string `json:"service_account"`
	StatefulSet       *string `json:"statefulset"`
	PodName           *string `json:"pod_name"`
	JoinKeyThumbprint *string `json:"join_key_thumbprint"`
}

// ReadClusterSigning reads a cluster's signing trust, its live replicas'
// pods and last rotations, and, for those who manage or approve it, its
// waiting requests' signing material and refused rotation tokens
// (schema 233).
func (store *KubernetesClusterStore) ReadClusterSigning(ctx context.Context, session accountsession.Session,
	scope network.Scope, id kubecluster.ID) (kubecluster.Signing, error) {
	var signing kubecluster.Signing
	err := store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, readKubernetesClusterSigningSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), id.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var read struct {
			NetworkID     string                             `json:"network_id"`
			ClusterID     string                             `json:"cluster_id"`
			Trust         *kubernetesSigningTrustDocument    `json:"trust"`
			Replicas      []kubernetesSigningReplicaDocument `json:"replicas"`
			Requests      []kubernetesSigningRequestDocument `json:"requests"`
			Truncated     bool                               `json:"requests_truncated"`
			TokenWarnings *kubernetesKeyWarningsDocument     `json:"token_warnings"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &read); err != nil ||
			read.NetworkID != scope.NetworkID().String() || read.ClusterID != id.String() || read.Replicas == nil ||
			len(read.Replicas) > kubecluster.MaximumOrdinal+1 ||
			len(read.Requests) > kubecluster.MaximumSigningRequests ||
			(read.TokenWarnings == nil) != (read.Requests == nil) ||
			read.Truncated && len(read.Requests) != kubecluster.MaximumSigningRequests {
			return false, kubecluster.ErrInvalid
		}
		decoded, err := decodeKubernetesSigning(read.Trust, read.Replicas, read.Requests, read.TokenWarnings)
		if err != nil {
			return false, err
		}
		signing = decoded
		signing.RequestsTruncated = read.Truncated
		return false, nil
	})
	return signing, err
}

func decodeKubernetesSigning(trust *kubernetesSigningTrustDocument, replicas []kubernetesSigningReplicaDocument,
	requests []kubernetesSigningRequestDocument, warnings *kubernetesKeyWarningsDocument) (kubecluster.Signing,
	error) {
	var signing kubecluster.Signing
	if trust != nil {
		decoded, err := trust.trust()
		if err != nil {
			return kubecluster.Signing{}, err
		}
		signing.Trust = &decoded
	}
	signing.Replicas = make([]kubecluster.ReplicaSigning, 0, len(replicas))
	seen := make(map[string]bool, len(replicas)+len(requests))
	for _, document := range replicas {
		deviceID, err := node.ParseID(document.DeviceID)
		if err != nil || !kubejoin.ValidName(document.PodName) || seen[document.DeviceID] {
			return kubecluster.Signing{}, kubecluster.ErrInvalid
		}
		seen[document.DeviceID] = true
		replica := kubecluster.ReplicaSigning{DeviceID: deviceID, PodName: document.PodName}
		if document.LastTokenRotation != nil {
			if document.LastTokenRotation.IsZero() {
				return kubecluster.Signing{}, kubecluster.ErrInvalid
			}
			replica.LastTokenRotation = document.LastTokenRotation.UTC()
		}
		signing.Replicas = append(signing.Replicas, replica)
	}
	if requests != nil {
		signing.Requests = make([]kubecluster.RequestSigning, 0, len(requests))
		for _, document := range requests {
			request, err := document.request()
			if err != nil {
				return kubecluster.Signing{}, err
			}
			if seen[document.RequestID] {
				return kubecluster.Signing{}, kubecluster.ErrInvalid
			}
			seen[document.RequestID] = true
			signing.Requests = append(signing.Requests, request)
		}
	}
	if warnings != nil {
		decoded, err := warnings.warnings()
		if err != nil {
			return kubecluster.Signing{}, err
		}
		for _, warning := range decoded.Devices {
			if !warning.LastReason.TokenRefused() {
				return kubecluster.Signing{}, kubecluster.ErrInvalid
			}
		}
		signing.TokenWarnings = &decoded
	}
	return signing, nil
}

func (document kubernetesSigningTrustDocument) trust() (kubecluster.SigningTrust, error) {
	source := kubecluster.TrustSource(document.Source)
	if !kubejoin.ValidIssuer(document.Issuer) || !kubejoin.ValidNamespace(document.Namespace) ||
		!kubejoin.ValidName(document.ServiceAccount) || !kubejoin.ValidName(document.StatefulSet) ||
		document.Version < 1 || !source.IsKnown() || document.SetAt.IsZero() ||
		len(document.KeyThumbprints) == 0 || len(document.KeyThumbprints) > maximumTrustKeys {
		return kubecluster.SigningTrust{}, kubecluster.ErrInvalid
	}
	thumbprints := make([][32]byte, 0, len(document.KeyThumbprints))
	for _, encoded := range document.KeyThumbprints {
		thumbprint, ok := decodeThumbprint(encoded)
		if !ok || slices.Contains(thumbprints, thumbprint) {
			return kubecluster.SigningTrust{}, kubecluster.ErrInvalid
		}
		thumbprints = append(thumbprints, thumbprint)
	}
	return kubecluster.SigningTrust{Issuer: document.Issuer, KeyThumbprints: thumbprints,
		Namespace: document.Namespace, ServiceAccount: document.ServiceAccount, StatefulSet: document.StatefulSet,
		Version: document.Version, Source: source, SetAt: document.SetAt.UTC()}, nil
}

// request validates a waiting request's signing material: none at code
// version 1, all of it at version 2.
func (document kubernetesSigningRequestDocument) request() (kubecluster.RequestSigning, error) {
	id, err := publicid.Parse(document.RequestID)
	if err != nil {
		return kubecluster.RequestSigning{}, kubecluster.ErrInvalid
	}
	request := kubecluster.RequestSigning{RequestID: kubecluster.RequestID(id), CodeVersion: document.CodeVersion}
	fields := []*string{document.Issuer, document.Namespace, document.ServiceAccount, document.StatefulSet,
		document.PodName, document.JoinKeyThumbprint}
	switch document.CodeVersion {
	case 1:
		for _, field := range fields {
			if field != nil {
				return kubecluster.RequestSigning{}, kubecluster.ErrInvalid
			}
		}
		return request, nil
	case 2:
		for _, field := range fields {
			if field == nil {
				return kubecluster.RequestSigning{}, kubecluster.ErrInvalid
			}
		}
	default:
		return kubecluster.RequestSigning{}, kubecluster.ErrInvalid
	}
	thumbprint, ok := decodeThumbprint(*document.JoinKeyThumbprint)
	if !ok || !kubejoin.ValidIssuer(*document.Issuer) || !kubejoin.ValidNamespace(*document.Namespace) ||
		!kubejoin.ValidName(*document.ServiceAccount) || !kubejoin.ValidName(*document.StatefulSet) ||
		!kubejoin.ValidName(*document.PodName) {
		return kubecluster.RequestSigning{}, kubecluster.ErrInvalid
	}
	request.Issuer, request.Namespace, request.ServiceAccount = *document.Issuer, *document.Namespace,
		*document.ServiceAccount
	request.StatefulSet, request.PodName, request.JoinKeyThumbprint = *document.StatefulSet, *document.PodName,
		thumbprint
	return request, nil
}

func decodeThumbprint(encoded string) ([32]byte, bool) {
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != encoded {
		return [32]byte{}, false
	}
	return [32]byte(raw), true
}
